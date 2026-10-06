// Package tunnel speaks the transport Firefox VPN uses: a TLS connection with
// ALPN h2 to Mozilla's Fastly edge, where every destination is a separate
// HTTP/2 stream opened with CONNECT and authorised by a short-lived proxy pass.
//
// This is deliberately dependency-light and pure Go, because the same code has
// to run inside an iOS network-extension process with a 50 MB memory ceiling.
package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	// keepaliveIdle is how long a session may sit unused before it pings.
	keepaliveIdle = 15 * time.Second
	// streamWindow is what we advertise for inbound data per stream.
	streamWindow = 4 << 20
	// connWindow is our inbound connection-level budget.
	connWindow = 16 << 20
	// maxFrame is the largest frame we write.
	maxFrame = 16 << 10
	// openTimeout bounds a single CONNECT round trip.
	openTimeout = 20 * time.Second
)

// ErrRejected means the edge refused a CONNECT for a specific destination.
type ErrRejected struct {
	Authority string
	Status    int
}

func (e ErrRejected) Error() string {
	return fmt.Sprintf("edge refused CONNECT to %s: status %d", e.Authority, e.Status)
}

// Session is one TLS/H2 connection to a single edge, carrying many streams.
type Session struct {
	host      string
	port      int
	bearer    func() string
	conn      net.Conn
	framer    *http2.Framer
	writeMu   sync.Mutex
	streams   map[uint32]*stream
	streamsMu sync.Mutex
	nextID    uint32
	dead      chan struct{}
	deadOnce  sync.Once
	err       error
	errMu     sync.Mutex

	enc           *hpack.Encoder
	encBuf        *bytes.Buffer
	peerTableSize int32
	peerMaxFrame  int32
	peerInitWin   int32
	connSendWin   int32
	connRecvUsed  int32
	winCond       *sync.Cond
	dialerIP      string
	lastActivity  time.Time
}

type stream struct {
	id        uint32
	authority string
	headers   chan int
	status    int
	statusErr error
	readBuf   bytes.Buffer
	pending   [][]byte
	closed    chan struct{}
	closeOnce sync.Once
	sendWin   int32
	err       error
	mu        sync.Mutex
	cond      *sync.Cond
	session   *Session
}

// New dials the edge and completes the HTTP/2 handshake.
func New(ctx context.Context, host string, port int, bearer func() string) (*Session, error) {
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("dial edge %s: %w", host, err)
	}
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: host,
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	})
	_ = tlsConn.SetDeadline(time.Now().Add(20 * time.Second))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls handshake with %s: %w", host, err)
	}
	_ = tlsConn.SetDeadline(time.Time{})
	if proto := tlsConn.ConnectionState().NegotiatedProtocol; proto != "h2" {
		tlsConn.Close()
		return nil, fmt.Errorf("edge negotiated %q, not h2", proto)
	}

	var wire net.Conn = tlsConn
	if debug() {
		wire = &wireLog{Conn: tlsConn}
	}
	s := &Session{
		host: host, port: port, bearer: bearer,
		conn: wire, framer: http2.NewFramer(wire, wire),
		streams: map[uint32]*stream{}, nextID: 1,
		dead: make(chan struct{}),
		// A peer that never sends SETTINGS assumes the spec default.
		peerMaxFrame: 1 << 14, peerInitWin: 65535, connSendWin: 65535,
		peerTableSize: 4096,
	}
	s.winCond = sync.NewCond(&s.writeMu)
	s.encBuf = &bytes.Buffer{}
	s.enc = hpack.NewEncoder(s.encBuf)
	// Without this the framer hands back raw *HeadersFrame values and every
	// response would be silently ignored.
	s.framer.ReadMetaHeaders = hpack.NewDecoder(8192, nil)
	if err := s.writeSettings(); err != nil {
		tlsConn.Close()
		return nil, err
	}
	go s.readLoop()
	select {
	case <-s.dead:
		return nil, s.failure()
	case <-time.After(2 * time.Second):
	}
	return s, nil
}

// clientPreface is mandatory before the first frame; x/net/http2 does not
// write it for a bare Framer, and the edge drops the connection without it.
const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

func (s *Session) writeSettings() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := io.WriteString(s.conn, clientPreface); err != nil {
		return fmt.Errorf("h2 preface: %w", err)
	}
	return s.framer.WriteSettings(
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: uint32(streamWindow)},
		http2.Setting{ID: http2.SettingMaxFrameSize, Val: uint32(maxFrame)},
	)
}

// Addr reports the edge this session is attached to.
func (s *Session) Addr() string { return net.JoinHostPort(s.host, strconv.Itoa(s.port)) }

// IsDead is closed once the session can no longer carry streams.
func (s *Session) IsDead() <-chan struct{} { return s.dead }

func (s *Session) failure() error {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.err != nil {
		return s.err
	}
	return errors.New("session closed")
}

// Close tears the connection down and releases every stream.
func (s *Session) Close() error {
	s.fail(errors.New("session closed by us"))
	return s.conn.Close()
}

func (s *Session) fail(err error) {
	s.errMu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.errMu.Unlock()
	s.deadOnce.Do(func() { close(s.dead) })
	s.streamsMu.Lock()
	for _, st := range s.streams {
		st.shutdown(err)
	}
	s.streamsMu.Unlock()
	s.winCond.Broadcast()
}

// Open CONNECTs to targetHost:targetPort through the edge.
func (s *Session) Open(ctx context.Context, targetHost string, targetPort int) (net.Conn, error) {
	authority := targetHost + ":" + strconv.Itoa(targetPort)
	if bytes.ContainsRune([]byte(targetHost), ':') {
		authority = "[" + targetHost + "]:" + strconv.Itoa(targetPort)
	}
	select {
	case <-s.dead:
		return nil, s.failure()
	default:
	}

	s.streamsMu.Lock()
	if s.nextID > 1<<30 {
		s.streamsMu.Unlock()
		return nil, errors.New("stream ids exhausted")
	}
	id := s.nextID
	s.nextID += 2
	st := &stream{id: id, authority: authority, headers: make(chan int, 1), closed: make(chan struct{}), session: s, sendWin: s.peerInitWin}
	st.cond = sync.NewCond(&st.mu)
	s.streams[id] = st
	s.streamsMu.Unlock()

	block, err := s.encodeHeaders(authority, s.bearer())
	if err != nil {
		s.dropStream(id)
		return nil, err
	}
	if err := s.writeHeaders(id, block); err != nil {
		s.dropStream(id)
		return nil, err
	}

	timer := time.NewTimer(openTimeout)
	defer timer.Stop()
	select {
	case status := <-st.headers:
		if status < 200 || status > 299 {
			s.dropStream(id)
			return nil, ErrRejected{Authority: authority, Status: status}
		}
		return &streamConn{st: st}, nil
	case <-st.closed:
		s.dropStream(id)
		if st.statusErr != nil {
			return nil, st.statusErr
		}
		return nil, s.failure()
	case <-s.dead:
		s.dropStream(id)
		return nil, s.failure()
	case <-ctx.Done():
		s.dropStream(id)
		return nil, ctx.Err()
	case <-timer.C:
		s.dropStream(id)
		return nil, fmt.Errorf("timed out waiting for CONNECT response from %s", s.Addr())
	}
}

func (s *Session) encodeHeaders(authority, token string) ([]byte, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	// One encoder for the whole connection: the edge keeps a single HPACK
	// decoding context, so a fresh encoder per stream would desynchronise the
	// dynamic table indices.
	buf := s.encBuf
	buf.Reset()
	fields := []hpack.HeaderField{
		{Name: ":method", Value: "CONNECT"},
		{Name: ":authority", Value: authority},
	}
	fields = append(fields, hpack.HeaderField{Name: "proxy-authorization", Value: "Bearer " + token})
	for _, field := range fields {
		if err := s.enc.WriteField(field); err != nil {
			return nil, err
		}
	}
	block := append([]byte(nil), buf.Bytes()...)
	if debug() {
		decoded := hpack.NewDecoder(4096, nil)
		fields, err := decoded.DecodeFull(block)
		if err != nil {
			logf("hpack round-trip FAILED: %v", err)
		} else {
			for _, f := range fields {
				value := f.Value
				if len(value) > 40 {
					value = value[:40] + fmt.Sprintf("…(%d)", len(f.Value))
				}
				logf("hpack field %s = %s", f.Name, value)
			}
		}
	}
	return block, nil
}

func (s *Session) writeHeaders(id uint32, block []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: block, EndHeaders: true, EndStream: os.Getenv("VULPINE_ENDSTREAM") == "1",
	}); err != nil {
		return err
	}
	if debug() {
		logf(">> HEADERS stream=%d block=%d bytes", id, len(block))
	}
	s.lastActivity = time.Now()
	return nil
}

func (s *Session) dropStream(id uint32) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
}

func (s *Session) readLoop() {
	for {
		frame, err := s.framer.ReadFrame()
		if debug() && frame != nil {
			logf("<< %s stream=%d len=%d", frame.Header().Type, frame.Header().StreamID, frame.Header().Length)
		}
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !isTimeout(err) {
				s.fail(fmt.Errorf("edge frame read: %w", err))
			} else {
				s.fail(err)
			}
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			s.applySettings(f)
			if !f.IsAck() {
				s.writeMu.Lock()
				_ = s.framer.WriteSettingsAck()
				s.writeMu.Unlock()
			}
		case *http2.MetaHeadersFrame:
			s.handleHeaders(f)
		case *http2.DataFrame:
			s.handleData(f)
		case *http2.WindowUpdateFrame:
			s.handleWindowUpdate(f)
		case *http2.RSTStreamFrame:
			if st := s.lookup(f.StreamID); st != nil {
				st.shutdown(fmt.Errorf("edge reset the stream (%s)", f.ErrCode))
				s.dropStream(f.StreamID)
			}
		case *http2.GoAwayFrame:
			s.fail(fmt.Errorf("edge sent GOAWAY (%s)", f.ErrCode))
			return
		case *http2.PingFrame:
			if f.IsAck() {
				continue
			}
			s.writeMu.Lock()
			_ = s.framer.WritePing(false, f.Data)
			s.writeMu.Unlock()
		}
	}
}

func (s *Session) applySettings(f *http2.SettingsFrame) {
	if value, ok := f.Value(http2.SettingMaxFrameSize); ok {
		s.peerMaxFrame = int32(value)
	}
	if value, ok := f.Value(http2.SettingHeaderTableSize); ok && debug() {
		// The edge advertises a 32-byte HPACK table, which is why every header
		// below is written never-indexed.
		logf("peer HPACK table size = %d", value)
		s.peerTableSize = int32(value)
	}
	if value, ok := f.Value(http2.SettingInitialWindowSize); ok {
		delta := int32(value) - s.peerInitWin
		s.peerInitWin = int32(value)
		s.writeMu.Lock()
		s.connSendWin += delta
		s.winCond.Broadcast()
		s.writeMu.Unlock()
		s.streamsMu.Lock()
		for _, st := range s.streams {
			st.mu.Lock()
			st.sendWin += delta
			st.cond.Broadcast()
			st.mu.Unlock()
		}
		s.streamsMu.Unlock()
	}
}

func (s *Session) lookup(id uint32) *stream {
	s.streamsMu.Lock()
	defer s.streamsMu.Unlock()
	return s.streams[id]
}

func (s *Session) handleHeaders(f *http2.MetaHeadersFrame) {
	st := s.lookup(f.StreamID)
	if st == nil {
		return
	}
	status := 0
	reason := ""
	for _, hf := range f.Fields {
		switch hf.Name {
		case ":status":
			status, _ = strconv.Atoi(hf.Value)
		case "proxy-status", "x-proxy-error", "message":
			reason = hf.Value
		}
	}
	if status == 0 {
		return
	}
	if reason != "" && (status < 200 || status > 299) {
		st.statusErr = fmt.Errorf("edge refused CONNECT to %s: status %d (%s)", st.authority, status, reason)
	}
	st.mu.Lock()
	st.status = status
	st.mu.Unlock()
	select {
	case st.headers <- status:
	default:
	}
	if f.StreamEnded() {
		st.shutdown(io.EOF)
	}
}

func (s *Session) handleData(f *http2.DataFrame) {
	payload := make([]byte, len(f.Data()))
	copy(payload, f.Data())
	st := s.lookup(f.StreamID)
	if st == nil {
		return
	}
	st.enqueue(payload)
	// Return the budget immediately so the edge keeps flowing.
	s.credit(int32(len(payload)), f.StreamID)
}

func (s *Session) credit(amount int32, streamID uint32) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.framer.WriteWindowUpdate(0, uint32(amount)); err != nil {
		return
	}
	if streamID != 0 {
		_ = s.framer.WriteWindowUpdate(streamID, uint32(amount))
	}
}

func (s *Session) handleWindowUpdate(f *http2.WindowUpdateFrame) {
	if f.StreamID == 0 {
		s.writeMu.Lock()
		s.connSendWin += int32(f.Increment)
		s.winCond.Broadcast()
		s.writeMu.Unlock()
		return
	}
	if st := s.lookup(f.StreamID); st != nil {
		st.mu.Lock()
		st.sendWin += int32(f.Increment)
		st.cond.Broadcast()
		st.mu.Unlock()
	}
}

// streamConn adapts one HTTP/2 stream to net.Conn for the callers above it.
type streamConn struct {
	st *stream
}

func (c *streamConn) Read(p []byte) (int, error) { return c.st.read(p) }

func (c *streamConn) Write(p []byte) (int, error) { return c.st.write(p) }

func (c *streamConn) Close() error {
	c.st.session.streamsMu.Lock()
	delete(c.st.session.streams, c.st.id)
	c.st.session.streamsMu.Unlock()
	c.st.session.writeMu.Lock()
	_ = c.st.session.framer.WriteRSTStream(c.st.id, http2.ErrCodeNo)
	c.st.session.writeMu.Unlock()
	c.st.shutdown(io.EOF)
	return nil
}

func (c *streamConn) LocalAddr() net.Addr              { return c.st.session.conn.LocalAddr() }
func (c *streamConn) RemoteAddr() net.Addr             { return c.st.session.conn.RemoteAddr() }
func (c *streamConn) SetDeadline(time.Time) error      { return nil }
func (c *streamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *streamConn) SetWriteDeadline(time.Time) error { return nil }

func (st *stream) enqueue(payload []byte) {
	st.mu.Lock()
	st.pending = append(st.pending, payload)
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *stream) read(p []byte) (int, error) {
	for {
		st.mu.Lock()
		if st.readBuf.Len() == 0 {
			if len(st.pending) > 0 {
				st.readBuf.Write(st.pending[0])
				st.pending = st.pending[1:]
			}
		}
		if st.readBuf.Len() > 0 {
			n, _ := st.readBuf.Read(p)
			st.mu.Unlock()
			return n, nil
		}
		if st.err != nil {
			err := st.err
			st.mu.Unlock()
			return 0, err
		}
		st.cond.Wait()
		st.mu.Unlock()
	}
}

func (st *stream) write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		chunk := len(p) - written
		if int32(chunk) > st.session.peerMaxFrame {
			chunk = int(st.session.peerMaxFrame)
		}
		if err := st.awaitWindow(int32(chunk)); err != nil {
			return written, err
		}
		st.session.writeMu.Lock()
		if st.session.connSendWin < 0 {
			// The connection window is exhausted; wait for an update.
			st.session.winCond.Wait()
		}
		err := st.session.framer.WriteData(st.id, false, p[written:written+chunk])
		st.session.connSendWin -= int32(chunk)
		st.session.writeMu.Unlock()
		if err != nil {
			return written, err
		}
		st.mu.Lock()
		st.sendWin -= int32(chunk)
		st.mu.Unlock()
		written += chunk
	}
	return written, nil
}

func (st *stream) awaitWindow(need int32) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	for {
		if st.err != nil {
			return st.err
		}
		if st.sendWin >= need {
			return nil
		}
		st.cond.Wait()
	}
}

func (st *stream) shutdown(err error) {
	st.mu.Lock()
	if st.err == nil {
		st.err = err
	}
	st.cond.Broadcast()
	st.mu.Unlock()
	st.closeOnce.Do(func() { close(st.closed) })
}

func debug() bool { return os.Getenv("VULPINE_DEBUG") != "" }

func verbose() bool { return os.Getenv("VULPINE_DEBUG") == "2" }

// wireLog dumps the first bytes in each direction so a handshake rejection can
// be told apart from a stream-level one.
type wireLog struct {
	net.Conn
	wrote, read bool
}

func (w *wireLog) Write(b []byte) (int, error) {
	if !w.wrote || verbose() {
		w.wrote = true
		logf("WIRE >> (%d bytes) % x", len(b), head(b, 64))
	}
	return w.Conn.Write(b)
}

func (w *wireLog) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	if n > 0 && (!w.read || verbose()) {
		w.read = true
		logf("WIRE << (%d bytes) % x", n, head(b[:n], 64))
	}
	if err != nil && n == 0 {
		logf("WIRE << read error: %v", err)
	}
	return n, err
}

func head(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[tunnel] "+format+"\n", args...)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// appendLiteralNeverIndexed encodes RFC 7541 6.2.6: 0b00011111 then the literal
// name and value, so the peer's (32-byte) dynamic table is never touched.
func appendLiteralNeverIndexed(buf *bytes.Buffer, f hpack.HeaderField) {
	buf.WriteByte(0x1f)
	appendLiteralString(buf, f.Name)
	appendLiteralString(buf, f.Value)
}

func appendLiteralString(buf *bytes.Buffer, value string) {
	n := len(value)
	switch {
	case n < 0x80:
		buf.WriteByte(byte(n))
	case n < 0x4000:
		buf.WriteByte(byte(n>>7) | 0x80)
		buf.WriteByte(byte(n & 0x7f))
	default:
		buf.WriteByte(0x80 | 0x40)
		buf.WriteByte(byte((n>>14)&0x3f) | 0x80)
		buf.WriteByte(byte(n >> 7))
	}
	buf.WriteString(value)
}
