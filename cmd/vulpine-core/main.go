// Command vulpine-core verifies the Go tunnel core end to end: it reuses the
// signed-in session, mints a proxy pass, opens an HTTP/2 CONNECT stream through
// Mozilla's edge, and fetches an IP echo service over it. The exit address it
// prints is the proof the transport works without any JVM in the loop.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/HELBOYCODER/vulpine-core/internal/controlplane"
	"github.com/HELBOYCODER/vulpine-core/internal/prefs"
	"github.com/HELBOYCODER/vulpine-core/internal/tunnel"
)

func main() {
	country := flag.String("country", controlplane.RecommendedCountry, "country code to dial")
	target := flag.String("probe", "api.ipify.org:443", "host:port to reach through the tunnel")
	path := flag.String("path", "/", "request path for the probe")
	flag.Parse()

	if err := run(*country, *target, *path); err != nil {
		fmt.Fprintln(os.Stderr, "FAILED:", err)
		os.Exit(1)
	}
}

func run(country, target, path string) error {
	auth, err := prefs.LoadAuth()
	if err != nil {
		return fmt.Errorf("session: %w", err)
	}
	fmt.Printf("session: access token recovered (%d chars, expires %s)\n",
		len(auth.AccessToken), time.Unix(auth.ExpiresAt, 0).Format(time.RFC3339))

	httpClient := &http.Client{Timeout: 20 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	candidates, err := controlplane.Candidates(ctx, httpClient, country)
	if err != nil {
		return fmt.Errorf("server list: %w", err)
	}
	fmt.Printf("server list: %d edge(s) for %s, first is %s\n", len(candidates), country, candidates[0].Authority())

	pass, err := controlplane.FetchProxyPass(ctx, httpClient, controlplane.GuardianDefault, auth.AccessToken)
	if err != nil {
		return fmt.Errorf("proxy pass: %w", err)
	}
	fmt.Printf("proxy pass: minted (%d chars, %ds of life left)\n", len(pass.Token), pass.RemainingSeconds())

	bearer := func() string { return pass.Token }
	session, err := tunnel.New(ctx, candidates[0].Host, candidates[0].Port, bearer)
	if err != nil {
		return fmt.Errorf("tunnel: %w", err)
	}
	defer session.Close()
	fmt.Printf("tunnel: h2 session to %s established\n", session.Addr())

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("probe address: %w", err)
	}
	_ = portStr
	stream, err := session.Open(ctx, host, port(target))
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer stream.Close()
	fmt.Printf("connect: stream to %s open through the edge\n", target)

	tlsConn := tls.Client(stream, &tls.Config{ServerName: host})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("probe tls: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return fmt.Errorf("probe request: %w", err)
	}
	if err := request.Write(tlsConn); err != nil {
		return fmt.Errorf("probe write: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), request)
	if err != nil {
		return fmt.Errorf("probe response: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return fmt.Errorf("probe read: %w", err)
	}
	fmt.Printf("exit address via tunnel: %s (HTTP %d)\n", string(trim(body)), response.StatusCode)

	for i := 2; i <= 4; i++ {
		second, err := probeStream(ctx, session, host, port(target), path)
		if err != nil {
			return fmt.Errorf("stream %d: %w", i, err)
		}
		fmt.Printf("stream %d through the same session: %s\n", i, second)
	}

	direct, err := directProbe(ctx, host, path)
	if err != nil {
		fmt.Printf("direct address: unavailable (%v)\n", err)
	} else {
		fmt.Printf("direct address: %s\n", direct)
	}
	if direct != "" && string(trim(body)) != direct {
		fmt.Println("VERDICT: the tunnel carries traffic — the two addresses differ")
	} else if direct != "" {
		fmt.Println("VERDICT: identical addresses, the probe did not go through the edge")
		return fmt.Errorf("probe did not traverse the tunnel")
	}
	return nil
}

func port(hostPort string) int {
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return 443
	}
	value := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			return 443
		}
		value = value*10 + int(c-'0')
	}
	if value == 0 {
		return 443
	}
	return value
}

// probeStream opens another CONNECT on an existing session and returns the
// echoed address, which proves the shared HPACK context stays in sync.
func probeStream(ctx context.Context, session *tunnel.Session, host string, port int, path string) (string, error) {
	stream, err := session.Open(ctx, host, port)
	if err != nil {
		return "", err
	}
	defer stream.Close()
	tlsConn := tls.Client(stream, &tls.Config{ServerName: host})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return "", err
	}
	if err := request.Write(tlsConn); err != nil {
		return "", err
	}
	response, err := http.ReadResponse(bufio.NewReader(tlsConn), request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return "", err
	}
	return string(trim(body)), nil
}

func directProbe(ctx context.Context, host, path string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+path, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<16))
	if err != nil {
		return "", err
	}
	return string(trim(body)), nil
}

func trim(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}
