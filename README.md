# Vulpine Core

The transport layer of Vulpine VPN, rewritten in pure Go with no JVM in the
loop, so the same code can run inside an iOS network extension (50 MB ceiling)
as well as on a desktop.

Firefox VPN's free tier is not a WireGuard or OpenVPN tunnel. It is an HTTP/2
CONNECT proxy at Mozilla's Fastly edge, authorised by a short-lived **proxy
pass** that Guardian mints against a Firefox account. This module speaks that
protocol directly.

## What is here

| Package | Role |
|---|---|
| `internal/controlplane` | Guardian proxy-pass minting and the Remote Settings server list |
| `internal/tunnel` | TLS + ALPN `h2` session, one HTTP/2 stream per destination |
| `internal/prefs` | Reads the signed-in session the macOS app stored (verification only) |
| `cmd/vulpine-core` | End-to-end proof: mint a pass, CONNECT through the edge, echo the exit address |

## Verifying it

```bash
go build -o /tmp/vulpine-core ./cmd/vulpine-core
/tmp/vulpine-core                      # optional: -country NL -probe example.com:80
```

Expected shape of a successful run — the tunnelled and direct addresses differ:

```
proxy pass: minted (596 chars, 600s of life left)
tunnel: h2 session to p.m1.fastly-masque.net:2499 established
connect: stream to api.ipify.org:443 open through the edge
exit address via tunnel: 45.58.235.48 (HTTP 200)
direct address: 188.211.121.131
VERDICT: the tunnel carries traffic — the two addresses differ
```

`VULPINE_DEBUG=1` logs every HTTP/2 frame, `VULPINE_DEBUG=2` additionally
hexdumps the first bytes in each direction.

## Protocol notes learned the hard way

* The **client connection preface** is mandatory. `x/net/http2`'s `Framer` does
  not write it for you, and the edge drops the connection without a GOAWAY when
  it is missing.
* `Framer.WriteHeaders` needs **`EndHeaders: true`** explicitly. Without the
  flag the peer waits forever for CONTINUATION frames and says nothing.
* `Framer` must be given a **`ReadMetaHeaders`** HPACK decoder, otherwise
  responses arrive as raw `*HeadersFrame` values and are silently ignored.
* One `hpack.Encoder` per connection, not per stream: the edge keeps a single
  decoding context, and a fresh encoder desynchronises the dynamic table.
* The edge advertises `HEADER_TABLE_SIZE 8192`, `MAX_CONCURRENT_STREAMS 1000`
  and `ENABLE_CONNECT_PROTOCOL 1`.
* A CONNECT request here carries exactly `:method`, `:authority` and
  `proxy-authorization: Bearer <pass>`. Adding `:scheme` or `:protocol` makes
  the edge close the connection.

## Where this goes next

This core is the payload of the iOS `NEPacketTunnelProvider` extension: the
extension hands it the captured flows, each flow becomes one stream here, and
the proxy pass is renewed by the containing app through a shared app group.
Building that requires Xcode on the machine and, for installation without the
App Store, TrollStore on the device (iOS 14.0–16.6.1 or 17.0).
