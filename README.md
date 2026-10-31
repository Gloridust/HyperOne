# HyperOne

A research prototype of a TLS-camouflaged circumvention transport, in the
spirit of REALITY / VLESS / ShadowTLS, built to study whether a few specific
techniques can raise the cost of **both** active probing and passive traffic
analysis.

> **Status: research prototype.** This is for studying censorship-resistance
> and traffic analysis. It has not been evaluated against real DPI systems and
> makes no guarantee of undetectability. See the honest limitations in
> [`docs/PROTOCOL.md`](docs/PROTOCOL.md) §7 before drawing any conclusions.

## Idea in one paragraph

A HyperOne server sits in front of a real HTTPS site. Anyone who connects
without proving knowledge of a pre-shared key — including a censor's active
probe — is transparently relayed to that real site and sees its real
certificate and behaviour (the [ShadowTLS](https://github.com/ihciah/shadow-tls)
approach). A client that *does* hold the key carries a proof hidden inside the
TLS `session_id`, completes a genuine Chrome-fingerprinted handshake via
[uTLS](https://github.com/refraction-networking/utls), then switches to an
encrypted inner channel whose records are framed to look like ordinary TLS 1.3
application data. The design is documented in full in
[`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Layout

| Path | What it is |
|------|------------|
| `internal/auth`  | PSK authenticator (HMAC tag in `session_id`, replay cache) + HKDF key schedule |
| `internal/frame` | Inner AEAD records framed as TLS 1.3 application_data, with padding |
| `internal/relay` | ShadowTLS-style handshake relay, fallback, handoff, tunnel |
| `internal/socks` | Minimal SOCKS5 server + address codec |
| `cmd/h1-server`  | Server daemon |
| `cmd/h1-client`  | Local SOCKS5 proxy that tunnels through the server |
| `cmd/h1-keygen`  | Generates a random PSK |

## Build

```sh
go build ./...
go test ./...
```

## Try it locally

1. Generate a shared key:
   ```sh
   go run ./cmd/h1-keygen
   ```
2. Copy `config/server.example.json` and `config/client.example.json`, drop the
   key into both as `psk_hex`, and set `camouflage` / `sni` to a real TLS site
   you control or are allowed to front, and `server` to your server's address.
3. Run the server (on the VPS) and the client (locally):
   ```sh
   go run ./cmd/h1-server -config config/server.json -debug
   go run ./cmd/h1-client -config config/client.json -debug
   ```
4. Point a browser or `curl` at the client's SOCKS5 port:
   ```sh
   curl -x socks5h://127.0.0.1:1080 https://example.org
   ```

The end-to-end path (auth, handoff, tunnel) and the probe-fallback path are
both covered by `internal/relay/e2e_test.go`.

## Roadmap

The next and most important piece is an HTTP/2-shaped padding/timing policy over
the padding-record mechanism, to attack the TLS-in-TLS size signature that
current proxies leak. After that: stream multiplexing, a deployment SNI/ASN
sanity checker, and evaluation against nDPI / Zeek. Tracked in
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) §7.

## License

MIT (see below). For research and authorized use.
