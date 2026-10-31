package relay

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Gloridust/HyperOne/internal/auth"
	"github.com/Gloridust/HyperOne/internal/frame"
	"github.com/Gloridust/HyperOne/internal/socks"
)

// ServerConfig configures a HyperOne server.
type ServerConfig struct {
	// PSK is the pre-shared key shared with authorized clients.
	PSK []byte
	// Camouflage is the real TLS site (host:port) that unauthenticated
	// connections are relayed to, and that authenticated clients handshake
	// against. For reliable handoff it should be a site that does not send
	// TLS 1.3 session tickets mid-stream (see docs/PROTOCOL.md).
	Camouflage string
	// Skew bounds the auth timestamp window; 0 uses auth.DefaultSkew.
	Skew time.Duration
	// Dial dials tunnelled targets; nil uses a default dialer. Overridable so
	// tests can intercept egress.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Logger receives operational events; nil discards them.
	Logger *slog.Logger
}

// Server accepts HyperOne connections.
type Server struct {
	cfg      ServerConfig
	verifier *auth.Verifier
	log      *slog.Logger
	dial     func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewServer builds a Server from cfg.
func NewServer(cfg ServerConfig) *Server {
	log := cfg.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	dial := cfg.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	return &Server{
		cfg:      cfg,
		verifier: auth.NewVerifier(cfg.PSK, cfg.Skew),
		log:      log,
		dial:     dial,
	}
}

// Serve accepts connections on ln until it errors or is closed.
func (s *Server) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

// handle processes one inbound connection: parse the ClientHello, then either
// fall back to the camouflage site (probe / non-client) or run the tunnel.
func (s *Server) handle(client net.Conn) {
	defer client.Close()

	first, err := readRecord(client)
	if err != nil {
		return
	}
	hello, err := parseClientHello(first)
	if err != nil {
		// Not even a ClientHello; still relay so a port scanner sees the site.
		s.fallback(client, first.raw)
		return
	}

	if err := s.verifier.Verify(hello.sessionID, hello.random); err != nil {
		// Unauthenticated: indistinguishable from the real site to this peer.
		s.log.Debug("fallback", "reason", err)
		s.fallback(client, first.raw)
		return
	}
	s.log.Debug("authenticated client", "remote", client.RemoteAddr())
	s.tunnel(client, first, hello)
}

// fallback dials the camouflage site, replays the bytes already read from the
// client, and splices the two connections. This is the path a censor's active
// probe takes: it gets the genuine site, certificate and all.
func (s *Server) fallback(client net.Conn, firstBytes []byte) {
	backend, err := net.DialTimeout("tcp", s.cfg.Camouflage, 10*time.Second)
	if err != nil {
		return
	}
	defer backend.Close()
	if _, err := backend.Write(firstBytes); err != nil {
		return
	}
	splice(client, backend)
}

// tunnel runs the authenticated path: relay the real TLS handshake to the
// camouflage backend, capture both handshake randoms, detect the handoff to
// inner records, then pipe the tunnel to the requested target.
func (s *Server) tunnel(client net.Conn, firstHello record, hello clientHello) {
	backend, err := net.DialTimeout("tcp", s.cfg.Camouflage, 10*time.Second)
	if err != nil {
		return
	}
	// Forward the ClientHello that we already consumed.
	if _, err := backend.Write(firstHello.raw); err != nil {
		backend.Close()
		return
	}

	// Relay backend->client, publishing the ServerHello random when seen.
	srvRandom := make(chan []byte, 1)
	relayDone := make(chan struct{})
	var once sync.Once
	go func() {
		defer close(relayDone)
		for {
			rec, err := readRecord(backend)
			if err != nil {
				return
			}
			if rec.typ == recHandshake {
				if r, err := parseServerHelloRandom(rec); err == nil {
					once.Do(func() { srvRandom <- r })
				}
			}
			if _, err := client.Write(rec.raw); err != nil {
				return
			}
		}
	}()

	// Wait for the ServerHello random (bounded) so we can derive inner keys.
	var serverRandom []byte
	select {
	case serverRandom = <-srvRandom:
	case <-time.After(15 * time.Second):
		backend.Close()
		<-relayDone
		return
	}
	keys, err := auth.DeriveKeys(s.cfg.PSK, hello.random, serverRandom)
	if err != nil {
		backend.Close()
		<-relayDone
		return
	}

	// Read client records. Forward real-handshake records to the backend until
	// a record authenticates under the inner key — that is the handoff.
	for {
		rec, err := readRecord(client)
		if err != nil {
			backend.Close()
			<-relayDone
			return
		}
		if rec.typ == recAppData && frame.TrialOpen(keys.ClientToServer, rec.raw) {
			// Handoff. Stop the camouflage relay and switch to the tunnel.
			backend.Close()
			<-relayDone
			s.runTunnel(client, rec.raw, keys)
			return
		}
		if _, err := backend.Write(rec.raw); err != nil {
			backend.Close()
			<-relayDone
			return
		}
	}
}

// runTunnel takes over after handoff. firstRecord is the client's first inner
// record (already read); it is replayed into the frame layer so the AEAD
// counters line up.
func (s *Server) runTunnel(client net.Conn, firstRecord []byte, keys auth.SessionKeys) {
	pc := &prefixConn{Conn: client, prefix: firstRecord}
	fc, err := frame.NewConn(pc, keys.ServerToClient, keys.ClientToServer)
	if err != nil {
		return
	}
	// First inner message is the SOCKS-encoded target to dial.
	target, err := socks.ReadAddr(fc)
	if err != nil {
		s.log.Debug("tunnel: read target", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	dst, err := s.dial(ctx, "tcp", target.String())
	cancel()
	if err != nil {
		s.log.Debug("tunnel: dial target", "target", target.String(), "err", err)
		return
	}
	defer dst.Close()
	s.log.Debug("tunnel open", "target", target.String())
	splice(fc, dst)
}

// splice copies bytes in both directions until either side closes.
func splice(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		io.Copy(dst, src)
		// Unblock the other direction.
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go cp(a, b)
	go cp(b, a)
	wg.Wait()
	a.Close()
	b.Close()
}
