package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/Gloridust/HyperOne/internal/auth"
	"github.com/Gloridust/HyperOne/internal/frame"
	"github.com/Gloridust/HyperOne/internal/socks"
)

// ClientConfig configures a HyperOne client dialer.
type ClientConfig struct {
	// Server is the HyperOne server address (host:port).
	Server string
	// SNI is the camouflage domain presented in the ClientHello. It must match
	// the certificate the server's camouflage backend serves, so TLS
	// verification of a genuine site succeeds.
	SNI string
	// PSK is the pre-shared key.
	PSK []byte
	// RootCAs, if set, replaces the system roots when verifying the camouflage
	// certificate. Normally nil: a real camouflage site has a publicly trusted
	// cert. Used for self-signed camouflage sites in tests or private setups.
	RootCAs *x509.CertPool
	// Dial dials the server; nil uses a default dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Client dials targets through a HyperOne server.
type Client struct {
	cfg  ClientConfig
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewClient builds a Client from cfg.
func NewClient(cfg ClientConfig) *Client {
	dial := cfg.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: 10 * time.Second}
		dial = d.DialContext
	}
	return &Client{cfg: cfg, dial: dial}
}

// Dial opens a tunnelled connection to target (host:port) through the server.
// The returned conn is the inner stream; bytes written to it reach target.
func (c *Client) Dial(ctx context.Context, target socks.Addr) (*frame.Conn, error) {
	raw, err := c.dial(ctx, "tcp", c.cfg.Server)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			raw.Close()
		}
	}()

	// Tee inbound bytes so we can read the ServerHello random off the wire;
	// uTLS does not expose it directly.
	tee := &teeConn{Conn: raw}

	ucfg := &utls.Config{
		ServerName: c.cfg.SNI,
		RootCAs:    c.cfg.RootCAs,
		// Disable resumption so the ClientHello carries no PSK binder that
		// would need recomputation after we set the session_id.
		SessionTicketsDisabled: true,
	}
	u := utls.UClient(tee, ucfg, utls.HelloChrome_Auto)

	if err := u.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("build hello: %w", err)
	}
	// Ensure a client random exists, then authenticate it via the session_id.
	if len(u.HandshakeState.Hello.Random) != 32 {
		r := make([]byte, 32)
		if _, err := rand.Read(r); err != nil {
			return nil, err
		}
		u.HandshakeState.Hello.Random = r
	}
	clientRandom := append([]byte(nil), u.HandshakeState.Hello.Random...)
	sid, err := auth.Tag(c.cfg.PSK, clientRandom)
	if err != nil {
		return nil, err
	}
	u.HandshakeState.Hello.SessionId = sid
	if err := u.MarshalClientHello(); err != nil {
		return nil, fmt.Errorf("marshal hello: %w", err)
	}

	if err := u.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	serverRandom, err := serverHelloRandomFrom(tee.inbound.Bytes())
	if err != nil {
		return nil, fmt.Errorf("read server random: %w", err)
	}
	keys, err := auth.DeriveKeys(c.cfg.PSK, clientRandom, serverRandom)
	if err != nil {
		return nil, err
	}

	// Switch off the TLS session; speak inner records on the raw socket.
	fc, err := frame.NewConn(raw, keys.ClientToServer, keys.ServerToClient)
	if err != nil {
		return nil, err
	}
	enc, err := target.Encode()
	if err != nil {
		return nil, err
	}
	if _, err := fc.WriteData(enc); err != nil {
		return nil, err
	}
	ok = true
	return fc, nil
}

// serverHelloRandomFrom parses the first TLS record in b (the ServerHello) and
// returns its 32-byte random.
func serverHelloRandomFrom(b []byte) ([]byte, error) {
	rec, err := readRecord(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	return parseServerHelloRandom(rec)
}

// teeConn records every inbound byte into inbound while passing reads through.
type teeConn struct {
	net.Conn
	inbound bytes.Buffer
}

func (t *teeConn) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	if n > 0 {
		t.inbound.Write(b[:n])
	}
	return n, err
}
