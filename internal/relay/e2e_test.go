package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/Gloridust/HyperOne/internal/socks"
)

// camouflage spins up a real TLS 1.3 server with a self-signed cert for
// "example.test". It echoes any application data, standing in for a genuine
// site. Session tickets are disabled so no post-handshake records race the
// HyperOne handoff. It returns the listen address and the cert pool to trust.
func camouflage(t *testing.T) (addr string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		DNSNames:     []string{"example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	pool = x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	pool.AddCert(parsed)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:           []tls.Certificate{cert},
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // echo
			}(c)
		}
	}()
	return ln.Addr().String(), pool
}

// targetEcho is a plain TCP server that echoes, standing in for the real
// destination the tunnel dials.
func targetEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { defer c.Close(); io.Copy(c, c) }(c)
		}
	}()
	return ln.Addr().String()
}

func startServer(t *testing.T, psk []byte, camo string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := NewServer(ServerConfig{PSK: psk, Camouflage: camo})
	go srv.Serve(ln)
	return ln.Addr().String()
}

func TestEndToEndTunnel(t *testing.T) {
	psk := []byte("shared secret for the test")
	camo, pool := camouflage(t)
	target := targetEcho(t)
	serverAddr := startServer(t, psk, camo)

	client := NewClient(ClientConfig{Server: serverAddr, SNI: "example.test", PSK: psk, RootCAs: pool})

	host, portStr, _ := net.SplitHostPort(target)
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, socks.Addr{Host: host, Port: port})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("round trip through the HyperOne tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

// TestProbeSeesRealSite checks the fallback path: a client with the wrong PSK
// (a stand-in for an active probe) is relayed to the camouflage site and
// completes a genuine TLS handshake against its real certificate.
func TestProbeSeesRealSite(t *testing.T) {
	psk := []byte("the real psk")
	camo, pool := camouflage(t)
	serverAddr := startServer(t, psk, camo)

	raw, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()

	// A probe using a different (or no) key. We use standard uTLS with no
	// HyperOne tag; the session_id will not authenticate.
	u := utls.UClient(raw, &utls.Config{
		ServerName: "example.test",
		RootCAs:    pool,
	}, utls.HelloChrome_Auto)
	if err := u.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("probe handshake should reach real site: %v", err)
	}
	// The probe can speak to the real echo site.
	if _, err := u.Write([]byte("ping")); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(u, got); err != nil {
		t.Fatalf("probe read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("probe got %q, want ping", got)
	}
	if cs := u.ConnectionState(); cs.PeerCertificates[0].Subject.CommonName != "example.test" {
		t.Fatalf("probe saw cert CN %q", cs.PeerCertificates[0].Subject.CommonName)
	}
}
