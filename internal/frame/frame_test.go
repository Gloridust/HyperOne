package frame

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/Gloridust/HyperOne/internal/auth"
)

// pipePair returns two framed Conns wired together, as a client and server
// would be after key derivation.
func pipePair(t *testing.T) (client, server *Conn) {
	t.Helper()
	c2s := make([]byte, 32)
	s2c := make([]byte, 32)
	rand.Read(c2s)
	rand.Read(s2c)

	a, b := net.Pipe()
	client, err := NewConn(a, c2s, s2c)
	if err != nil {
		t.Fatal(err)
	}
	server, err = NewConn(b, s2c, c2s)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestDataRoundTrip(t *testing.T) {
	client, server := pipePair(t)
	defer client.Close()
	defer server.Close()

	msg := []byte("hello through a record that looks like TLS app-data")
	go func() { client.WriteData(msg) }()

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("got %q, want %q", got, msg)
	}
}

func TestLargePayloadSplitsIntoRecords(t *testing.T) {
	client, server := pipePair(t)
	defer client.Close()
	defer server.Close()

	msg := make([]byte, 5*MaxPlaintext+123)
	rand.Read(msg)
	go func() { client.WriteData(msg) }()

	got := make([]byte, len(msg))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("large payload mismatch")
	}
}

func TestPaddingIsTransparentToReader(t *testing.T) {
	client, server := pipePair(t)
	defer client.Close()
	defer server.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		client.WritePadding(200)
		client.WriteData([]byte("A"))
		client.WritePadding(4000)
		client.WriteData([]byte("B"))
	}()

	got := make([]byte, 2)
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "AB" {
		t.Fatalf("got %q, want AB (padding leaked into stream)", got)
	}
	wg.Wait()
}

func TestWireLooksLikeTLSAppData(t *testing.T) {
	// Inspect the actual bytes on the wire: the first record must carry the
	// TLS 1.3 application_data header.
	var buf bytes.Buffer
	c, err := NewConn(nopCloser{&buf}, make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	c.WriteData([]byte("x"))

	wire := buf.Bytes()
	if len(wire) < hdrLen {
		t.Fatal("no record written")
	}
	if wire[0] != 0x17 || wire[1] != 0x03 || wire[2] != 0x03 {
		t.Fatalf("header = % x, want 17 03 03", wire[:3])
	}
}

func TestTamperedCiphertextFailsAuth(t *testing.T) {
	a, b := net.Pipe()
	key := make([]byte, 32)
	sender, _ := NewConn(writeOnly{a}, key, key)
	go func() {
		sender.WriteData([]byte("payload"))
		a.Close()
	}()

	// Flip a byte in the ciphertext region before the receiver sees it.
	raw, _ := io.ReadAll(b)
	if len(raw) > hdrLen {
		raw[hdrLen] ^= 0x01
	}
	recv, _ := NewConn(readOnly{bytes.NewReader(raw)}, key, key)
	if _, err := recv.Read(make([]byte, 16)); err != ErrAuth {
		t.Fatalf("Read tampered = %v, want ErrAuth", err)
	}
}

// Ensure keys from auth.DeriveKeys slot straight into NewConn.
func TestInteropWithDerivedKeys(t *testing.T) {
	cr := make([]byte, 32)
	sr := make([]byte, 32)
	rand.Read(cr)
	rand.Read(sr)
	ks, err := auth.DeriveKeys([]byte("psk"), cr, sr)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	client, _ := NewConn(a, ks.ClientToServer, ks.ServerToClient)
	server, _ := NewConn(b, ks.ServerToClient, ks.ClientToServer)
	defer client.Close()
	defer server.Close()

	go client.WriteData([]byte("ok"))
	got := make([]byte, 2)
	io.ReadFull(server, got)
	if string(got) != "ok" {
		t.Fatalf("got %q", got)
	}
}

type nopCloser struct{ io.ReadWriter }

func (nopCloser) Close() error { return nil }

type writeOnly struct{ io.Writer }

func (writeOnly) Read([]byte) (int, error) { return 0, io.EOF }
func (writeOnly) Close() error             { return nil }

type readOnly struct{ io.Reader }

func (readOnly) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (readOnly) Close() error              { return nil }
