// Package frame carries HyperOne's inner channel as a stream of records that
// are byte-for-byte shaped like TLS 1.3 application_data records.
//
// Every record on the wire is:
//
//	0x17 0x03 0x03  len(2)  ciphertext(len)
//
// which is exactly the five-byte header a TLS 1.3 record uses for
// application_data (content type 23, legacy version 0x0303). After a real TLS
// handshake completes, all application traffic looks like this, so a HyperOne
// record carrying tunnelled data is indistinguishable at the record layer from
// the encrypted page the camouflage site would have served.
//
// The ciphertext is ChaCha20-Poly1305 over an inner plaintext whose first byte
// is a record type (data or padding) so the receiver can drop padding records
// without handing them to the stream layer. The nonce is a per-direction
// 64-bit counter in the low 8 bytes of the 12-byte nonce; it never repeats
// within a session because the key is session-unique (see auth.DeriveKeys).
package frame

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	hdrLen = 5
	// MaxRecord is the largest TLS record payload (2^14). Real TLS never
	// exceeds it, so neither may we, or the length field would betray us.
	MaxRecord = 16384
	// MaxPlaintext leaves room for the Poly1305 tag and the 1-byte inner type
	// inside a single record.
	MaxPlaintext = MaxRecord - chacha20poly1305.Overhead - 1
)

// Inner record types, the first plaintext byte of every record.
const (
	typeData byte = 0x00
	typePad  byte = 0x01
)

var (
	// ErrOversize is returned when a record claims more than MaxRecord bytes.
	ErrOversize = errors.New("frame: record exceeds TLS maximum")
	// ErrAuth is returned when a record fails AEAD authentication.
	ErrAuth = errors.New("frame: record authentication failed")
)

var tlsAppDataHeader = [3]byte{0x17, 0x03, 0x03}

// Conn is a bidirectional framed connection over an underlying stream.
type Conn struct {
	raw io.ReadWriteCloser

	seal    cipher.AEAD
	open    cipher.AEAD
	sealCtr uint64
	openCtr uint64

	// readBuf holds decrypted-but-unconsumed data record payload.
	readBuf []byte
	hdr     [hdrLen]byte
}

// NewConn wraps raw with the given directional keys. sendKey encrypts outbound
// records; recvKey decrypts inbound ones. The caller picks which of the two
// SessionKeys fields maps to which direction based on its role.
func NewConn(raw io.ReadWriteCloser, sendKey, recvKey []byte) (*Conn, error) {
	seal, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, err
	}
	open, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, err
	}
	return &Conn{raw: raw, seal: seal, open: open}, nil
}

func (c *Conn) nonce(ctr uint64) []byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(n[4:], ctr)
	return n[:]
}

// writeRecord encrypts one inner record of the given type and payload. payload
// must not exceed MaxPlaintext.
func (c *Conn) writeRecord(typ byte, payload []byte) error {
	if len(payload) > MaxPlaintext {
		return ErrOversize
	}
	plain := make([]byte, 1+len(payload))
	plain[0] = typ
	copy(plain[1:], payload)

	nonce := c.nonce(c.sealCtr)
	c.sealCtr++

	rec := make([]byte, hdrLen, hdrLen+len(plain)+chacha20poly1305.Overhead)
	rec[0], rec[1], rec[2] = tlsAppDataHeader[0], tlsAppDataHeader[1], tlsAppDataHeader[2]
	sealed := c.seal.Seal(rec[hdrLen:], nonce, plain, nil)
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(sealed)))
	rec = rec[:hdrLen+len(sealed)]

	_, err := c.raw.Write(rec)
	return err
}

// WriteData sends payload as one or more data records, splitting on
// MaxPlaintext. It returns the number of plaintext bytes written.
func (c *Conn) WriteData(payload []byte) (int, error) {
	total := 0
	for len(payload) > 0 {
		chunk := payload
		if len(chunk) > MaxPlaintext {
			chunk = chunk[:MaxPlaintext]
		}
		if err := c.writeRecord(typeData, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		payload = payload[len(chunk):]
	}
	return total, nil
}

// Write sends p as tunnelled data, satisfying io.Writer. It is a thin alias
// for WriteData so a Conn can be spliced with io.Copy.
func (c *Conn) Write(p []byte) (int, error) { return c.WriteData(p) }

// WritePadding sends a padding record of n random-free zero bytes. The receiver
// authenticates and discards it. Padding records let the shaper add cover bytes
// and break up the size pattern of the inner traffic.
func (c *Conn) WritePadding(n int) error {
	if n > MaxPlaintext {
		n = MaxPlaintext
	}
	return c.writeRecord(typePad, make([]byte, n))
}

// Read returns the next chunk of tunnelled data, transparently skipping padding
// records. It satisfies io.Reader semantics for the data stream.
func (c *Conn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		if err := c.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// fill reads and decrypts exactly one record, loading readBuf if it is a data
// record or looping again (via the caller) if it is padding.
func (c *Conn) fill() error {
	if _, err := io.ReadFull(c.raw, c.hdr[:]); err != nil {
		return err
	}
	if c.hdr[0] != tlsAppDataHeader[0] {
		return fmt.Errorf("frame: unexpected content type 0x%02x", c.hdr[0])
	}
	n := int(binary.BigEndian.Uint16(c.hdr[3:5]))
	if n > MaxRecord || n < chacha20poly1305.Overhead+1 {
		return ErrOversize
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.raw, buf); err != nil {
		return err
	}
	nonce := c.nonce(c.openCtr)
	c.openCtr++
	plain, err := c.open.Open(buf[:0], nonce, buf, nil)
	if err != nil {
		return ErrAuth
	}
	if len(plain) == 0 {
		return ErrAuth
	}
	switch plain[0] {
	case typeData:
		c.readBuf = plain[1:]
	case typePad:
		// discard; caller's loop reads the next record
	default:
		return fmt.Errorf("frame: unknown inner type 0x%02x", plain[0])
	}
	return nil
}

// Close closes the underlying stream.
func (c *Conn) Close() error { return c.raw.Close() }

// TrialOpen reports whether raw is a well-formed inner record that
// authenticates under recvKey at counter 0. The relay uses it to find the
// handoff point: the client's real TLS Finished (encrypted under the genuine
// TLS keys) fails to open, while the first inner record succeeds. raw must be a
// complete record including its 5-byte header.
func TrialOpen(recvKey, raw []byte) bool {
	if len(raw) < hdrLen || raw[0] != tlsAppDataHeader[0] {
		return false
	}
	n := int(binary.BigEndian.Uint16(raw[3:5]))
	if n != len(raw)-hdrLen || n < chacha20poly1305.Overhead+1 {
		return false
	}
	aead, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return false
	}
	var nonce [chacha20poly1305.NonceSize]byte // counter 0
	body := append([]byte(nil), raw[hdrLen:]...)
	_, err = aead.Open(body[:0], nonce[:], body, nil)
	return err == nil
}
