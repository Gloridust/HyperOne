// Package relay implements HyperOne's outer layer: a ShadowTLS-style front
// where a real TLS handshake to a genuine camouflage site is relayed through
// the server, and only a client that proves knowledge of the PSK is switched
// onto the inner tunnel. Everyone else — including a censor's active probe —
// transparently reaches the real site, with its real certificate and real
// post-handshake behavior.
package relay

import (
	"errors"
	"fmt"
	"io"
)

// TLS record content types.
const (
	recHandshake   byte = 0x16
	recChangeCipher byte = 0x14
	recAppData     byte = 0x17
	recAlert       byte = 0x15
)

// TLS handshake message types.
const (
	hsClientHello byte = 0x01
	hsServerHello byte = 0x02
)

const (
	tlsHdrLen    = 5
	randomLen    = 32
	maxRecordLen = 1 << 14 // RFC 8446 plaintext limit; ciphertext may add a little
	maxCiphertextLen = maxRecordLen + 256
)

var (
	errShortRecord = errors.New("relay: truncated TLS record")
	errNotHandshake = errors.New("relay: expected handshake record")
	errNotClientHello = errors.New("relay: handshake is not a ClientHello")
	errNotServerHello = errors.New("relay: handshake is not a ServerHello")
)

// record is one raw TLS record, header included.
type record struct {
	typ byte
	raw []byte // full record: 5-byte header + body
}

// readRecord reads exactly one TLS record from r, returning its content type
// and the complete raw bytes (so they can be relayed verbatim).
func readRecord(r io.Reader) (record, error) {
	hdr := make([]byte, tlsHdrLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return record{}, err
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n == 0 || n > maxCiphertextLen {
		return record{}, fmt.Errorf("relay: bad record length %d", n)
	}
	raw := make([]byte, tlsHdrLen+n)
	copy(raw, hdr)
	if _, err := io.ReadFull(r, raw[tlsHdrLen:]); err != nil {
		return record{}, err
	}
	return record{typ: hdr[0], raw: raw}, nil
}

// clientHello carries the two fields HyperOne needs from a parsed ClientHello.
type clientHello struct {
	random    []byte // 32 bytes
	sessionID []byte // 0..32 bytes as sent
}

// parseClientHello extracts the random and session_id from a handshake record.
// It assumes the ClientHello fits in a single record, which is true for every
// normal browser hello (well under 16 KiB).
func parseClientHello(rec record) (clientHello, error) {
	if rec.typ != recHandshake {
		return clientHello{}, errNotHandshake
	}
	b := rec.raw[tlsHdrLen:]
	// handshake header: type(1) length(3)
	if len(b) < 4 || b[0] != hsClientHello {
		return clientHello{}, errNotClientHello
	}
	body := b[4:]
	// body: client_version(2) random(32) session_id_len(1) session_id(..)
	if len(body) < 2+randomLen+1 {
		return clientHello{}, errShortRecord
	}
	random := body[2 : 2+randomLen]
	sidLen := int(body[2+randomLen])
	off := 2 + randomLen + 1
	if len(body) < off+sidLen {
		return clientHello{}, errShortRecord
	}
	return clientHello{
		random:    random,
		sessionID: body[off : off+sidLen],
	}, nil
}

// parseServerHelloRandom extracts the 32-byte random from a ServerHello record.
// Both peers read it off the wire to derive matching inner keys.
func parseServerHelloRandom(rec record) ([]byte, error) {
	if rec.typ != recHandshake {
		return nil, errNotHandshake
	}
	b := rec.raw[tlsHdrLen:]
	if len(b) < 4 || b[0] != hsServerHello {
		return nil, errNotServerHello
	}
	body := b[4:]
	if len(body) < 2+randomLen {
		return nil, errShortRecord
	}
	return body[2 : 2+randomLen], nil
}
