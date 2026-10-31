// Package auth implements HyperOne's client authenticator.
//
// The authenticator lets a server distinguish a HyperOne client from an
// ordinary TLS client (a censor's active probe) without adding any field that
// a probe could observe. The proof is carried inside the TLS ClientHello
// session_id, a 32-byte field that is opaque on the wire and echoed verbatim by
// a TLS 1.3 server in compatibility mode, so it never changes how the handshake
// looks to a passive observer.
//
// Layout of the 32-byte session_id:
//
//	[0:4]   big-endian unix seconds (replay window anchor)
//	[4:16]  client random (per-connection uniqueness)
//	[16:32] HMAC-SHA256(PSK, epoch || nonce || transcript)[:16]
//
// The transcript is the ClientHello with the session_id bytes zeroed, so the
// tag commits to the exact hello the client sent. A server that does not hold
// the PSK cannot tell an authenticated session_id from a random one, so to any
// other observer the field is indistinguishable from a normal session ticket id.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"
)

const (
	// SessionIDLen is the fixed TLS session_id length HyperOne uses. 32 bytes
	// is what every modern browser sends, so anything shorter would stand out.
	SessionIDLen = 32

	epochLen = 4
	nonceLen = 12
	tagLen   = 16

	// DefaultSkew is how far a tag's timestamp may drift from the server clock
	// before it is rejected. It bounds the size of the replay cache.
	DefaultSkew = 90 * time.Second
)

var (
	// ErrBadLength is returned when a session_id is not SessionIDLen bytes.
	ErrBadLength = errors.New("auth: session_id wrong length")
	// ErrExpired is returned when a tag's timestamp is outside the skew window.
	ErrExpired = errors.New("auth: timestamp outside skew window")
	// ErrBadTag is returned when the HMAC does not verify under the PSK.
	ErrBadTag = errors.New("auth: tag mismatch")
	// ErrReplay is returned when a valid tag has been seen before.
	ErrReplay = errors.New("auth: replay detected")
)

// Now is the clock used for timestamps; overridable in tests.
var Now = time.Now

// Tag builds a 32-byte session_id authenticating transcript under psk. The
// transcript must be the ClientHello bytes with the session_id region already
// zeroed (see frame of reference in package doc).
func Tag(psk, transcript []byte) ([]byte, error) {
	out := make([]byte, SessionIDLen)
	binary.BigEndian.PutUint32(out[0:epochLen], uint32(Now().Unix()))
	if _, err := rand.Read(out[epochLen : epochLen+nonceLen]); err != nil {
		return nil, err
	}
	mac := compute(psk, out[:epochLen+nonceLen], transcript)
	copy(out[epochLen+nonceLen:], mac)
	return out, nil
}

// compute returns HMAC-SHA256(psk, header || transcript)[:tagLen].
func compute(psk, header, transcript []byte) []byte {
	h := hmac.New(sha256.New, psk)
	h.Write(header)
	h.Write(transcript)
	return h.Sum(nil)[:tagLen]
}

// Verifier checks tags and rejects replays. It is safe for concurrent use.
type Verifier struct {
	psk  []byte
	skew time.Duration
	seen *replayCache
}

// NewVerifier returns a Verifier for psk with the given replay window.
func NewVerifier(psk []byte, skew time.Duration) *Verifier {
	if skew <= 0 {
		skew = DefaultSkew
	}
	return &Verifier{psk: psk, skew: skew, seen: newReplayCache()}
}

// Verify checks that sessionID is a live, non-replayed tag over transcript.
// transcript must already have the session_id region zeroed. On success the
// tag is recorded so a later identical session_id is rejected as a replay.
func (v *Verifier) Verify(sessionID, transcript []byte) error {
	if len(sessionID) != SessionIDLen {
		return ErrBadLength
	}
	epoch := int64(binary.BigEndian.Uint32(sessionID[0:epochLen]))
	drift := Now().Unix() - epoch
	if drift < 0 {
		drift = -drift
	}
	if time.Duration(drift)*time.Second > v.skew {
		return ErrExpired
	}
	want := compute(v.psk, sessionID[:epochLen+nonceLen], transcript)
	got := sessionID[epochLen+nonceLen:]
	if subtle.ConstantTimeCompare(want, got) != 1 {
		return ErrBadTag
	}
	// Only now, after the tag proves PSK knowledge, consult the replay cache.
	// Checking earlier would let a probe populate the cache with random tags.
	if !v.seen.add(sessionID, epoch, v.skew) {
		return ErrReplay
	}
	return nil
}
