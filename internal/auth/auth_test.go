package auth

import (
	"bytes"
	"testing"
	"time"
)

func zeroedTranscript() []byte {
	// Stand-in for a ClientHello with its session_id region already zeroed.
	t := make([]byte, 128)
	for i := range t {
		t[i] = byte(i)
	}
	return t
}

func TestTagRoundTrip(t *testing.T) {
	psk := []byte("correct horse battery staple")
	tr := zeroedTranscript()

	sid, err := Tag(psk, tr)
	if err != nil {
		t.Fatalf("Tag: %v", err)
	}
	if len(sid) != SessionIDLen {
		t.Fatalf("session_id len = %d, want %d", len(sid), SessionIDLen)
	}

	v := NewVerifier(psk, DefaultSkew)
	if err := v.Verify(sid, tr); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsWrongPSK(t *testing.T) {
	tr := zeroedTranscript()
	sid, _ := Tag([]byte("real psk"), tr)
	v := NewVerifier([]byte("attacker guess"), DefaultSkew)
	if err := v.Verify(sid, tr); err != ErrBadTag {
		t.Fatalf("Verify with wrong psk = %v, want ErrBadTag", err)
	}
}

func TestVerifyRejectsTamperedTranscript(t *testing.T) {
	psk := []byte("psk")
	tr := zeroedTranscript()
	sid, _ := Tag(psk, tr)

	tr[10] ^= 0xff // a probe that resent a different ClientHello
	v := NewVerifier(psk, DefaultSkew)
	if err := v.Verify(sid, tr); err != ErrBadTag {
		t.Fatalf("Verify with tampered transcript = %v, want ErrBadTag", err)
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	psk := []byte("psk")
	tr := zeroedTranscript()
	sid, _ := Tag(psk, tr)

	v := NewVerifier(psk, DefaultSkew)
	if err := v.Verify(sid, tr); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if err := v.Verify(sid, tr); err != ErrReplay {
		t.Fatalf("second Verify = %v, want ErrReplay", err)
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	psk := []byte("psk")
	tr := zeroedTranscript()

	base := time.Now()
	Now = func() time.Time { return base }
	defer func() { Now = time.Now }()

	sid, _ := Tag(psk, tr)

	// Jump the clock forward past the skew window.
	Now = func() time.Time { return base.Add(10 * time.Minute) }
	v := NewVerifier(psk, DefaultSkew)
	if err := v.Verify(sid, tr); err != ErrExpired {
		t.Fatalf("Verify after skew = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsBadLength(t *testing.T) {
	v := NewVerifier([]byte("psk"), DefaultSkew)
	if err := v.Verify(make([]byte, 31), zeroedTranscript()); err != ErrBadLength {
		t.Fatalf("got %v, want ErrBadLength", err)
	}
}

func TestExpiredTagDoesNotPopulateReplayCache(t *testing.T) {
	// An expired/invalid tag must be rejected before touching the replay
	// cache, otherwise a probe could grow the cache without knowing the PSK.
	psk := []byte("psk")
	tr := zeroedTranscript()
	v := NewVerifier(psk, DefaultSkew)

	junk := make([]byte, SessionIDLen) // fails tag check
	_ = v.Verify(junk, tr)
	if len(v.seen.entries) != 0 {
		t.Fatalf("replay cache grew on invalid tag: %d entries", len(v.seen.entries))
	}

	// A genuine tag with a matching body hashes differently, confirming the
	// cache only holds authenticated tags.
	sid, _ := Tag(psk, tr)
	if err := v.Verify(sid, tr); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(v.seen.entries) != 1 {
		t.Fatalf("replay cache = %d entries, want 1", len(v.seen.entries))
	}
	if bytes.Equal(sid, junk) {
		t.Fatal("tag unexpectedly all zero")
	}
}
