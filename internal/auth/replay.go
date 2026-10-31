package auth

import (
	"sync"
	"time"
)

// replayCache remembers tags that have been accepted so an identical tag
// replayed within the skew window is rejected. Entries older than the window
// can never be accepted again (they fail the timestamp check first), so they
// are evicted lazily to keep the cache bounded by the window, not by lifetime.
type replayCache struct {
	mu      sync.Mutex
	entries map[string]int64 // tag key -> epoch seconds
	lastGC  int64
}

func newReplayCache() *replayCache {
	return &replayCache{entries: make(map[string]int64)}
}

// add records sessionID and reports whether it was new. A false return means
// the tag was already present (a replay). epoch is the tag's own timestamp and
// skew is the acceptance window, used to drive eviction.
func (c *replayCache) add(sessionID []byte, epoch int64, skew time.Duration) bool {
	// Key on the random nonce plus HMAC; those 28 bytes are what make a tag
	// unique. Using the epoch too would be redundant since it is covered by
	// the HMAC input already.
	key := string(sessionID[epochLen:])

	c.mu.Lock()
	defer c.mu.Unlock()

	now := Now().Unix()
	c.gc(now, int64(skew/time.Second))

	if _, ok := c.entries[key]; ok {
		return false
	}
	c.entries[key] = epoch
	return true
}

// gc drops entries whose timestamp has fallen outside the window. It runs at
// most once per second to keep the common path cheap. Caller holds the lock.
func (c *replayCache) gc(now, windowSecs int64) {
	if now == c.lastGC {
		return
	}
	c.lastGC = now
	cutoff := now - windowSecs
	for k, ts := range c.entries {
		if ts < cutoff {
			delete(c.entries, k)
		}
	}
}
