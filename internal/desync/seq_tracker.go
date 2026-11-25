package desync

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/xvzc/spoofdpi/internal/netutil"
)

// SeqAck holds the sequence and acknowledgment numbers the local host uses
// for its next segment on a TCP connection.
type SeqAck struct {
	Seq uint32
	Ack uint32
}

type seqEntry struct {
	seq       SeqAck
	filled    bool
	ready     chan struct{} // closed once seq is filled
	expiresAt time.Time
}

// SeqTracker records, per TCP connection, the sequence numbers learned from
// the server's SYN/ACK, so that crafted packets can carry the connection's
// real sequence numbers.
//
// The sniffer and the sender race: the sender may ask for a connection
// before the sniffer goroutine has processed its SYN/ACK. Wait handles both
// orders by parking on a per-connection channel that Put closes.
type SeqTracker struct {
	mu        sync.Mutex
	entries   map[netutil.NATKey]*seqEntry
	ttl       time.Duration
	nextSweep time.Time
}

// NewSeqTracker creates a SeqTracker whose entries expire after ttl if they
// are never consumed by Wait.
func NewSeqTracker(ttl time.Duration) *SeqTracker {
	return &SeqTracker{
		entries: make(map[netutil.NATKey]*seqEntry),
		ttl:     ttl,
	}
}

// CanLearnSeq reports whether the sniffer can learn sequence numbers for a
// connection to remote. The SYN/ACK filter only captures IPv4, so waiting
// for other connections would always time out.
func CanLearnSeq(remote net.IP) bool {
	return remote.To4() != nil
}

// SeqKey builds the key for a connection from the local host's view.
func SeqKey(local, remote *net.TCPAddr) netutil.NATKey {
	return netutil.NewNATKey(local.IP, local.Port, remote.IP, remote.Port)
}

// Put records seq for the connection identified by key and wakes up any
// pending Wait for it.
func (t *SeqTracker) Put(key netutil.NATKey, seq SeqAck) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	t.sweepLocked(now)

	e := t.entries[key]
	if e == nil {
		e = &seqEntry{ready: make(chan struct{})}
		t.entries[key] = e
	}

	e.seq = seq
	e.expiresAt = now.Add(t.ttl)
	if !e.filled {
		e.filled = true
		close(e.ready)
	}
}

// Wait returns the sequence numbers recorded for key, waiting up to timeout
// for Put if they are not recorded yet. The entry is removed once returned.
// ok is false if nothing was recorded in time or ctx was canceled.
func (t *SeqTracker) Wait(
	ctx context.Context,
	key netutil.NATKey,
	timeout time.Duration,
) (seq SeqAck, ok bool) {
	t.mu.Lock()
	now := time.Now()
	t.sweepLocked(now)

	e := t.entries[key]
	if e == nil {
		// Keep the placeholder alive for the whole wait, so a sweep cannot
		// drop it while this call is parked on its channel.
		e = &seqEntry{ready: make(chan struct{}), expiresAt: now.Add(timeout + t.ttl)}
		t.entries[key] = e
	}

	if e.filled {
		seq = e.seq
		delete(t.entries, key)
		t.mu.Unlock()
		return seq, true
	}
	t.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-e.ready:
	case <-timer.C:
	case <-ctx.Done():
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.entries[key] == e {
		delete(t.entries, key)
	}
	if !e.filled {
		return SeqAck{}, false
	}

	return e.seq, true
}

// Len returns the number of tracked connections.
func (t *SeqTracker) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return len(t.entries)
}

// sweepLocked drops expired entries, at most once per ttl.
func (t *SeqTracker) sweepLocked(now time.Time) {
	if now.Before(t.nextSweep) {
		return
	}
	t.nextSweep = now.Add(t.ttl)

	for k, e := range t.entries {
		if now.After(e.expiresAt) {
			delete(t.entries, k)
		}
	}
}
