package packet

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// testAddrs returns the local and remote addresses of a test connection.
func testAddrs(localPort int) [2]*net.TCPAddr {
	return [2]*net.TCPAddr{
		{IP: net.ParseIP("192.168.1.11"), Port: localPort},
		{IP: net.ParseIP("203.0.113.1"), Port: 443},
	}
}

func TestSeqTracker_PutThenWait(t *testing.T) {
	tr := NewSeqTracker(time.Minute)
	addrs := testAddrs(50000)
	key := SeqKey(addrs[0], addrs[1])

	tr.Put(key, SeqAck{Seq: 100, Ack: 200})

	seq, ok := tr.Wait(context.Background(), key, time.Second)
	assert.True(t, ok)
	assert.Equal(t, SeqAck{Seq: 100, Ack: 200}, seq)
	assert.Equal(t, 0, tr.Len(), "entry is removed once consumed")

	_, ok = tr.Wait(context.Background(), key, 10*time.Millisecond)
	assert.False(t, ok, "entry is consumed only once")
}

func TestSeqTracker_WaitThenPut(t *testing.T) {
	tr := NewSeqTracker(time.Minute)
	addrs := testAddrs(50000)
	key := SeqKey(addrs[0], addrs[1])

	type result struct {
		seq SeqAck
		ok  bool
	}
	done := make(chan result, 1)
	go func() {
		seq, ok := tr.Wait(context.Background(), key, 5*time.Second)
		done <- result{seq, ok}
	}()

	// Let Wait park before Put.
	assert.Eventually(
		t,
		func() bool { return tr.Len() == 1 },
		time.Second,
		time.Millisecond,
	)

	start := time.Now()
	tr.Put(key, SeqAck{Seq: 1, Ack: 2})

	select {
	case r := <-done:
		assert.True(t, r.ok)
		assert.Equal(t, SeqAck{Seq: 1, Ack: 2}, r.seq)
		assert.Less(
			t,
			time.Since(start),
			time.Second,
			"Put wakes Wait up without waiting for the timeout",
		)
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after Put")
	}
	assert.Equal(t, 0, tr.Len())
}

func TestSeqTracker_WaitTimeout(t *testing.T) {
	tr := NewSeqTracker(time.Minute)
	addrs := testAddrs(50000)

	_, ok := tr.Wait(
		context.Background(),
		SeqKey(addrs[0], addrs[1]),
		10*time.Millisecond,
	)
	assert.False(t, ok)
	assert.Equal(t, 0, tr.Len(), "placeholder is removed on timeout")
}

func TestSeqTracker_WaitCanceled(t *testing.T) {
	tr := NewSeqTracker(time.Minute)
	addrs := testAddrs(50000)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, ok := tr.Wait(ctx, SeqKey(addrs[0], addrs[1]), 5*time.Second)
	assert.False(t, ok)
	assert.Less(t, time.Since(start), time.Second)
	assert.Equal(t, 0, tr.Len())
}

func TestSeqTracker_KeysAreDistinctPerConnection(t *testing.T) {
	tr := NewSeqTracker(time.Minute)
	a := testAddrs(50000)
	b := testAddrs(50001)

	tr.Put(SeqKey(a[0], a[1]), SeqAck{Seq: 1})
	tr.Put(SeqKey(b[0], b[1]), SeqAck{Seq: 2})

	seqA, okA := tr.Wait(context.Background(), SeqKey(a[0], a[1]), time.Second)
	seqB, okB := tr.Wait(context.Background(), SeqKey(b[0], b[1]), time.Second)
	assert.True(t, okA)
	assert.True(t, okB)
	assert.Equal(t, uint32(1), seqA.Seq)
	assert.Equal(t, uint32(2), seqB.Seq)
}

func TestSeqTracker_KeyIgnoresIPv4Form(t *testing.T) {
	local4 := &net.TCPAddr{IP: net.IPv4(192, 168, 1, 11).To4(), Port: 50000}
	local16 := &net.TCPAddr{IP: net.IPv4(192, 168, 1, 11), Port: 50000}
	remote := &net.TCPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443}

	assert.Equal(t, SeqKey(local4, remote), SeqKey(local16, remote))
}

func TestSeqTracker_ExpiresUnconsumedEntries(t *testing.T) {
	tr := NewSeqTracker(10 * time.Millisecond)
	a := testAddrs(50000)
	b := testAddrs(50001)

	tr.Put(SeqKey(a[0], a[1]), SeqAck{Seq: 1})
	time.Sleep(30 * time.Millisecond)

	// Any later call sweeps expired entries.
	tr.Put(SeqKey(b[0], b[1]), SeqAck{Seq: 2})
	assert.Equal(t, 1, tr.Len())

	_, ok := tr.Wait(context.Background(), SeqKey(a[0], a[1]), 10*time.Millisecond)
	assert.False(t, ok)
}

func TestSeqTracker_WaitSurvivesSweepWithShortTTL(t *testing.T) {
	// ttl is shorter than the wait: the placeholder must not be swept away
	// while Wait is parked, or the later Put would wake nobody.
	tr := NewSeqTracker(5 * time.Millisecond)
	a := testAddrs(50000)
	b := testAddrs(50001)
	key := SeqKey(a[0], a[1])

	done := make(chan bool, 1)
	go func() {
		_, ok := tr.Wait(context.Background(), key, 2*time.Second)
		done <- ok
	}()
	assert.Eventually(
		t,
		func() bool { return tr.Len() == 1 },
		time.Second,
		time.Millisecond,
	)

	// Let ttl pass, then trigger a sweep through another key.
	time.Sleep(20 * time.Millisecond)
	tr.Put(SeqKey(b[0], b[1]), SeqAck{Seq: 9})
	tr.Put(key, SeqAck{Seq: 1})

	select {
	case ok := <-done:
		assert.True(t, ok)
	case <-time.After(3 * time.Second):
		t.Fatal("Wait did not return")
	}
}
