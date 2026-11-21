package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var localIP = net.IPv4(192, 0, 2, 1)

// fakeSource is a packet source fed through frames. A read with nothing to
// return fails with errReadTimeout after a short wait, as a capture handle
// with a read timeout does.
type fakeSource struct {
	t       *testing.T
	frames  chan []byte
	readErr chan error
	closed  atomic.Bool
}

func newFakeSource(t *testing.T) *fakeSource {
	return &fakeSource{t: t, frames: make(chan []byte, 64), readErr: make(chan error, 1)}
}

func (s *fakeSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if s.closed.Load() {
		s.t.Error("read after close")
	}
	select {
	case f := <-s.frames:
		return f, gopacket.CaptureInfo{}, nil
	case err := <-s.readErr:
		return nil, gopacket.CaptureInfo{}, err
	case <-time.After(10 * time.Millisecond):
		return nil, gopacket.CaptureInfo{}, errReadTimeout
	}
}

func (s *fakeSource) LinkType() layers.LinkType { return layers.LinkTypeEthernet }
func (s *fakeSource) Close()                    { s.closed.Store(true) }

// frame builds an Ethernet/IP/TCP frame from src to dst:dstPort.
func frame(
	t *testing.T,
	src netip.AddrPort,
	dst net.IP,
	dstPort uint16,
	ttl uint8,
	syn, ack bool,
) []byte {
	t.Helper()
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(src.Port()),
		DstPort: layers.TCPPort(dstPort),
		SYN:     syn,
		ACK:     ack,
		Window:  65535,
	}
	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11},
	}
	var ip gopacket.SerializableLayer
	if src.Addr().Is4() {
		eth.EthernetType = layers.EthernetTypeIPv4
		ip4 := &layers.IPv4{
			Version: 4, TTL: ttl, Protocol: layers.IPProtocolTCP,
			SrcIP: src.Addr().AsSlice(), DstIP: dst.To4(),
		}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip4))
		ip = ip4
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
		ip6 := &layers.IPv6{
			Version: 6, HopLimit: ttl, NextHeader: layers.IPProtocolTCP,
			SrcIP: src.Addr().AsSlice(), DstIP: dst,
		}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(ip6))
		ip = ip6
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, eth, ip, tcp))
	return buf.Bytes()
}

// synAck builds a SYN/ACK frame from src to the local port dstPort.
func synAck(t *testing.T, src netip.AddrPort, dstPort uint16, ttl uint8) []byte {
	return frame(t, src, localIP, dstPort, ttl, true, true)
}

// udpFrame builds an Ethernet/IPv4/UDP frame from src to the local port
// dstPort.
func udpFrame(t *testing.T, src netip.AddrPort, dstPort uint16, ttl uint8) []byte {
	t.Helper()
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(src.Port()),
		DstPort: layers.UDPPort(dstPort),
	}
	ip := &layers.IPv4{
		Version: 4, TTL: ttl, Protocol: layers.IPProtocolUDP,
		SrcIP: src.Addr().AsSlice(), DstIP: localIP.To4(),
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(
		t,
		gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload("x")),
	)
	return buf.Bytes()
}

// synAckLearner starts a SYN/ACK learner on src for servers.
func synAckLearner(src *fakeSource, servers ...netip.Addr) *learner {
	return newLearner(src, parseSynAck, servers)
}

func TestLearner_Await(t *testing.T) {
	src := newFakeSource(t)
	l := synAckLearner(src, testServer.Addr())
	defer l.Close()

	other := netip.MustParseAddrPort("203.0.113.99:443")
	src.frames <- synAck(t, other, 40001, 50)                                     // another server
	src.frames <- synAck(t, netip.AddrPortFrom(testServer.Addr(), 80), 40001, 51) // another port
	src.frames <- synAck(t, testServer, 40002, 52)                                // another connection
	src.frames <- frame(t, testServer, localIP, 40001, 53, true, false)           // a SYN
	src.frames <- frame(t, testServer, localIP, 40001, 53, false, true)           // an ACK
	go func() {
		time.Sleep(50 * time.Millisecond)
		src.frames <- synAck(t, testServer, 40001, 54)
	}()

	got, ok := l.await(context.Background(), testServer, 40001, 2*time.Second)
	require.True(t, ok)
	assert.Equal(
		t,
		observation{src: testServer, dstPort: 40001, ttlLeft: 54, hops: 10},
		got,
	)
}

func TestLearner_AwaitTimesOut(t *testing.T) {
	src := newFakeSource(t)
	l := synAckLearner(src, testServer.Addr())
	defer l.Close()

	src.frames <- synAck(t, testServer, 40002, 52)
	start := time.Now()
	_, ok := l.await(context.Background(), testServer, 40001, 100*time.Millisecond)
	assert.False(t, ok)
	assert.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond)
}

func TestLearner_AwaitCancel(t *testing.T) {
	l := synAckLearner(newFakeSource(t), testServer.Addr())
	defer l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, ok := l.await(ctx, testServer, 40001, time.Minute)
	assert.False(t, ok)
}

func TestLearner_IgnoresIPv6(t *testing.T) {
	v6 := netip.MustParseAddrPort("[2001:db8::10]:443")
	src := newFakeSource(t)
	l := synAckLearner(src, v6.Addr())
	defer l.Close()

	src.frames <- frame(t, v6, net.ParseIP("2001:db8::1"), 40001, 54, true, true)
	_, ok := l.await(context.Background(), v6, 40001, 100*time.Millisecond)
	assert.False(t, ok)
	assert.Zero(t, l.mark())
}

func TestLearner_IgnoresUnprobedServers(t *testing.T) {
	src := newFakeSource(t)
	l := synAckLearner(src, testServer.Addr())
	defer l.Close()

	other := netip.MustParseAddrPort("203.0.113.99:443")
	src.frames <- synAck(t, other, 40001, 54)
	_, ok := l.await(context.Background(), other, 40001, 100*time.Millisecond)
	assert.False(t, ok)
	assert.Zero(t, l.mark())
}

func TestLearner_UDP(t *testing.T) {
	src := newFakeSource(t)
	l := newLearner(src, parseUDP, []netip.Addr{testServer.Addr()})
	defer l.Close()

	src.frames <- synAck(t, testServer, 40001, 50) // not UDP
	src.frames <- udpFrame(t, testServer, 40001, 52)
	got, ok := l.await(context.Background(), testServer, 40001, 2*time.Second)
	require.True(t, ok)
	assert.Equal(
		t,
		observation{src: testServer, dstPort: 40001, ttlLeft: 52, hops: 12},
		got,
	)
	assert.Equal(t, 1, l.mark(), "the SYN/ACK is not kept")
}

func TestLearner_HopsSince(t *testing.T) {
	src := newFakeSource(t)
	l := synAckLearner(src, testServer.Addr(), netip.MustParseAddr("203.0.113.99"))
	defer l.Close()

	src.frames <- synAck(t, testServer, 40001, 40) // before the mark
	_, ok := l.await(context.Background(), testServer, 40001, time.Second)
	require.True(t, ok)

	mark := l.mark()
	for i, ttl := range []uint8{52, 54, 52, 53} {
		src.frames <- synAck(t, testServer, uint16(40010+i), ttl)
	}
	src.frames <- synAck(t, netip.MustParseAddrPort("203.0.113.99:443"), 40020, 30)
	_, ok = l.await(
		context.Background(),
		netip.MustParseAddrPort("203.0.113.99:443"),
		40020,
		time.Second,
	)
	require.True(t, ok)

	assert.Equal(t, []uint8{10, 11, 12}, l.hopsSince(mark, testServer))
	assert.Nil(t, l.hopsSince(mark, netip.MustParseAddrPort("203.0.113.98:443")))
}

func TestLearner_ReadErrorStops(t *testing.T) {
	src := newFakeSource(t)
	l := synAckLearner(src)
	defer l.Close()

	src.readErr <- errors.New("device gone")
	assert.Eventually(
		t,
		func() bool { return l.err() != nil },
		5*time.Second,
		5*time.Millisecond,
	)
	assert.EqualError(t, l.err(), "capture stopped: device gone")
}

func TestLearner_CloseAfterReaderStops(t *testing.T) {
	src := newFakeSource(t)
	l := synAckLearner(src)

	done := make(chan struct{})
	go func() { l.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return")
	}
	assert.True(t, src.closed.Load())
}

// feed feeds f to src and waits until l has read it, as a SYN/ACK is
// captured before the connect that got it returns.
func feed(l *learner, src *fakeSource, f []byte) {
	before := l.mark()
	src.frames <- f
	for deadline := time.Now().Add(5 * time.Second); l.mark() == before && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
}

// stopCapture makes the next read of src fail, and waits until l has
// stopped.
func stopCapture(t *testing.T, l *learner, src *fakeSource) {
	t.Helper()
	src.readErr <- errors.New("device gone")
	require.Eventually(
		t,
		func() bool { return l.err() != nil },
		5*time.Second,
		5*time.Millisecond,
	)
}

// learnedCase is a learned hop count measurement.
type learnedCase struct {
	name string
	// ttlLeft are the TTLs of the baseline reply, then of a later one.
	ttlLeft []uint8
	// delay delays the baseline reply after the attempt returns.
	delay bool
	// stopped stops the capture before the measurement.
	stopped bool
	want    LearnedResult
}

var learnedCases = []learnedCase{
	{
		name:    "learned",
		ttlLeft: []uint8{56},
		want:    LearnedResult{Status: Learned, Hops: 8, TTLLeft: 56, Seen: []uint8{8}},
	},
	{
		name:    "reply after the attempt returns",
		ttlLeft: []uint8{56},
		delay:   true,
		want:    LearnedResult{Status: Learned, Hops: 8, TTLLeft: 56, Seen: []uint8{8}},
	},
	{
		name:    "replies vary",
		ttlLeft: []uint8{56, 55},
		want: LearnedResult{
			Status:  Learned,
			Hops:    8,
			TTLLeft: 56,
			Seen:    []uint8{8, 9},
		},
	},
	{
		name: "not captured",
		want: LearnedResult{Status: LearnedNotCaptured},
	},
	{
		name:    "capture stopped",
		stopped: true,
		want: LearnedResult{
			Status: LearnedNotCaptured,
			Reason: "capture stopped: device gone",
		},
	},
}

// reply sends the reply of tc for an attempt with the given TTL, from
// server to localPort, to src.
func (tc learnedCase) reply(
	l *learner,
	src *fakeSource,
	ttl int,
	baseline bool,
	frame func(ttlLeft uint8) []byte,
) {
	switch {
	case baseline && len(tc.ttlLeft) > 0 && tc.delay:
		// Within the learn wait, but after the attempt returns.
		time.AfterFunc(50*time.Millisecond, func() { src.frames <- frame(tc.ttlLeft[0]) })
	case baseline && len(tc.ttlLeft) > 0:
		feed(l, src, frame(tc.ttlLeft[0]))
	case !baseline && ttl == 9 && len(tc.ttlLeft) > 1:
		feed(l, src, frame(tc.ttlLeft[1]))
	}
}

func TestMeasureTCP_Learned(t *testing.T) {
	for _, tc := range learnedCases {
		t.Run(tc.name, func(t *testing.T) {
			src := newFakeSource(t)
			p := testProber(nil, nil)
			p.tcpLearner = synAckLearner(src, testServer.Addr())
			defer p.tcpLearner.Close()
			if tc.stopped {
				stopCapture(t, p.tcpLearner, src)
			}

			var baselines atomic.Int32
			dial := fakeTCP(9, nil)
			p.dialTCP = func(ctx context.Context, ttl int, addr netip.AddrPort) (net.Conn, error) {
				conn, err := dial(ctx, ttl, addr)
				if err != nil {
					return conn, err
				}
				port := uint16(conn.LocalAddr().(*net.TCPAddr).Port)
				baseline := ttl == 0 && baselines.Add(1) == 1
				tc.reply(p.tcpLearner, src, ttl, baseline, func(ttlLeft uint8) []byte {
					return synAck(t, addr, port, ttlLeft)
				})
				return conn, nil
			}

			gotTCP, got := p.measureTCP(context.Background(), testServer)
			assert.Equal(t, TCPResult{Status: TCPMeasured, Hops: 8}, gotTCP)
			assert.Equal(t, tc.want, got)
		})
	}
}
