package tun

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/rule"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
)

func TestGatewayIP(t *testing.T) {
	assert.Equal(t, "192.168.1.1", gatewayIP(&route.Route{
		Gateway: net.ParseIP("192.168.1.1"),
	}))
	assert.Equal(t, "", gatewayIP(&route.Route{}))
}

// blockingDevice is a tun.Device whose Read blocks until Close.
type blockingDevice struct {
	closeOnce sync.Once
	closed    chan struct{}
}

func newBlockingDevice() *blockingDevice {
	return &blockingDevice{closed: make(chan struct{})}
}

func (d *blockingDevice) File() *os.File { return nil }

func (d *blockingDevice) Read([][]byte, []int, int) (int, error) {
	<-d.closed
	return 0, os.ErrClosed
}

func (d *blockingDevice) Write(
	bufs [][]byte,
	_ int,
) (int, error) {
	return len(bufs), nil
}
func (d *blockingDevice) MTU() (int, error) { return 1500, nil }

func (d *blockingDevice) Name() (string, error)    { return "test0", nil }
func (d *blockingDevice) Events() <-chan tun.Event { return nil }
func (d *blockingDevice) BatchSize() int           { return 1 }

func (d *blockingDevice) Close() error {
	d.closeOnce.Do(func() { close(d.closed) })
	return nil
}

type deviceSysNet struct {
	TUNSystemNetwork
	device tun.Device
}

func (s *deviceSysNet) TunDevice() tun.Device { return s.device }

func TestTunServer_ServeStopsAndReleasesStack(t *testing.T) {
	device := newBlockingDevice()
	s := NewTUNServer(
		zerolog.Nop(),
		nil,
		nil,
		&deviceSysNet{device: device},
	).(*TunServer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, s.Listen(ctx))
	require.Len(t, s.netStack.NICInfo(), 1)

	served := make(chan error, 1)
	go func() { served <- s.Serve(ctx) }()

	start := time.Now()
	cancel()

	select {
	case err := <-served:
		assert.NoError(t, err)
		assert.Less(t, time.Since(start), 2*time.Second)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after ctx was cancelled")
	}

	select {
	case <-device.closed:
	default:
		t.Fatal("Serve did not close the tun device")
	}
	assert.Empty(t, s.netStack.NICInfo(), "Serve must destroy the network stack")
}

func TestTunServer_ListenWithoutDevice(t *testing.T) {
	s := NewTUNServer(zerolog.Nop(), nil, nil, &deviceSysNet{})

	assert.Error(t, s.Listen(context.Background()))
}

// packetDevice is a tun.Device whose Read returns one queued packet per
// call and reports the device as closed once the queue is empty.
type packetDevice struct {
	*blockingDevice
	packets [][]byte
}

func (d *packetDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(d.packets) == 0 {
		return 0, os.ErrClosed
	}
	sizes[0] = copy(bufs[0][offset:], d.packets[0])
	d.packets = d.packets[1:]
	return 1, nil
}

// listenTunServer starts a TunServer's network stack, with its connection
// context set as Serve would set it, and stops it when the test ends.
func listenTunServer(
	t *testing.T,
	tcpHandler *TCPHandler,
	udpHandler *UDPHandler,
	sysNet TUNSystemNetwork,
) *TunServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := NewTUNServer(zerolog.Nop(), tcpHandler, udpHandler, &deviceSysNet{
		TUNSystemNetwork: sysNet,
		device:           newBlockingDevice(),
	}).(*TunServer)
	require.NoError(t, s.Listen(ctx))
	s.serveCtx = ctx
	t.Cleanup(func() {
		cancel()
		s.conns.Wait(2 * time.Second)
		s.netStack.Destroy()
	})
	return s
}

// injectPackets feeds packets to the server's stack through the TUN read
// path.
func injectPackets(t *testing.T, s *TunServer, packets ...[]byte) {
	t.Helper()
	dev := &packetDevice{blockingDevice: newBlockingDevice(), packets: packets}
	s.tunToStack(context.Background(), zerolog.Nop(), s.ep, dev)
}

// readPacket returns the next packet the stack writes towards the TUN, or
// nil if none arrives within timeout.
func readPacket(t *testing.T, s *TunServer, timeout time.Duration) gopacket.Packet {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	pkt := s.ep.ReadContext(ctx)
	if pkt == nil {
		return nil
	}
	defer pkt.DecRef()
	raw := pkt.ToView().AsSlice()
	first := layers.LayerTypeIPv4
	if raw[0]>>4 == 6 {
		first = layers.LayerTypeIPv6
	}
	return gopacket.NewPacket(raw, first, gopacket.Default)
}

// serializeIP builds an IP packet from an IPv4 or IPv6 header, a TCP or
// UDP header, and a payload, with valid lengths and checksums.
func serializeIP(
	t *testing.T,
	ip gopacket.NetworkLayer,
	transport gopacket.SerializableLayer,
	payload []byte,
) []byte {
	t.Helper()
	switch l := transport.(type) {
	case *layers.TCP:
		require.NoError(t, l.SetNetworkLayerForChecksum(ip))
	case *layers.UDP:
		require.NoError(t, l.SetNetworkLayerForChecksum(ip))
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	require.NoError(t, gopacket.SerializeLayers(
		buf,
		opts,
		ip.(gopacket.SerializableLayer),
		transport,
		gopacket.Payload(payload),
	))
	return buf.Bytes()
}

var (
	testClient6 = net.ParseIP("2001:db8::1")
	testServer6 = net.ParseIP("2001:db8::2")
	testClient4 = net.ParseIP("10.0.0.1").To4()
	testServer4 = net.ParseIP("203.0.113.1").To4()
)

func ipv6Header(next layers.IPProtocol) *layers.IPv6 {
	return &layers.IPv6{
		Version:    6,
		NextHeader: next,
		HopLimit:   64,
		SrcIP:      testClient6,
		DstIP:      testServer6,
	}
}

func ipv4Header(proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: proto,
		SrcIP:    testClient4,
		DstIP:    testServer4,
	}
}

func TestTunServer_IPv6TCPGetsReset(t *testing.T) {
	s := listenTunServer(t, nil, nil, nil)

	syn := &layers.TCP{SrcPort: 40000, DstPort: 443, Seq: 1000, SYN: true, Window: 65535}
	injectPackets(t, s, serializeIP(t, ipv6Header(layers.IPProtocolTCP), syn, nil))

	pkt := readPacket(t, s, 2*time.Second)
	require.NotNil(t, pkt, "the stack must answer the SYN")

	ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	require.True(t, ok, "the answer must be IPv6: %v", pkt)
	assert.True(t, ip6.SrcIP.Equal(testServer6), "RST must come from the destination")
	assert.True(t, ip6.DstIP.Equal(testClient6))

	tcpLayer, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	require.True(t, ok, "the answer must be TCP: %v", pkt)
	assert.True(t, tcpLayer.RST, "the answer must be a RST")
	assert.False(t, tcpLayer.SYN, "the connection must not be accepted")
	assert.Equal(t, layers.TCPPort(443), tcpLayer.SrcPort)
	assert.Equal(t, layers.TCPPort(40000), tcpLayer.DstPort)
	assert.Equal(t, uint32(1001), tcpLayer.Ack)
}

func TestTunServer_IPv6UDPGetsPortUnreachable(t *testing.T) {
	s := listenTunServer(t, nil, nil, nil)

	udpLayer := &layers.UDP{SrcPort: 40000, DstPort: 443}
	injectPackets(
		t,
		s,
		serializeIP(t, ipv6Header(layers.IPProtocolUDP), udpLayer, []byte("quic")),
	)

	pkt := readPacket(t, s, 2*time.Second)
	require.NotNil(t, pkt, "the stack must answer the datagram")

	ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	require.True(t, ok, "the answer must be IPv6: %v", pkt)
	assert.True(t, ip6.SrcIP.Equal(testServer6), "ICMPv6 must come from the destination")
	assert.True(t, ip6.DstIP.Equal(testClient6))

	icmp, ok := pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	require.True(t, ok, "the answer must be ICMPv6: %v", pkt)
	assert.Equal(
		t,
		layers.CreateICMPv6TypeCode(
			layers.ICMPv6TypeDestinationUnreachable,
			layers.ICMPv6CodePortUnreachable,
		),
		icmp.TypeCode,
	)
}

// gVisor answers an echo request to any address itself, so a ping to a
// refused IPv6 destination still gets a reply.
func TestTunServer_IPv6EchoIsAnsweredByStack(t *testing.T) {
	s := listenTunServer(t, nil, nil, nil)

	echo := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
	}
	ip := ipv6Header(layers.IPProtocolICMPv6)
	require.NoError(t, echo.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(
		buf,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip,
		echo,
		&layers.ICMPv6Echo{Identifier: 1, SeqNumber: 1},
	))
	injectPackets(t, s, buf.Bytes())

	pkt := readPacket(t, s, 2*time.Second)
	require.NotNil(t, pkt, "the stack must answer the echo request")

	ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	require.True(t, ok, "the answer must be IPv6: %v", pkt)
	assert.True(
		t,
		ip6.SrcIP.Equal(testServer6),
		"the reply must come from the destination",
	)

	icmp, ok := pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	require.True(t, ok, "the answer must be ICMPv6: %v", pkt)
	assert.Equal(t, uint8(layers.ICMPv6TypeEchoReply), icmp.TypeCode.Type())
}

func TestTunServer_IPv4TCPIsAccepted(t *testing.T) {
	tcpHandler := NewTCPHandler(zerolog.Nop(), nil, nil, nil, &config.RuntimeConfig{})
	s := listenTunServer(t, tcpHandler, nil, nil)

	syn := &layers.TCP{SrcPort: 40000, DstPort: 443, Seq: 1000, SYN: true, Window: 65535}
	injectPackets(t, s, serializeIP(t, ipv4Header(layers.IPProtocolTCP), syn, nil))

	pkt := readPacket(t, s, 2*time.Second)
	require.NotNil(t, pkt, "the stack must answer the SYN")

	ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	require.True(t, ok, "the answer must be IPv4: %v", pkt)
	assert.True(t, ip4.SrcIP.Equal(testServer4))
	assert.True(t, ip4.DstIP.Equal(testClient4))

	tcpLayer, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	require.True(t, ok, "the answer must be TCP: %v", pkt)
	assert.True(t, tcpLayer.SYN && tcpLayer.ACK, "the answer must be a SYN-ACK")
	assert.False(t, tcpLayer.RST)
	assert.Equal(t, uint32(1001), tcpLayer.Ack)

	// Completing the handshake lets the forwarder hand the connection to the
	// handler instead of leaving it waiting in the handshake.
	ack := &layers.TCP{
		SrcPort: 40000,
		DstPort: 443,
		Seq:     1001,
		Ack:     tcpLayer.Seq + 1,
		ACK:     true,
		Window:  65535,
	}
	injectPackets(t, s, serializeIP(t, ipv4Header(layers.IPProtocolTCP), ack, nil))
	assert.Eventually(t, func() bool { return s.conns.Active() == 1 },
		2*time.Second, 10*time.Millisecond, "the tcp handler must get the connection")
}

func TestTunServer_IPv4UDPIsHandled(t *testing.T) {
	sysNet := &dialCountingSysNet{}
	udpHandler := NewUDPHandler(
		zerolog.Nop(),
		desync.NewUDPDesyncer(zerolog.Nop(), nil, nil, nil),
		rule.NewRuleSet(),
		&config.RuntimeConfig{},
	)
	s := listenTunServer(t, nil, udpHandler, sysNet)

	udpLayer := &layers.UDP{SrcPort: 40000, DstPort: 443}
	injectPackets(
		t,
		s,
		serializeIP(t, ipv4Header(layers.IPProtocolUDP), udpLayer, []byte("quic")),
	)

	assert.Eventually(t, func() bool { return sysNet.dials.Load() == 1 },
		2*time.Second, 10*time.Millisecond, "the udp handler must dial the destination")
	assert.Nil(
		t,
		readPacket(t, s, 100*time.Millisecond),
		"the datagram must not be refused",
	)
}

func TestNetworkProtocol(t *testing.T) {
	tcs := []struct {
		name   string
		packet []byte
		want   tcpip.NetworkProtocolNumber
		wantOK bool
	}{
		{"ipv4", []byte{0x45}, ipv4.ProtocolNumber, true},
		{"ipv6", []byte{0x60}, ipv6.ProtocolNumber, true},
		{"unknown version", []byte{0x00}, 0, false},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := networkProtocol(tc.packet)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}
