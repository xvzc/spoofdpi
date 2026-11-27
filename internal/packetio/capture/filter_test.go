package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// filterFrame is one crafted packet, as the IP packet plus the EtherType
// it travels under on an Ethernet link.
type filterFrame struct {
	name      string
	etherType layers.EthernetType
	// payload is the IP packet, or the ARP message for ARP.
	payload []byte
}

var (
	filterSrc4 = net.ParseIP("203.0.113.7").To4()
	filterDst4 = net.ParseIP("192.168.0.2").To4()
	filterSrc6 = net.ParseIP("2001:db8::7")
	filterDst6 = net.ParseIP("2001:db8::2")
)

func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, ls...))
	return buf.Bytes()
}

func tcpLayer(syn, ack bool) *layers.TCP {
	return &layers.TCP{
		SrcPort: 443,
		DstPort: 50000,
		Seq:     1000,
		Ack:     2000,
		SYN:     syn,
		ACK:     ack,
		Window:  65535,
	}
}

func ipv4TCP(t *testing.T, syn, ack bool) []byte {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      50,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    filterSrc4,
		DstIP:    filterDst4,
	}
	tcp := tcpLayer(syn, ack)
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	return serialize(t, ip, tcp)
}

func ipv4UDP(t *testing.T) []byte {
	t.Helper()

	ip := &layers.IPv4{
		Version:  4,
		TTL:      50,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    filterSrc4,
		DstIP:    filterDst4,
	}
	udp := &layers.UDP{SrcPort: 443, DstPort: 50000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	return serialize(t, ip, udp, gopacket.Payload("x"))
}

// ipv4Fragment builds a non-first fragment of protocol proto whose payload
// looks like a TCP SYN/ACK header, so only the fragment check can reject
// it.
func ipv4Fragment(t *testing.T, proto layers.IPProtocol) []byte {
	t.Helper()

	ip := &layers.IPv4{
		Version:    4,
		TTL:        50,
		Protocol:   proto,
		FragOffset: 185,
		SrcIP:      filterSrc4,
		DstIP:      filterDst4,
	}
	tcp := gopacket.NewSerializeBuffer()
	require.NoError(t, tcpLayer(true, true).SerializeTo(tcp, gopacket.SerializeOptions{}))
	return serialize(t, ip, gopacket.Payload(tcp.Bytes()))
}

// checksummedLayer is a transport layer whose checksum covers the IP
// pseudo-header.
type checksummedLayer interface {
	gopacket.SerializableLayer
	SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
}

// ipv6Packet builds an IPv6 packet whose next header is nextHeader: the
// extension header ext, if any, followed by l4.
func ipv6Packet(
	t *testing.T,
	nextHeader layers.IPProtocol,
	ext []byte,
	l4 checksummedLayer,
) []byte {
	t.Helper()

	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   50,
		NextHeader: nextHeader,
		SrcIP:      filterSrc6,
		DstIP:      filterDst6,
	}
	require.NoError(t, l4.SetNetworkLayerForChecksum(ip))
	upper := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, l4.SerializeTo(upper, opts))
	return serialize(t, ip, gopacket.Payload(append(ext, upper.Bytes()...)))
}

func ipv6TCP(t *testing.T, syn, ack bool) []byte {
	t.Helper()

	return ipv6Packet(t, layers.IPProtocolTCP, nil, tcpLayer(syn, ack))
}

// ipv6UDP builds an IPv6 UDP packet whose byte at the offset of the TCP
// flags has SYN and ACK set, so only the next header check can reject it
// from a SYN/ACK filter.
func ipv6UDP(t *testing.T) []byte {
	t.Helper()

	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   50,
		NextHeader: layers.IPProtocolUDP,
		SrcIP:      filterSrc6,
		DstIP:      filterDst6,
	}
	udp := &layers.UDP{SrcPort: 443, DstPort: 50000}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	// The TCP flags are at offset 13 of the transport header, 5 into the
	// payload of a UDP one.
	payload := []byte{0, 0, 0, 0, 0, 0x12, 0, 0}
	return serialize(t, ip, udp, gopacket.Payload(payload))
}

// optionsHeader is an IPv6 hop-by-hop or destination options header
// followed by nextHeader, padded to its 8 bytes with a PadN option.
func optionsHeader(nextHeader layers.IPProtocol) []byte {
	return []byte{byte(nextHeader), 0, 1, 4, 0, 0, 0, 0}
}

// routingHeader is an 8-byte IPv6 routing header with no segments left,
// followed by nextHeader.
func routingHeader(nextHeader layers.IPProtocol) []byte {
	return []byte{byte(nextHeader), 0, 0, 0, 0, 0, 0, 0}
}

// authHeader is a 12-byte IPsec authentication header without an ICV,
// followed by nextHeader.
func authHeader(nextHeader layers.IPProtocol) []byte {
	return []byte{byte(nextHeader), 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1}
}

// fragmentHeader is an IPv6 fragment header of the fragment at offset
// (in 8-byte units) of a packet of protocol nextHeader, with more
// fragments to follow when offset is 0.
func fragmentHeader(nextHeader layers.IPProtocol, offset uint16) []byte {
	offsetAndFlags := offset << 3
	if offset == 0 {
		offsetAndFlags |= 1
	}
	return append(
		[]byte{byte(nextHeader), 0},
		byte(offsetAndFlags>>8), byte(offsetAndFlags), 0, 0, 0, 7,
	)
}

func arpRequest(t *testing.T) []byte {
	t.Helper()

	return serialize(t, &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte{0, 1, 2, 3, 4, 5},
		SourceProtAddress: filterDst4,
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    filterSrc4,
	})
}

// ppp wraps the IP packet of f in a PPP frame, with the HDLC address and
// control bytes if hdlc is set. ok is false when f has no PPP protocol
// number.
func ppp(f filterFrame, hdlc bool) (frame []byte, ok bool) {
	var proto uint16
	switch f.etherType {
	case layers.EthernetTypeIPv4:
		proto = 0x0021
	case layers.EthernetTypeIPv6:
		proto = 0x0057
	default:
		return nil, false
	}
	if hdlc {
		frame = []byte{0xff, 0x03}
	}
	frame = binary.BigEndian.AppendUint16(frame, proto)
	return append(frame, f.payload...), true
}

// onLink wraps f in the link-layer header of lt; hdlc selects the PPP
// framing. ok is false when f cannot travel on lt (ARP has no
// Null/Loop/Raw/PPP encoding).
func onLink(lt layers.LinkType, hdlc bool, f filterFrame) (frame []byte, ok bool) {
	switch lt {
	case layers.LinkTypeEthernet:
		hdr := make([]byte, 14)
		copy(hdr[0:6], []byte{6, 7, 8, 9, 10, 11})
		copy(hdr[6:12], []byte{0, 1, 2, 3, 4, 5})
		binary.BigEndian.PutUint16(hdr[12:14], uint16(f.etherType))
		return append(hdr, f.payload...), true
	case layers.LinkTypePPP:
		return ppp(f, hdlc)
	}

	var family uint32
	switch f.etherType {
	case layers.EthernetTypeIPv4:
		family = uint32(layers.ProtocolFamilyIPv4)
	case layers.EthernetTypeIPv6:
		family = uint32(layers.ProtocolFamilyIPv6BSD)
	default:
		return nil, false
	}

	switch lt {
	case layers.LinkTypeNull:
		// DLT_NULL carries the family in host byte order; every
		// supported host is little-endian.
		hdr := binary.LittleEndian.AppendUint32(nil, family)
		return append(hdr, f.payload...), true
	case layers.LinkTypeLoop:
		hdr := binary.BigEndian.AppendUint32(nil, family)
		return append(hdr, f.payload...), true
	default: // layers.LinkTypeRaw
		return f.payload, true
	}
}

// filterLink is a link type, and for PPP one of its two framings.
type filterLink struct {
	name string
	lt   layers.LinkType
	hdlc bool
}

var filterLinks = []filterLink{
	{"Ethernet", layers.LinkTypeEthernet, false},
	{"Null", layers.LinkTypeNull, false},
	{"Loop", layers.LinkTypeLoop, false},
	{"Raw", layers.LinkTypeRaw, false},
	{"PPP with HDLC framing", layers.LinkTypePPP, true},
	{"PPP without HDLC framing", layers.LinkTypePPP, false},
}

var (
	ipv4Only     = netutil.NewFamilySet(netutil.FamilyV4)
	ipv6Only     = netutil.NewFamilySet(netutil.FamilyV6)
	bothFamilies = netutil.NewFamilySet(netutil.FamilyV4, netutil.FamilyV6)
)

// familyFilter is SynAckFilter or UDPFilter.
type familyFilter func(layers.LinkType, netutil.FamilySet) ([]BPFInstruction, error)

// testFilter checks that the program built by filter for fams accepts
// exactly the frames whose name is in accept, on every supported link
// type.
func testFilter(
	t *testing.T,
	filter familyFilter,
	fams netutil.FamilySet,
	frames []filterFrame,
	accept map[string]bool,
) {
	t.Helper()

	for _, link := range filterLinks {
		prog, err := filter(link.lt, fams)
		require.NoError(t, err)
		for _, f := range frames {
			frame, ok := onLink(link.lt, link.hdlc, f)
			if !ok {
				continue
			}
			t.Run(link.name+"/"+f.name, func(t *testing.T) {
				require.Equal(t, accept[f.name], runFilter(t, prog, frame))
			})
		}
	}
}

// testFamilies runs testFilter for IPv4, IPv6, and both, where the program
// for both accepts what either of the others does.
func testFamilies(t *testing.T, filter familyFilter, accept4, accept6 []string) {
	t.Helper()

	frames := filterFrames(t)
	both := append(slices.Clone(accept4), accept6...)
	tcs := []struct {
		name   string
		fams   netutil.FamilySet
		accept []string
	}{
		{"ipv4", ipv4Only, accept4},
		{"ipv6", ipv6Only, accept6},
		{"both", bothFamilies, both},
	}
	for _, tc := range tcs {
		accept := make(map[string]bool)
		for _, name := range tc.accept {
			accept[name] = true
		}
		t.Run(tc.name, func(t *testing.T) {
			testFilter(t, filter, tc.fams, frames, accept)
		})
	}
}

func filterFrames(t *testing.T) []filterFrame {
	t.Helper()

	udp := func() *layers.UDP { return &layers.UDP{SrcPort: 443, DstPort: 50000} }
	return []filterFrame{
		{"ipv4 tcp syn/ack", layers.EthernetTypeIPv4, ipv4TCP(t, true, true)},
		{"ipv4 tcp ack", layers.EthernetTypeIPv4, ipv4TCP(t, false, true)},
		{"ipv4 tcp syn", layers.EthernetTypeIPv4, ipv4TCP(t, true, false)},
		{"ipv4 udp", layers.EthernetTypeIPv4, ipv4UDP(t)},
		{
			"ipv4 tcp fragment",
			layers.EthernetTypeIPv4,
			ipv4Fragment(t, layers.IPProtocolTCP),
		},
		{
			"ipv4 udp fragment",
			layers.EthernetTypeIPv4,
			ipv4Fragment(t, layers.IPProtocolUDP),
		},
		{"ipv6 tcp syn/ack", layers.EthernetTypeIPv6, ipv6TCP(t, true, true)},
		{"ipv6 tcp ack", layers.EthernetTypeIPv6, ipv6TCP(t, false, true)},
		{"ipv6 tcp syn", layers.EthernetTypeIPv6, ipv6TCP(t, true, false)},
		{"ipv6 udp", layers.EthernetTypeIPv6, ipv6UDP(t)},
		{
			"ipv6 hop-by-hop tcp syn/ack",
			layers.EthernetTypeIPv6,
			ipv6Packet(t, layers.IPProtocolIPv6HopByHop,
				optionsHeader(layers.IPProtocolTCP), tcpLayer(true, true)),
		},
		{
			"ipv6 hop-by-hop udp",
			layers.EthernetTypeIPv6,
			ipv6Packet(t, layers.IPProtocolIPv6HopByHop,
				optionsHeader(layers.IPProtocolUDP), udp()),
		},
		{
			"ipv6 routing tcp syn/ack",
			layers.EthernetTypeIPv6,
			ipv6Packet(t, layers.IPProtocolIPv6Routing,
				routingHeader(layers.IPProtocolTCP), tcpLayer(true, true)),
		},
		{
			"ipv6 routing udp",
			layers.EthernetTypeIPv6,
			ipv6Packet(t, layers.IPProtocolIPv6Routing,
				routingHeader(layers.IPProtocolUDP), udp()),
		},
		{
			"ipv6 destination options tcp syn/ack",
			layers.EthernetTypeIPv6,
			ipv6Packet(t, layers.IPProtocolIPv6Destination,
				optionsHeader(layers.IPProtocolTCP), tcpLayer(true, true)),
		},
		{
			"ipv6 destination options udp",
			layers.EthernetTypeIPv6,
			ipv6Packet(t, layers.IPProtocolIPv6Destination,
				optionsHeader(layers.IPProtocolUDP), udp()),
		},
		{
			"ipv6 ah tcp syn/ack",
			layers.EthernetTypeIPv6,
			ipv6Packet(t, layers.IPProtocolAH,
				authHeader(layers.IPProtocolTCP), tcpLayer(true, true)),
		},
		{
			"ipv6 ah udp",
			layers.EthernetTypeIPv6,
			ipv6Packet(t, layers.IPProtocolAH, authHeader(layers.IPProtocolUDP), udp()),
		},
		{
			"ipv6 tcp fragment",
			layers.EthernetTypeIPv6,
			ipv6Packet(t, layers.IPProtocolIPv6Fragment,
				fragmentHeader(layers.IPProtocolTCP, 0), tcpLayer(true, true)),
		},
		{
			"ipv6 udp fragment",
			layers.EthernetTypeIPv6,
			ipv6Packet(t, layers.IPProtocolIPv6Fragment,
				fragmentHeader(layers.IPProtocolUDP, 0), udp()),
		},
		{
			// A non-first fragment, whose payload is not a UDP header.
			"ipv6 udp non-first fragment",
			layers.EthernetTypeIPv6,
			serialize(t, &layers.IPv6{
				Version:    6,
				HopLimit:   50,
				NextHeader: layers.IPProtocolIPv6Fragment,
				SrcIP:      filterSrc6,
				DstIP:      filterDst6,
			}, gopacket.Payload(append(
				fragmentHeader(layers.IPProtocolUDP, 185),
				make([]byte, 16)...,
			))),
		},
		{
			"ipv6 icmp",
			layers.EthernetTypeIPv6,
			ipv6Packet(t, layers.IPProtocolICMPv6, nil, &layers.ICMPv6{
				TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0),
			}),
		},
		{"arp", layers.EthernetTypeARP, arpRequest(t)},
	}
}

func TestSynAckFilter(t *testing.T) {
	// Over IPv6, a packet whose first next header is a hop-by-hop,
	// routing, or destination options header passes without a look at
	// what follows it, and ParseSynAck drops it unless it is a SYN/ACK.
	// Fragments and other next headers, such as AH, are rejected.
	testFamilies(t, SynAckFilter,
		[]string{"ipv4 tcp syn/ack"},
		[]string{
			"ipv6 tcp syn/ack",
			"ipv6 hop-by-hop tcp syn/ack",
			"ipv6 hop-by-hop udp",
			"ipv6 routing tcp syn/ack",
			"ipv6 routing udp",
			"ipv6 destination options tcp syn/ack",
			"ipv6 destination options udp",
		},
	)
}

func TestUDPFilter(t *testing.T) {
	// UDPFilter is "ip and udp": like tcpdump's, it does not look at the
	// fragment offset, so a non-first UDP fragment passes and is dropped
	// by ParseUDP instead. Over IPv6, it likewise accepts any fragment
	// whose fragment header carries UDP, first or not, and a packet whose
	// first next header is a hop-by-hop, routing, or destination options
	// header without a look at what follows it. Other next headers, such
	// as AH, are rejected.
	testFamilies(t, UDPFilter,
		[]string{"ipv4 udp", "ipv4 udp fragment"},
		[]string{
			"ipv6 udp",
			"ipv6 hop-by-hop udp",
			"ipv6 hop-by-hop tcp syn/ack",
			"ipv6 routing udp",
			"ipv6 routing tcp syn/ack",
			"ipv6 destination options udp",
			"ipv6 destination options tcp syn/ack",
			"ipv6 udp fragment",
			"ipv6 udp non-first fragment",
		},
	)
}

// The parsers decode what follows an IPv6 extension header the filters
// pass unchecked, and drop a fragment, first or not.
func TestFilters_IPv6ExtensionHeadersParse(t *testing.T) {
	frames := make(map[string][]byte)
	for _, f := range filterFrames(t) {
		frames[f.name] = f.payload
	}
	packet := func(name string) gopacket.Packet {
		return gopacket.NewPacket(frames[name], layers.LayerTypeIPv6, gopacket.Default)
	}

	sa, ok := ParseSynAck(packet("ipv6 hop-by-hop tcp syn/ack"))
	require.True(t, ok)
	assert.True(t, filterSrc6.Equal(sa.Src))
	assert.Equal(t, uint8(50), sa.TTLLeft)
	_, ok = ParseSynAck(packet("ipv6 hop-by-hop udp"))
	assert.False(t, ok)

	u, ok := ParseUDP(packet("ipv6 hop-by-hop udp"))
	require.True(t, ok)
	assert.True(t, filterSrc6.Equal(u.Src))
	assert.Equal(t, uint16(443), u.SrcPort)
	_, ok = ParseUDP(packet("ipv6 hop-by-hop tcp syn/ack"))
	assert.False(t, ok)
	_, ok = ParseUDP(packet("ipv6 udp fragment"))
	assert.False(t, ok)
	_, ok = ParseUDP(packet("ipv6 udp non-first fragment"))
	assert.False(t, ok)
}

// The IPv4 programs are the ones the filters built before they had an
// IPv6 branch.
func TestFilters_IPv4Golden(t *testing.T) {
	synAckEthernet := []BPFInstruction{
		{0x28, 0, 0, 0xc},
		{0x15, 0, 9, 0x800},
		{0x30, 0, 0, 0x17},
		{0x15, 0, 7, 0x6},
		{0x28, 0, 0, 0x14},
		{0x45, 5, 0, 0x1fff},
		{0xb1, 0, 0, 0xe},
		{0x50, 0, 0, 0x1b},
		{0x54, 0, 0, 0x12},
		{0x15, 0, 1, 0x12},
		{0x06, 0, 0, 0x40000},
		{0x06, 0, 0, 0x0},
	}
	synAckNull := []BPFInstruction{
		{0x30, 0, 0, 0x4},
		{0x54, 0, 0, 0xf0},
		{0x15, 0, 9, 0x40},
		{0x30, 0, 0, 0xd},
		{0x15, 0, 7, 0x6},
		{0x28, 0, 0, 0xa},
		{0x45, 5, 0, 0x1fff},
		{0xb1, 0, 0, 0x4},
		{0x50, 0, 0, 0x11},
		{0x54, 0, 0, 0x12},
		{0x15, 0, 1, 0x12},
		{0x06, 0, 0, 0x40000},
		{0x06, 0, 0, 0x0},
	}
	synAckRaw := []BPFInstruction{
		{0x30, 0, 0, 0x0},
		{0x54, 0, 0, 0xf0},
		{0x15, 0, 9, 0x40},
		{0x30, 0, 0, 0x9},
		{0x15, 0, 7, 0x6},
		{0x28, 0, 0, 0x6},
		{0x45, 5, 0, 0x1fff},
		{0xb1, 0, 0, 0x0},
		{0x50, 0, 0, 0xd},
		{0x54, 0, 0, 0x12},
		{0x15, 0, 1, 0x12},
		{0x06, 0, 0, 0x40000},
		{0x06, 0, 0, 0x0},
	}
	synAckPPP := []BPFInstruction{
		{0x28, 0, 0, 0x0},
		{0x15, 0, 12, 0xff03},
		{0x28, 0, 0, 0x2},
		{0x15, 0, 9, 0x21},
		{0x30, 0, 0, 0xd},
		{0x15, 0, 7, 0x6},
		{0x28, 0, 0, 0xa},
		{0x45, 5, 0, 0x1fff},
		{0xb1, 0, 0, 0x4},
		{0x50, 0, 0, 0x11},
		{0x54, 0, 0, 0x12},
		{0x15, 0, 1, 0x12},
		{0x06, 0, 0, 0x40000},
		{0x06, 0, 0, 0x0},
		{0x28, 0, 0, 0x0},
		{0x15, 0, 9, 0x21},
		{0x30, 0, 0, 0xb},
		{0x15, 0, 7, 0x6},
		{0x28, 0, 0, 0x8},
		{0x45, 5, 0, 0x1fff},
		{0xb1, 0, 0, 0x2},
		{0x50, 0, 0, 0xf},
		{0x54, 0, 0, 0x12},
		{0x15, 0, 1, 0x12},
		{0x06, 0, 0, 0x40000},
		{0x06, 0, 0, 0x0},
	}
	udpEthernet := []BPFInstruction{
		{0x28, 0, 0, 0xc},
		{0x15, 0, 3, 0x800},
		{0x30, 0, 0, 0x17},
		{0x15, 0, 1, 0x11},
		{0x06, 0, 0, 0x40000},
		{0x06, 0, 0, 0x0},
	}
	udpNull := []BPFInstruction{
		{0x30, 0, 0, 0x4},
		{0x54, 0, 0, 0xf0},
		{0x15, 0, 3, 0x40},
		{0x30, 0, 0, 0xd},
		{0x15, 0, 1, 0x11},
		{0x06, 0, 0, 0x40000},
		{0x06, 0, 0, 0x0},
	}
	udpRaw := []BPFInstruction{
		{0x30, 0, 0, 0x0},
		{0x54, 0, 0, 0xf0},
		{0x15, 0, 3, 0x40},
		{0x30, 0, 0, 0x9},
		{0x15, 0, 1, 0x11},
		{0x06, 0, 0, 0x40000},
		{0x06, 0, 0, 0x0},
	}
	udpPPP := []BPFInstruction{
		{0x28, 0, 0, 0x0},
		{0x15, 0, 6, 0xff03},
		{0x28, 0, 0, 0x2},
		{0x15, 0, 3, 0x21},
		{0x30, 0, 0, 0xd},
		{0x15, 0, 1, 0x11},
		{0x06, 0, 0, 0x40000},
		{0x06, 0, 0, 0x0},
		{0x28, 0, 0, 0x0},
		{0x15, 0, 3, 0x21},
		{0x30, 0, 0, 0xb},
		{0x15, 0, 1, 0x11},
		{0x06, 0, 0, 0x40000},
		{0x06, 0, 0, 0x0},
	}

	tcs := []struct {
		name   string
		filter familyFilter
		lt     layers.LinkType
		want   []BPFInstruction
	}{
		{"SynAckFilter/Ethernet", SynAckFilter, layers.LinkTypeEthernet, synAckEthernet},
		{"SynAckFilter/Null", SynAckFilter, layers.LinkTypeNull, synAckNull},
		{"SynAckFilter/Loop", SynAckFilter, layers.LinkTypeLoop, synAckNull},
		{"SynAckFilter/Raw", SynAckFilter, layers.LinkTypeRaw, synAckRaw},
		{"SynAckFilter/PPP", SynAckFilter, layers.LinkTypePPP, synAckPPP},
		{"UDPFilter/Ethernet", UDPFilter, layers.LinkTypeEthernet, udpEthernet},
		{"UDPFilter/Null", UDPFilter, layers.LinkTypeNull, udpNull},
		{"UDPFilter/Loop", UDPFilter, layers.LinkTypeLoop, udpNull},
		{"UDPFilter/Raw", UDPFilter, layers.LinkTypeRaw, udpRaw},
		{"UDPFilter/PPP", UDPFilter, layers.LinkTypePPP, udpPPP},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			prog, err := tc.filter(tc.lt, ipv4Only)
			require.NoError(t, err)
			assert.Equal(t, tc.want, prog)
		})
	}
}

func TestFilters_NoFamily(t *testing.T) {
	for name, filter := range map[string]familyFilter{
		"SynAckFilter": SynAckFilter,
		"UDPFilter":    UDPFilter,
	} {
		t.Run(name, func(t *testing.T) {
			prog, err := filter(layers.LinkTypeEthernet, netutil.FamilySet(0))
			require.ErrorIs(t, err, ErrNoFamily)
			assert.Nil(t, prog)
		})
	}
}

func TestFilters_UnsupportedLinkType(t *testing.T) {
	filters := map[string]func(layers.LinkType) ([]BPFInstruction, error){
		"SynAckFilter": func(lt layers.LinkType) ([]BPFInstruction, error) {
			return SynAckFilter(lt, bothFamilies)
		},
		"UDPFilter": func(lt layers.LinkType) ([]BPFInstruction, error) {
			return UDPFilter(lt, bothFamilies)
		},
		"TCPHostFilter": func(lt layers.LinkType) ([]BPFInstruction, error) {
			return TCPHostFilter(lt, []net.IP{filterSrc4})
		},
	}
	// The link types a handle reports under another number are normalized
	// before they reach a filter, which does not know them.
	linkTypes := []layers.LinkType{
		layers.LinkTypeLinuxSLL, layers.LinkTypeIEEE802_11, 12, 50, 200,
	}
	for name, filter := range filters {
		for _, lt := range linkTypes {
			t.Run(fmt.Sprintf("%s/%d", name, lt), func(t *testing.T) {
				prog, err := filter(lt)
				require.ErrorIs(t, err, ErrUnsupportedLinkType)
				assert.Contains(t, err.Error(), fmt.Sprintf(": %d", lt))
				assert.Nil(t, prog)
			})
		}
	}
}

// A PPP frame whose protocol is not that of a family the filter captures
// is rejected whatever follows it.
func TestFilters_PPPProtocol(t *testing.T) {
	tcs := []struct {
		name     string
		fams     netutil.FamilySet
		tcp, udp []byte
		protos   []uint16
	}{
		{
			"ipv4",
			ipv4Only,
			ipv4TCP(t, true, true),
			ipv4UDP(t),
			[]uint16{0xc021, 0x0057, 0x8021},
		},
		{
			"ipv6",
			ipv6Only,
			ipv6TCP(t, true, true),
			ipv6UDP(t),
			[]uint16{0xc021, 0x0021, 0x8057},
		},
	}
	for _, tc := range tcs {
		synAck, err := SynAckFilter(layers.LinkTypePPP, tc.fams)
		require.NoError(t, err)
		udp, err := UDPFilter(layers.LinkTypePPP, tc.fams)
		require.NoError(t, err)

		for _, hdlc := range []bool{true, false} {
			for _, proto := range tc.protos {
				var frame []byte
				if hdlc {
					frame = []byte{0xff, 0x03}
				}
				frame = binary.BigEndian.AppendUint16(frame, proto)
				tcpFrame := append(frame[:len(frame):len(frame)], tc.tcp...)
				udpFrame := append(frame[:len(frame):len(frame)], tc.udp...)

				name := fmt.Sprintf("%s hdlc=%v proto=%#04x", tc.name, hdlc, proto)
				assert.False(t, runFilter(t, synAck, tcpFrame), name)
				assert.False(t, runFilter(t, udp, udpFrame), name)
			}
		}
	}

	tcp, err := TCPHostFilter(layers.LinkTypePPP, []net.IP{filterSrc4})
	require.NoError(t, err)
	for _, hdlc := range []bool{true, false} {
		for _, proto := range []uint16{0xc021, 0x0057, 0x8021} {
			var frame []byte
			if hdlc {
				frame = []byte{0xff, 0x03}
			}
			frame = binary.BigEndian.AppendUint16(frame, proto)
			frame = append(frame, ipv4TCP(t, true, true)...)
			assert.False(t, runFilter(t, tcp, frame),
				"hdlc=%v proto=%#04x", hdlc, proto)
		}
	}
}
