package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func ipv6TCP(t *testing.T) []byte {
	t.Helper()

	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   50,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      filterSrc6,
		DstIP:      filterDst6,
	}
	tcp := tcpLayer(true, true)
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	return serialize(t, ip, tcp)
}

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
	return serialize(t, ip, udp, gopacket.Payload("x"))
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

// testFilter checks that the program built by filter accepts exactly the
// frames whose name is in accept, on every supported link type.
func testFilter(
	t *testing.T,
	filter func(layers.LinkType) ([]BPFInstruction, error),
	frames []filterFrame,
	accept map[string]bool,
) {
	t.Helper()

	for _, link := range filterLinks {
		prog, err := filter(link.lt)
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

func filterFrames(t *testing.T) []filterFrame {
	t.Helper()

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
		{"ipv6 tcp syn/ack", layers.EthernetTypeIPv6, ipv6TCP(t)},
		{"ipv6 udp", layers.EthernetTypeIPv6, ipv6UDP(t)},
		{"arp", layers.EthernetTypeARP, arpRequest(t)},
	}
}

func TestSynAckFilter(t *testing.T) {
	testFilter(t, SynAckFilter, filterFrames(t), map[string]bool{
		"ipv4 tcp syn/ack": true,
	})
}

func TestUDPFilter(t *testing.T) {
	// UDPFilter is "ip and udp": like tcpdump's, it does not look at the
	// fragment offset, so a non-first UDP fragment passes and is dropped
	// by ParseUDP instead.
	testFilter(t, UDPFilter, filterFrames(t), map[string]bool{
		"ipv4 udp":          true,
		"ipv4 udp fragment": true,
	})
}

func TestFilters_UnsupportedLinkType(t *testing.T) {
	filters := map[string]func(layers.LinkType) ([]BPFInstruction, error){
		"SynAckFilter": SynAckFilter,
		"UDPFilter":    UDPFilter,
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

// A PPP frame whose protocol is not IPv4 is rejected whatever follows it.
func TestFilters_PPPProtocol(t *testing.T) {
	synAck, err := SynAckFilter(layers.LinkTypePPP)
	require.NoError(t, err)
	udp, err := UDPFilter(layers.LinkTypePPP)
	require.NoError(t, err)
	tcp, err := TCPHostFilter(layers.LinkTypePPP, []net.IP{filterSrc4})
	require.NoError(t, err)

	for _, hdlc := range []bool{true, false} {
		for _, proto := range []uint16{0xc021, 0x0057, 0x8021} {
			var frame []byte
			if hdlc {
				frame = []byte{0xff, 0x03}
			}
			frame = binary.BigEndian.AppendUint16(frame, proto)
			tcpFrame := append(frame[:len(frame):len(frame)], ipv4TCP(t, true, true)...)
			udpFrame := append(frame[:len(frame):len(frame)], ipv4UDP(t)...)

			name := fmt.Sprintf("hdlc=%v proto=%#04x", hdlc, proto)
			assert.False(t, runFilter(t, synAck, tcpFrame), name)
			assert.False(t, runFilter(t, tcp, tcpFrame), name)
			assert.False(t, runFilter(t, udp, udpFrame), name)
		}
	}
}
