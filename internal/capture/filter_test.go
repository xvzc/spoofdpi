package capture

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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

// onLink wraps f in the link-layer header of lt. ok is false when f
// cannot travel on lt (ARP has no Null/Loop/Raw encoding).
func onLink(lt layers.LinkType, f filterFrame) (frame []byte, ok bool) {
	switch lt {
	case layers.LinkTypeEthernet:
		hdr := make([]byte, 14)
		copy(hdr[0:6], []byte{6, 7, 8, 9, 10, 11})
		copy(hdr[6:12], []byte{0, 1, 2, 3, 4, 5})
		binary.BigEndian.PutUint16(hdr[12:14], uint16(f.etherType))
		return append(hdr, f.payload...), true
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

var filterLinkTypes = []layers.LinkType{
	layers.LinkTypeEthernet,
	layers.LinkTypeNull,
	layers.LinkTypeLoop,
	layers.LinkTypeRaw,
}

// testFilter checks that the program built by filter accepts exactly the
// frames whose name is in accept, on every supported link type.
func testFilter(
	t *testing.T,
	filter func(layers.LinkType) []BPFInstruction,
	frames []filterFrame,
	accept map[string]bool,
) {
	t.Helper()

	for _, lt := range filterLinkTypes {
		for _, f := range frames {
			frame, ok := onLink(lt, f)
			if !ok {
				continue
			}
			t.Run(lt.String()+"/"+f.name, func(t *testing.T) {
				require.Equal(t, accept[f.name], runFilter(t, filter(lt), frame))
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
