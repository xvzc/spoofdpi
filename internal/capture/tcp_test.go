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
	"golang.org/x/net/bpf"
)

// segmentFrame builds an IPv4 TCP frame of the given link type.
func segmentFrame(
	t *testing.T,
	linkType layers.LinkType,
	src, dst *net.TCPAddr,
	tcp *layers.TCP,
	payload []byte,
	fragment bool,
) []byte {
	t.Helper()
	tcp.SrcPort = layers.TCPPort(src.Port)
	tcp.DstPort = layers.TCPPort(dst.Port)
	ip := &layers.IPv4{
		Version:  4,
		TTL:      7,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    src.IP.To4(),
		DstIP:    dst.IP.To4(),
	}
	if fragment {
		ip.FragOffset = 100
	}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))

	var layersOut []gopacket.SerializableLayer
	switch linkType {
	case layers.LinkTypeEthernet:
		layersOut = append(layersOut, &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
			DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
			EthernetType: layers.EthernetTypeIPv4,
		})
	case layers.LinkTypeNull:
		layersOut = append(layersOut, &layers.Loopback{Family: layers.ProtocolFamilyIPv4})
	}
	layersOut = append(layersOut, ip, tcp, gopacket.Payload(payload))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(t, gopacket.SerializeLayers(buf, opts, layersOut...))
	return buf.Bytes()
}

func TestParseTCPSegment(t *testing.T) {
	server := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}
	client := &net.TCPAddr{IP: net.ParseIP("192.168.0.2"), Port: 50000}
	sack := make([]byte, 16)
	binary.BigEndian.PutUint32(sack[0:], 3000)
	binary.BigEndian.PutUint32(sack[4:], 3001)
	binary.BigEndian.PutUint32(sack[8:], 4000)
	binary.BigEndian.PutUint32(sack[12:], 4100)

	data := segmentFrame(t, layers.LinkTypeEthernet, server, client, &layers.TCP{
		Seq: 1000, Ack: 2000, ACK: true, Window: 100,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
			{OptionType: layers.TCPOptionKindNop, OptionLength: 1},
			{OptionType: layers.TCPOptionKindSACK, OptionLength: 18, OptionData: sack},
		},
	}, nil, false)
	seg, ok := ParseTCPSegment(
		gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default),
	)
	require.True(t, ok)
	assert.True(t, server.IP.Equal(seg.Src))
	assert.True(t, client.IP.Equal(seg.Dst))
	assert.Equal(t, uint16(443), seg.SrcPort)
	assert.Equal(t, uint16(50000), seg.DstPort)
	assert.Equal(t, uint32(1000), seg.Seq)
	assert.Equal(t, uint32(2000), seg.Ack)
	assert.True(t, seg.ACK)
	assert.False(t, seg.SYN || seg.RST || seg.FIN)
	assert.Equal(t, 0, seg.PayloadLen)
	assert.Equal(t, uint8(7), seg.TTL)
	assert.Equal(t, [][2]uint32{{3000, 3001}, {4000, 4100}}, seg.SACK)

	data = segmentFrame(t, layers.LinkTypeEthernet, client, server,
		&layers.TCP{Seq: 5, PSH: true, ACK: true}, []byte("hello"), false)
	seg, ok = ParseTCPSegment(
		gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default),
	)
	require.True(t, ok)
	assert.Equal(t, 5, seg.PayloadLen)
	assert.Nil(t, seg.SACK)

	udp := &layers.UDP{SrcPort: 1, DstPort: 2}
	ip := &layers.IPv4{
		Version: 4, TTL: 3, Protocol: layers.IPProtocolUDP,
		SrcIP: client.IP.To4(), DstIP: server.IP.To4(),
	}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf,
		gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}, ip, udp))
	_, ok = ParseTCPSegment(
		gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default),
	)
	assert.False(t, ok, "UDP")
}

// runFilter runs prog on data and reports whether it accepts it.
func runFilter(t *testing.T, prog []BPFInstruction, data []byte) bool {
	t.Helper()
	raw := make([]bpf.RawInstruction, len(prog))
	for i, in := range prog {
		raw[i] = bpf.RawInstruction{Op: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	insns, ok := bpf.Disassemble(raw)
	require.True(t, ok)
	vm, err := bpf.NewVM(insns)
	require.NoError(t, err)
	n, err := vm.Run(data)
	require.NoError(t, err)
	return n > 0
}

// hostFilterFrame builds an IPv4 TCP frame on link, from src to dst.
func hostFilterFrame(
	t *testing.T,
	link filterLink,
	src, dst *net.TCPAddr,
	fragment bool,
) []byte {
	t.Helper()
	ip := segmentFrame(
		t,
		layers.LinkTypeRaw,
		src,
		dst,
		&layers.TCP{ACK: true},
		nil,
		fragment,
	)
	frame, ok := onLink(link.lt, link.hdlc, filterFrame{
		etherType: layers.EthernetTypeIPv4,
		payload:   ip,
	})
	require.True(t, ok)
	return frame
}

func TestTCPHostFilter(t *testing.T) {
	watched := &net.TCPAddr{IP: net.ParseIP("203.0.113.7"), Port: 443}
	other := &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 443}
	local := &net.TCPAddr{IP: net.ParseIP("192.168.0.2"), Port: 50000}
	hosts := []net.IP{net.ParseIP("203.0.113.1"), watched.IP, net.ParseIP("2001:db8::1")}

	for _, link := range filterLinks {
		t.Run(link.name, func(t *testing.T) {
			prog, err := TCPHostFilter(link.lt, hosts)
			require.NoError(t, err)
			frame := func(src, dst *net.TCPAddr, fragment bool) []byte {
				return hostFilterFrame(t, link, src, dst, fragment)
			}
			assert.True(t, runFilter(t, prog, frame(watched, local, false)), "from a host")
			assert.True(t, runFilter(t, prog, frame(local, watched, false)), "to a host")
			assert.False(t, runFilter(t, prog, frame(other, local, false)), "another host")
			assert.False(t, runFilter(t, prog, frame(local, watched, true)), "a fragment")
		})
	}
}

func TestTCPHostFilter_ManyHosts(t *testing.T) {
	var hosts []net.IP
	for i := range maxFilterHosts {
		hosts = append(hosts, net.ParseIP(fmt.Sprintf("10.0.%d.%d", i/250, i%250+1)))
	}
	local := &net.TCPAddr{IP: net.ParseIP("192.168.0.2"), Port: 50000}
	last := &net.TCPAddr{IP: hosts[len(hosts)-1], Port: 443}
	other := &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 443}

	// PPP is the longest program, with one copy for each framing.
	for _, link := range filterLinks {
		t.Run(link.name, func(t *testing.T) {
			frame := func(src, dst *net.TCPAddr) []byte {
				return hostFilterFrame(t, link, src, dst, false)
			}

			prog, err := TCPHostFilter(link.lt, hosts)
			require.NoError(t, err)
			assert.True(t, runFilter(t, prog, frame(local, last)), "the farthest jump fits")
			assert.False(t, runFilter(t, prog, frame(local, other)))

			prog, err = TCPHostFilter(link.lt, append(hosts, net.ParseIP("10.9.9.9")))
			require.NoError(t, err)
			assert.True(t, runFilter(t, prog, frame(local, other)), "too many hosts: all TCP")
		})
	}
}
