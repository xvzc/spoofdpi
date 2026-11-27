package desync

import (
	"bytes"
	"errors"
	"net"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packetio/capture"
)

var (
	ipv4Only = netutil.NewFamilySet(netutil.FamilyV4)
	ipv6Only = netutil.NewFamilySet(netutil.FamilyV6)
	bothFams = netutil.NewFamilySet(netutil.FamilyV4, netutil.FamilyV6)
)

// linkHandle is a filterHandle on the link type lt.
type linkHandle struct {
	*filterHandle
	lt layers.LinkType
}

func (h *linkHandle) LinkType() layers.LinkType { return h.lt }

// useCaptureHandle makes the stacks open h, or fail with openErr, for the
// rest of the test.
func useCaptureHandle(t *testing.T, h capture.Handle, openErr error) {
	t.Helper()

	orig := newCaptureHandle
	t.Cleanup(func() { newCaptureHandle = orig })
	newCaptureHandle = func(*net.Interface) (capture.Handle, error) {
		return h, openErr
	}
}

// useCaptureHandles makes the stacks open the handle of handles named
// after the interface, or fail with the error of openErrs named after it,
// for the rest of the test. It returns the names of the interfaces
// opened, in order.
func useCaptureHandles(
	t *testing.T,
	handles map[string]capture.Handle,
	openErrs map[string]error,
) *[]string {
	t.Helper()

	orig := newCaptureHandle
	t.Cleanup(func() { newCaptureHandle = orig })
	var opened []string
	newCaptureHandle = func(iface *net.Interface) (capture.Handle, error) {
		opened = append(opened, iface.Name)
		if err := openErrs[iface.Name]; err != nil {
			return nil, err
		}
		h, ok := handles[iface.Name]
		require.True(t, ok, "unexpected interface %s", iface.Name)
		return h, nil
	}
	return &opened
}

// rejectFirstHandle is a filterHandle that rejects the first rejects
// filters installed on it with errRejected.
type rejectFirstHandle struct {
	*filterHandle
	rejects int
}

var errRejected = errors.New("program rejected")

func (h *rejectFirstHandle) SetBPFRawInstructionFilter(
	f []capture.BPFInstruction,
) error {
	if h.rejects > 0 {
		h.rejects--
		return errRejected
	}
	return h.filterHandle.SetBPFRawInstructionFilter(f)
}

// egress returns the egress interface name with the families fams.
func egress(name string, fams netutil.FamilySet) []EgressIface {
	return []EgressIface{{Iface: net.Interface{Name: name}, Fams: fams}}
}

// filterOf returns the program filter builds for lt and fams.
func filterOf(
	t *testing.T,
	filter func(layers.LinkType, netutil.FamilySet) ([]capture.BPFInstruction, error),
	lt layers.LinkType,
	fams netutil.FamilySet,
) []capture.BPFInstruction {
	t.Helper()

	prog, err := filter(lt, fams)
	require.NoError(t, err)
	return prog
}

func TestOpenTCPStack(t *testing.T) {
	iface := egress("test0", ipv4Only)
	rejected := errors.New("program rejected")

	t.Run("a supported link type starts the sniffer", func(t *testing.T) {
		h := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
		useCaptureHandle(t, h, nil)
		var logs bytes.Buffer

		stack, err := OpenTCPStack(
			"", zerolog.New(&logs), iface, Senders{}, NewHopStore(),
		)

		require.NoError(t, err)
		assert.Len(t, stack.Sniffers, 1)
		assert.NotNil(t, stack.Seqs)
		assert.NotNil(t, stack.Writer)
		assert.Equal(t,
			filterOf(t, capture.SynAckFilter, layers.LinkTypeEthernet, ipv4Only),
			h.filter)
		assert.False(t, h.closed)
		assert.Empty(t, logs.String())
	})

	t.Run("an unsupported link type leaves nothing to learn", func(t *testing.T) {
		h := &linkHandle{&filterHandle{}, layers.LinkTypeLinuxSLL}
		useCaptureHandle(t, h, nil)
		var logs bytes.Buffer

		stack, err := OpenTCPStack(
			"", zerolog.New(&logs), iface, Senders{}, NewHopStore(),
		)

		require.NoError(t, err)
		assert.Empty(t, stack.Sniffers)
		assert.Nil(t, stack.Seqs)
		assert.NotNil(t, stack.Writer)
		assert.False(t, stack.LearnsSeq(net.ParseIP("203.0.113.1")))
		assert.Empty(t, h.filter)
		assert.True(t, h.closed, "the handle is closed")
		assert.Zero(t, h.reads.Load())
		assert.Contains(t, logs.String(), `"level":"warn"`)
		assert.Contains(t, logs.String(), `"interface":"test0"`)
		assert.Contains(t, logs.String(), "unsupported link type: 113")
		assert.Contains(t, logs.String(),
			"hop counts and sequence numbers are not learned on this interface; "+
				"fake packets use hop-count-default and random sequence numbers")
	})

	t.Run("another sniffer error is fatal", func(t *testing.T) {
		h := &linkHandle{&filterHandle{setErr: rejected}, layers.LinkTypeEthernet}
		useCaptureHandle(t, h, nil)

		stack, err := OpenTCPStack("", zerolog.Nop(), iface, Senders{}, NewHopStore())

		require.ErrorIs(t, err, rejected)
		assert.EqualError(t, err,
			"on test0: set SYN/ACK capture filter: program rejected")
		assert.Nil(t, stack)
		assert.True(t, h.closed, "the handle is closed")
	})

	t.Run("an open error is fatal", func(t *testing.T) {
		useCaptureHandle(t, nil, rejected)

		stack, err := OpenTCPStack("", zerolog.Nop(), iface, Senders{}, NewHopStore())

		require.ErrorIs(t, err, rejected)
		assert.EqualError(t, err, "on test0: program rejected")
		assert.Nil(t, stack)
	})
}

func TestOpenTCPStack_Interfaces(t *testing.T) {
	v4 := net.ParseIP("203.0.113.1")
	v6 := net.ParseIP("2001:db8::1")

	t.Run("two interfaces get a handle each", func(t *testing.T) {
		eth := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
		tun := &linkHandle{&filterHandle{}, layers.LinkTypeRaw}
		opened := useCaptureHandles(
			t,
			map[string]capture.Handle{"en0": eth, "gif0": tun},
			nil,
		)

		stack, err := OpenTCPStack(
			"",
			zerolog.Nop(),
			append(egress("en0", ipv4Only), egress("gif0", ipv6Only)...),
			Senders{},
			NewHopStore(),
		)

		require.NoError(t, err)
		assert.Equal(t, []string{"en0", "gif0"}, *opened)
		assert.Len(t, stack.Sniffers, 2)
		assert.Equal(t,
			filterOf(t, capture.SynAckFilter, layers.LinkTypeEthernet, ipv4Only),
			eth.filter)
		assert.Equal(t,
			filterOf(t, capture.SynAckFilter, layers.LinkTypeRaw, ipv6Only),
			tun.filter)
		assert.True(t, stack.LearnsSeq(v4))
		assert.True(t, stack.LearnsSeq(v6))
	})

	t.Run("one interface of both families gets one handle", func(t *testing.T) {
		eth := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
		opened := useCaptureHandles(t, map[string]capture.Handle{"en0": eth}, nil)

		stack, err := OpenTCPStack(
			"", zerolog.Nop(), egress("en0", bothFams), Senders{}, NewHopStore(),
		)

		require.NoError(t, err)
		assert.Equal(t, []string{"en0"}, *opened)
		assert.Len(t, stack.Sniffers, 1)
		assert.Equal(t,
			filterOf(t, capture.SynAckFilter, layers.LinkTypeEthernet, bothFams),
			eth.filter)
		assert.True(t, stack.LearnsSeq(v4))
		assert.True(t, stack.LearnsSeq(v6))
	})

	t.Run("an unsupported link drops only its families", func(t *testing.T) {
		eth := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
		sll := &linkHandle{&filterHandle{}, layers.LinkTypeLinuxSLL}
		useCaptureHandles(t, map[string]capture.Handle{"en0": eth, "sll0": sll}, nil)
		var logs bytes.Buffer

		stack, err := OpenTCPStack(
			"",
			zerolog.New(&logs),
			append(egress("en0", ipv4Only), egress("sll0", ipv6Only)...),
			Senders{},
			NewHopStore(),
		)

		require.NoError(t, err)
		assert.Len(t, stack.Sniffers, 1)
		assert.NotNil(t, stack.Seqs)
		assert.NotEmpty(t, eth.filter)
		assert.False(t, eth.closed)
		assert.True(t, sll.closed, "the unsupported handle is closed")
		assert.Contains(t, logs.String(), `"level":"warn"`)
		assert.Contains(t, logs.String(), `"interface":"sll0"`)
		assert.True(t, stack.LearnsSeq(v4))
		assert.False(t, stack.LearnsSeq(v6))
	})
}

func TestTCPStack_LearnsSeq(t *testing.T) {
	tcs := []struct {
		name   string
		learns netutil.FamilySet
		ip     net.IP
		want   bool
	}{
		{"ipv4 learned", ipv4Only, net.ParseIP("203.0.113.1"), true},
		{"ipv4-mapped is ipv4", ipv4Only, net.ParseIP("::ffff:203.0.113.1"), true},
		{"ipv6 not learned", ipv4Only, net.ParseIP("2001:db8::1"), false},
		{"ipv6 learned", ipv6Only, net.ParseIP("2001:db8::1"), true},
		{"ipv4 not learned", ipv6Only, net.ParseIP("203.0.113.1"), false},
		{"both", bothFams, net.ParseIP("2001:db8::1"), true},
		{"none", 0, net.ParseIP("203.0.113.1"), false},
		{"invalid address", bothFams, net.IP{1, 2, 3}, false},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			s := &TCPStack{learns: tc.learns}
			assert.Equal(t, tc.want, s.LearnsSeq(tc.ip))
		})
	}
}

func TestOpenUDPStack(t *testing.T) {
	iface := egress("test0", ipv4Only)
	rejected := errors.New("program rejected")

	t.Run("a supported link type starts the sniffer", func(t *testing.T) {
		h := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
		useCaptureHandle(t, h, nil)
		var logs bytes.Buffer

		stack, err := OpenUDPStack(
			"", zerolog.New(&logs), iface, Senders{}, NewHopStore(),
		)

		require.NoError(t, err)
		assert.Len(t, stack.Sniffers, 1)
		assert.NotNil(t, stack.Writer)
		assert.Equal(t,
			filterOf(t, capture.UDPFilter, layers.LinkTypeEthernet, ipv4Only),
			h.filter)
		assert.False(t, h.closed)
		assert.Empty(t, logs.String())
	})

	t.Run("an unsupported link type leaves nothing to learn", func(t *testing.T) {
		h := &linkHandle{&filterHandle{}, layers.LinkTypeLinuxSLL}
		useCaptureHandle(t, h, nil)
		var logs bytes.Buffer

		stack, err := OpenUDPStack(
			"", zerolog.New(&logs), iface, Senders{}, NewHopStore(),
		)

		require.NoError(t, err)
		assert.Empty(t, stack.Sniffers)
		assert.NotNil(t, stack.Writer)
		assert.Empty(t, h.filter)
		assert.True(t, h.closed, "the handle is closed")
		assert.Zero(t, h.reads.Load())
		assert.Contains(t, logs.String(), `"level":"warn"`)
		assert.Contains(t, logs.String(), `"interface":"test0"`)
		assert.Contains(t, logs.String(), "unsupported link type: 113")
		assert.Contains(t, logs.String(),
			"hop counts are not learned on this interface; "+
				"fake packets use hop-count-default")
	})

	t.Run("another sniffer error is fatal", func(t *testing.T) {
		h := &linkHandle{&filterHandle{setErr: rejected}, layers.LinkTypeEthernet}
		useCaptureHandle(t, h, nil)

		stack, err := OpenUDPStack("", zerolog.Nop(), iface, Senders{}, NewHopStore())

		require.ErrorIs(t, err, rejected)
		assert.EqualError(t, err,
			"on test0: set UDP capture filter: program rejected")
		assert.Nil(t, stack)
		assert.True(t, h.closed, "the handle is closed")
	})

	t.Run("an open error is fatal", func(t *testing.T) {
		useCaptureHandle(t, nil, rejected)

		stack, err := OpenUDPStack("", zerolog.Nop(), iface, Senders{}, NewHopStore())

		require.ErrorIs(t, err, rejected)
		assert.EqualError(t, err, "on test0: program rejected")
		assert.Nil(t, stack)
	})
}

func TestOpenUDPStack_Interfaces(t *testing.T) {
	t.Run("two interfaces get a handle each", func(t *testing.T) {
		eth := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
		tun := &linkHandle{&filterHandle{}, layers.LinkTypeRaw}
		opened := useCaptureHandles(
			t,
			map[string]capture.Handle{"en0": eth, "gif0": tun},
			nil,
		)

		stack, err := OpenUDPStack(
			"",
			zerolog.Nop(),
			append(egress("en0", ipv4Only), egress("gif0", ipv6Only)...),
			Senders{},
			NewHopStore(),
		)

		require.NoError(t, err)
		assert.Equal(t, []string{"en0", "gif0"}, *opened)
		assert.Len(t, stack.Sniffers, 2)
		assert.Equal(t,
			filterOf(t, capture.UDPFilter, layers.LinkTypeEthernet, ipv4Only),
			eth.filter)
		assert.Equal(t,
			filterOf(t, capture.UDPFilter, layers.LinkTypeRaw, ipv6Only),
			tun.filter)
	})

	t.Run("one interface of both families gets one handle", func(t *testing.T) {
		eth := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
		opened := useCaptureHandles(t, map[string]capture.Handle{"en0": eth}, nil)

		stack, err := OpenUDPStack(
			"", zerolog.Nop(), egress("en0", bothFams), Senders{}, NewHopStore(),
		)

		require.NoError(t, err)
		assert.Equal(t, []string{"en0"}, *opened)
		assert.Len(t, stack.Sniffers, 1)
		assert.Equal(t,
			filterOf(t, capture.UDPFilter, layers.LinkTypeEthernet, bothFams),
			eth.filter)
	})

	t.Run("an unsupported link keeps the other handles", func(t *testing.T) {
		eth := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
		sll := &linkHandle{&filterHandle{}, layers.LinkTypeLinuxSLL}
		useCaptureHandles(t, map[string]capture.Handle{"en0": eth, "sll0": sll}, nil)
		var logs bytes.Buffer

		stack, err := OpenUDPStack(
			"",
			zerolog.New(&logs),
			append(egress("en0", ipv4Only), egress("sll0", ipv6Only)...),
			Senders{},
			NewHopStore(),
		)

		require.NoError(t, err)
		assert.Len(t, stack.Sniffers, 1)
		assert.NotEmpty(t, eth.filter)
		assert.False(t, eth.closed)
		assert.True(t, sll.closed, "the unsupported handle is closed")
		assert.Contains(t, logs.String(), `"interface":"sll0"`)
	})
}

// stackCase opens a TCP or UDP stack for TestOpenStacks_CaptureFailures.
type stackCase struct {
	name string
	// filter builds the capture filter of the stack.
	filter func(layers.LinkType, netutil.FamilySet) ([]capture.BPFInstruction, error)
	// setErr is the error the stack reports for a rejected filter.
	setErr string
	warn   captureWarnings
	// open opens the stack and returns its number of sniffers, and a
	// LearnsSeq of it, nil for a stack that learns no sequence numbers.
	open func(
		logger zerolog.Logger,
		ifaces []EgressIface,
	) (int, func(net.IP) bool, error)
}

var stackCases = []stackCase{
	{
		name:   "tcp",
		filter: capture.SynAckFilter,
		setErr: "set SYN/ACK capture filter: program rejected",
		warn:   tcpCaptureWarnings,
		open: func(logger zerolog.Logger, ifaces []EgressIface) (int, func(net.IP) bool, error) {
			s, err := OpenTCPStack("", logger, ifaces, Senders{}, NewHopStore())
			if err != nil {
				return 0, nil, err
			}
			return len(s.Sniffers), s.LearnsSeq, nil
		},
	},
	{
		name:   "udp",
		filter: capture.UDPFilter,
		setErr: "set UDP capture filter: program rejected",
		warn:   udpCaptureWarnings,
		open: func(logger zerolog.Logger, ifaces []EgressIface) (int, func(net.IP) bool, error) {
			s, err := OpenUDPStack("", logger, ifaces, Senders{}, NewHopStore())
			if err != nil {
				return 0, nil, err
			}
			return len(s.Sniffers), nil, nil
		},
	},
}

// TestOpenStacks_CaptureFailures checks that only the failures that cost
// IPv4 capture are fatal.
func TestOpenStacks_CaptureFailures(t *testing.T) {
	v4 := net.ParseIP("203.0.113.1")
	v6 := net.ParseIP("2001:db8::1")
	twoIfaces := append(egress("en0", ipv4Only), egress("gif0", ipv6Only)...)

	for _, sc := range stackCases {
		t.Run(sc.name+"/ipv6 interface that does not open", func(t *testing.T) {
			eth := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
			useCaptureHandles(t,
				map[string]capture.Handle{"en0": eth},
				map[string]error{"gif0": errRejected})
			var logs bytes.Buffer

			n, learns, err := sc.open(zerolog.New(&logs), twoIfaces)

			require.NoError(t, err)
			assert.Equal(t, 1, n)
			assert.False(t, eth.closed)
			assert.Contains(t, logs.String(), `"level":"warn"`)
			assert.Contains(t, logs.String(), `"interface":"gif0"`)
			assert.Contains(t, logs.String(), "program rejected")
			assert.Contains(t, logs.String(), sc.warn.none)
			if learns != nil {
				assert.True(t, learns(v4))
				assert.False(t, learns(v6))
			}
		})

		t.Run(sc.name+"/ipv6 interface whose filter is rejected", func(t *testing.T) {
			eth := &linkHandle{&filterHandle{}, layers.LinkTypeEthernet}
			gif := &linkHandle{&filterHandle{setErr: errRejected}, layers.LinkTypeRaw}
			useCaptureHandles(t, map[string]capture.Handle{"en0": eth, "gif0": gif}, nil)
			var logs bytes.Buffer

			n, learns, err := sc.open(zerolog.New(&logs), twoIfaces)

			require.NoError(t, err)
			assert.Equal(t, 1, n)
			assert.False(t, eth.closed)
			assert.True(t, gif.closed, "the rejected handle is closed")
			assert.Zero(t, gif.reads.Load())
			assert.Contains(t, logs.String(), `"interface":"gif0"`)
			assert.Contains(t, logs.String(), sc.warn.none)
			if learns != nil {
				assert.True(t, learns(v4))
				assert.False(t, learns(v6))
			}
		})

		t.Run(sc.name+"/shared interface falls back to ipv4", func(t *testing.T) {
			eth := &rejectFirstHandle{&filterHandle{}, 1}
			useCaptureHandles(t, map[string]capture.Handle{"en0": eth}, nil)
			var logs bytes.Buffer

			n, learns, err := sc.open(zerolog.New(&logs), egress("en0", bothFams))

			require.NoError(t, err)
			assert.Equal(t, 1, n)
			assert.False(t, eth.closed)
			assert.Equal(t,
				filterOf(t, sc.filter, layers.LinkTypeEthernet, ipv4Only),
				eth.filter, "the ipv4 filter is installed")
			assert.Contains(t, logs.String(), `"level":"warn"`)
			assert.Contains(t, logs.String(), `"interface":"en0"`)
			assert.Contains(t, logs.String(), sc.warn.ipv6)
			assert.NotContains(t, logs.String(), sc.warn.none)
			if learns != nil {
				assert.True(t, learns(v4))
				assert.False(t, learns(v6))
			}
		})

		t.Run(sc.name+"/shared interface without ipv4 is fatal", func(t *testing.T) {
			eth := &rejectFirstHandle{&filterHandle{}, 2}
			useCaptureHandles(t, map[string]capture.Handle{"en0": eth}, nil)

			_, _, err := sc.open(zerolog.Nop(), egress("en0", bothFams))

			require.ErrorIs(t, err, errRejected)
			assert.EqualError(t, err, "on en0: "+sc.setErr)
			assert.True(t, eth.closed, "the handle is closed")
		})

		t.Run(sc.name+"/second interface fails fatally", func(t *testing.T) {
			gif := &linkHandle{&filterHandle{}, layers.LinkTypeRaw}
			eth := &linkHandle{&filterHandle{setErr: errRejected}, layers.LinkTypeEthernet}
			opened := useCaptureHandles(t,
				map[string]capture.Handle{"gif0": gif, "en0": eth}, nil)

			_, _, err := sc.open(
				zerolog.Nop(),
				append(egress("gif0", ipv6Only), egress("en0", ipv4Only)...),
			)

			require.ErrorIs(t, err, errRejected)
			assert.EqualError(t, err, "on en0: "+sc.setErr)
			assert.Equal(t, []string{"gif0", "en0"}, *opened)
			assert.True(t, eth.closed, "the failed handle is closed")
			assert.False(t, gif.closed, "the started sniffer keeps its handle")
		})
	}
}
