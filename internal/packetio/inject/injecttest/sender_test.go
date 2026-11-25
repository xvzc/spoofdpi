package injecttest

import (
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/packetio/inject"
)

func testPacket(b byte) inject.Packet {
	return inject.Packet{
		Src:      netip.MustParseAddr("192.168.1.11"),
		Dst:      netip.MustParseAddr("192.0.2.1"),
		Proto:    6,
		HopLimit: 3,
		L4:       []byte{b},
	}
}

func TestSender_RecordsCopies(t *testing.T) {
	var s Sender
	p := testPacket(1)
	require.NoError(t, s.Send(p))
	p.L4[0] = 9

	got := s.Packets()
	require.Len(t, got, 1)
	assert.Equal(t, []byte{1}, got[0].L4)
	assert.Equal(t, uint8(3), got[0].HopLimit)
}

func TestSender_Err(t *testing.T) {
	var s Sender
	sendErr := inject.NewSendError(netip.MustParseAddr("192.0.2.9"), syscall.EPERM)
	s.SetErr(sendErr)
	assert.Same(t, sendErr, s.Send(testPacket(1)))
	assert.Empty(t, s.Packets())

	s.SetErr(syscall.EMSGSIZE)
	var got *inject.SendError
	require.ErrorAs(t, s.Send(testPacket(1)), &got)
	assert.Equal(t, inject.KindTooBig, got.Kind)
	assert.Equal(t, netip.MustParseAddr("192.0.2.1"), got.Dst)
	assert.ErrorIs(t, got, syscall.EMSGSIZE)
	assert.Empty(t, s.Packets())

	s.SetErr(nil)
	require.NoError(t, s.Send(testPacket(2)))
	assert.Len(t, s.Packets(), 1)
}

func TestSender_Close(t *testing.T) {
	var s Sender
	require.NoError(t, s.Close())
	assert.True(t, s.Closed())
	err := s.Send(testPacket(1))
	var sendErr *inject.SendError
	require.ErrorAs(t, err, &sendErr)
	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestSender_Concurrent(t *testing.T) {
	var s Sender
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Go(func() { _ = s.Send(testPacket(byte(i))) })
	}
	wg.Wait()
	assert.Len(t, s.Packets(), 16)
}
