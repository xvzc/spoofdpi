package tun

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/tun"
)

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
