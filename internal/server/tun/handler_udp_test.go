package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/rule"
)

// dialCountingSysNet counts dial attempts and fails each one, so a flow
// that gets as far as dialing ends without touching the network.
type dialCountingSysNet struct {
	TUNSystemNetwork
	dials atomic.Int32
}

func (s *dialCountingSysNet) BindDialer(*net.Dialer, string, net.IP) error {
	s.dials.Add(1)
	return errors.New("dial disabled in test")
}

func TestUDPHandler_Handle_Block(t *testing.T) {
	tcs := []struct {
		name      string
		block     bool
		wantDials int32
	}{
		{"blocked destination is not dialed", true, 0},
		{"allowed destination is dialed", false, 1},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			rs := rule.NewRuleSet()
			require.NoError(t, rs.Add(&config.Rule{
				Name:     "udp",
				Priority: 10,
				Block:    tc.block,
				Match:    &config.MatchAttrs{CIDRs: []string{"203.0.113.0/24"}},
			}))

			h := NewUDPHandler(
				zerolog.Nop(),
				desync.NewUDPDesyncer(zerolog.Nop(), nil, nil, nil),
				rs,
				&config.RuntimeConfig{},
			)

			lConn, peer := net.Pipe()
			defer func() { _ = peer.Close() }()

			sysNet := &dialCountingSysNet{}
			dst := &netutil.Destination{
				Addrs: []net.IP{net.ParseIP("203.0.113.7")},
				Port:  443,
			}

			done := make(chan struct{})
			go func() {
				h.Handle(context.Background(), lConn, dst, sysNet)
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Handle did not return")
			}

			assert.Equal(t, tc.wantDials, sysNet.dials.Load())

			// The flow is closed: the client side sees the end of the pipe.
			_, err := peer.Read(make([]byte, 1))
			assert.ErrorIs(t, err, io.EOF)
		})
	}
}
