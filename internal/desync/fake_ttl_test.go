package desync

import (
	"context"
	"net"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
)

// fakeTTLCases are fake TTLs for the connection options a connection was
// given: the base options, or those of the rule it matched.
var fakeTTLCases = []struct {
	name    string
	sniffer stubSniffer
	conn    *config.ConnOptions
	want    uint8
}{
	{"base options, not learned", stubSniffer{}, baseConnOpts(), 7},
	{
		"base options, learned",
		stubSniffer{hopLearned: true, hops: 16},
		baseConnOpts(),
		15,
	},
	{
		"rule hop-count-default, not learned",
		stubSniffer{},
		&config.ConnOptions{HopCountDefault: 12, HopCountMax: 255},
		11,
	},
	{
		"rule hop-count-default, learned",
		stubSniffer{hopLearned: true, hops: 16},
		&config.ConnOptions{HopCountDefault: 12, HopCountMax: 255},
		15,
	},
	{
		"rule hop-count-offset, learned",
		stubSniffer{hopLearned: true, hops: 16},
		&config.ConnOptions{HopCountDefault: 8, HopCountMax: 255, HopCountOffset: -5},
		10,
	},
	{
		"rule hop-count-offset, not learned",
		stubSniffer{},
		&config.ConnOptions{HopCountDefault: 8, HopCountMax: 255, HopCountOffset: -5},
		7,
	},
	{
		"rule hop-count-max",
		stubSniffer{hopLearned: true, hops: 43},
		&config.ConnOptions{HopCountDefault: 8, HopCountMax: 20},
		19,
	},
	{
		"rule hop-count-min",
		stubSniffer{hopLearned: true, hops: 5},
		&config.ConnOptions{HopCountDefault: 8, HopCountMin: 10, HopCountMax: 255},
		9,
	},
}

func TestDesync_FakeTTLFromConnOptions(t *testing.T) {
	for _, tc := range fakeTTLCases {
		t.Run(tc.name, func(t *testing.T) {
			w := &recordingWriter{}
			d := NewTLSDesyncer(zerolog.Nop(), w, tc.sniffer, nil)
			opts := tlsOpts(1, 100)
			opts.SynAckTimeout = 0

			_, err := d.Desync(
				context.Background(),
				newStubConn("203.0.113.1"),
				fakeMsg(),
				opts,
				tc.conn,
			)
			require.NoError(t, err)

			require.NotEmpty(t, w.packets)
			for _, p := range w.packets {
				assert.Equal(t, tc.want, p.ttl)
			}
		})
	}
}

func TestUDPDesync_FakeTTLFromConnOptions(t *testing.T) {
	conn := udpConn{
		local:  &net.UDPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000},
		remote: &net.UDPAddr{IP: net.ParseIP("203.0.113.1"), Port: 443},
	}
	opts := &config.UDPOptions{FakePreflight: 1, FakePacket: make([]byte, 8)}

	for _, tc := range fakeTTLCases {
		t.Run(tc.name, func(t *testing.T) {
			w := &udpWriter{}
			d := NewUDPDesyncer(zerolog.Nop(), w, tc.sniffer)

			_, err := d.Desync(context.Background(), conn, opts, tc.conn)
			require.NoError(t, err)

			require.Equal(t, 1, w.n)
			assert.Equal(t, tc.want, w.ttl)
		})
	}
}

// TestDesync_LocalLinkIgnoresRuleHopCount checks that a server learned on
// the local link gets no fakes, even when the connection's options would
// raise its hop count.
func TestDesync_LocalLinkIgnoresRuleHopCount(t *testing.T) {
	sniffer := stubSniffer{hopLearned: true, hops: 0}
	connOpts := &config.ConnOptions{
		HopCountDefault: 8,
		HopCountMin:     10,
		HopCountMax:     255,
		HopCountOffset:  5,
	}

	t.Run("tls", func(t *testing.T) {
		w := &recordingWriter{}
		d := NewTLSDesyncer(zerolog.Nop(), w, sniffer, nil)
		opts := tlsOpts(1, 100)
		opts.SynAckTimeout = 0

		_, err := d.Desync(
			context.Background(),
			newStubConn("192.168.1.20"),
			fakeMsg(),
			opts,
			connOpts,
		)
		require.NoError(t, err)
		assert.Empty(t, w.packets)
	})

	t.Run("udp", func(t *testing.T) {
		conn := udpConn{
			local:  &net.UDPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000},
			remote: &net.UDPAddr{IP: net.ParseIP("192.168.1.20"), Port: 443},
		}
		w := &udpWriter{}
		d := NewUDPDesyncer(zerolog.Nop(), w, sniffer)

		_, err := d.Desync(
			context.Background(),
			conn,
			&config.UDPOptions{FakePreflight: 1, FakePacket: make([]byte, 8)},
			connOpts,
		)
		require.NoError(t, err)
		assert.Equal(t, 0, w.n)
	})
}
