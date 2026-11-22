package dns

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreferIPv4(t *testing.T) {
	addrs := func(ss ...string) []netip.Addr {
		out := make([]netip.Addr, len(ss))
		for i, s := range ss {
			out[i] = netip.MustParseAddr(s)
		}
		return out
	}

	tcs := []struct {
		name   string
		addrs  []netip.Addr
		want   string
		wantOK bool
	}{
		{"no address", nil, "", false},
		{"only ipv4", addrs("192.0.2.1", "192.0.2.2"), "192.0.2.1", true},
		{"ipv6 before ipv4", addrs("2001:db8::1", "192.0.2.1"), "192.0.2.1", true},
		{"only ipv6", addrs("2001:db8::1", "2001:db8::2"), "2001:db8::1", true},
		{
			"mapped ipv4 is unmapped",
			addrs("2001:db8::1", "::ffff:192.0.2.1"),
			"192.0.2.1",
			true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := preferIPv4(tc.addrs)
			require.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, netip.MustParseAddr(tc.want), got)
			}
		})
	}
}

func TestSystemResolver_Resolve_MatchesResolveUDPAddr(t *testing.T) {
	for _, name := range []string{"localhost", "127.0.0.1", "::1"} {
		t.Run(name, func(t *testing.T) {
			want, err := net.ResolveUDPAddr("udp", net.JoinHostPort(name, "53"))
			require.NoError(t, err)

			got, err := SystemResolver{}.Resolve(context.Background(), nil, name)
			require.NoError(t, err)

			require.Len(t, got, 1)
			assert.True(
				t,
				want.IP.Equal(got[0].AsSlice()),
				"got %s, want %s",
				got[0],
				want.IP,
			)
		})
	}
}

func TestSystemResolver_Resolve_Error(t *testing.T) {
	_, err := SystemResolver{}.Resolve(context.Background(), nil, "unresolvable.invalid")
	assert.Error(t, err)
}
