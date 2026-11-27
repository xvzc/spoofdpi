package netutil

import (
	"errors"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChainControls(t *testing.T) {
	errFirst := errors.New("first failed")
	var calls []string
	record := func(name string, err error) SocketControl {
		return func(string, string, syscall.RawConn) error {
			calls = append(calls, name)
			return err
		}
	}

	tcs := []struct {
		name          string
		first, second SocketControl
		expectedCalls []string
		expectedErr   error
	}{
		{
			name:          "both run in order",
			first:         record("first", nil),
			second:        record("second", nil),
			expectedCalls: []string{"first", "second"},
		},
		{
			name:          "an error of first stops the chain",
			first:         record("first", errFirst),
			second:        record("second", nil),
			expectedCalls: []string{"first"},
			expectedErr:   errFirst,
		},
		{
			name:          "nil first",
			second:        record("second", nil),
			expectedCalls: []string{"second"},
		},
		{
			name:          "nil second",
			first:         record("first", nil),
			expectedCalls: []string{"first"},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			calls = nil
			err := ChainControls(tc.first, tc.second)("tcp6", "[::1]:443", nil)
			assert.ErrorIs(t, err, tc.expectedErr)
			assert.Equal(t, tc.expectedCalls, calls)
		})
	}

	t.Run("both nil", func(t *testing.T) {
		assert.Nil(t, ChainControls(nil, nil))
	})
}

func TestIsIPv6Socket(t *testing.T) {
	tcs := []struct {
		network  string
		expected bool
	}{
		{network: "tcp6", expected: true},
		{network: "udp6", expected: true},
		{network: "ip6", expected: true},
		{network: "ip6:tcp", expected: true},
		{network: "tcp4", expected: false},
		{network: "udp4", expected: false},
		{network: "ip4:255", expected: false},
	}
	for _, tc := range tcs {
		t.Run(tc.network, func(t *testing.T) {
			assert.Equal(t, tc.expected, isIPv6Socket(tc.network))
		})
	}
}
