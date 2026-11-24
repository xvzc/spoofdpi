package desync

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
)

// testGate allows fakes to IPv4 servers only, as main wires it.
var testGate = packet.NewStaticGate(
	nil,
	&packet.FakesOffError{
		Family: netutil.FamilyV6,
		Reason: "IPv6 fakes are not supported yet",
	},
)

// writeRecordingConn is a stubConn that records each write.
type writeRecordingConn struct {
	stubConn
	writes [][]byte
}

func (c *writeRecordingConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

// resetCannotFakeWarning makes the next skipped fake warn again, as in a
// new process.
func resetCannotFakeWarning(t *testing.T) {
	t.Helper()
	cannotFakeWarned.Clear()
	t.Cleanup(cannotFakeWarned.Clear)
}

func TestDesync_FakeCapability(t *testing.T) {
	tcs := []struct {
		name      string
		local     string
		remote    string
		wantFakes bool
	}{
		{"ipv4 server", "192.168.1.11", "203.0.113.1", true},
		{"ipv6 server", "2001:db8::2", "2001:db8::1", false},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			resetCannotFakeWarning(t)

			w := &recordingWriter{}
			d := NewTLSDesyncer(zerolog.Nop(), w, stubHops{}, nil, testGate)
			conn := &writeRecordingConn{stubConn: stubConn{
				local:  &net.TCPAddr{IP: net.ParseIP(tc.local), Port: 50000},
				remote: &net.TCPAddr{IP: net.ParseIP(tc.remote), Port: 443},
			}}
			opts := tlsOpts(1, 100)
			opts.SynAckTimeout = 0
			msg := fakeMsg()

			n, err := d.Desync(context.Background(), conn, msg, opts, baseConnOpts())
			require.NoError(t, err)

			if tc.wantFakes {
				assert.NotEmpty(t, w.packets)
			} else {
				assert.Empty(t, w.packets, "the writer is not called")
			}

			// The ClientHello is split either way.
			assert.Equal(t, len(msg.Raw()), n)
			assert.Greater(t, len(conn.writes), 1)
			assert.Equal(t, msg.Raw(), bytes.Join(conn.writes, nil))
		})
	}
}

func TestUDPDesync_FakeCapability(t *testing.T) {
	tcs := []struct {
		name      string
		local     string
		remote    string
		wantFakes int
	}{
		{"ipv4 server", "192.168.1.11", "203.0.113.1", 2},
		{"ipv6 server", "2001:db8::2", "2001:db8::1", 0},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			resetCannotFakeWarning(t)

			w := &udpWriter{}
			d := NewUDPDesyncer(zerolog.Nop(), w, stubHops{}, testGate)
			conn := udpConn{
				local:  &net.UDPAddr{IP: net.ParseIP(tc.local), Port: 50000},
				remote: &net.UDPAddr{IP: net.ParseIP(tc.remote), Port: 443},
			}

			_, err := d.Desync(
				context.Background(),
				conn,
				&config.UDPOptions{FakePreflight: 2, FakePacket: make([]byte, 8)},
				baseConnOpts(),
			)
			require.NoError(t, err)
			assert.Equal(t, tc.wantFakes, w.n)
		})
	}
}

// cannotFakeLevels returns the level of each log entry in log that says
// fake packets were skipped for a server they cannot be sent to.
func cannotFakeLevels(t *testing.T, log *bytes.Buffer) []string {
	t.Helper()

	var levels []string
	lines := bufio.NewScanner(bytes.NewReader(log.Bytes()))
	for lines.Scan() {
		var entry struct {
			Level   string `json:"level"`
			Message string `json:"message"`
		}
		require.NoError(t, json.Unmarshal(lines.Bytes(), &entry))
		if entry.Message == "skipping fake packets" {
			levels = append(levels, entry.Level)
		}
	}
	require.NoError(t, lines.Err())
	return levels
}

// The first skipped fake for a reason is a warning, whichever desyncer
// skips it; every later one for the same reason is logged at debug level.
func TestDesync_CannotFakeWarnsOncePerProcess(t *testing.T) {
	resetCannotFakeWarning(t)

	var log bytes.Buffer
	logger := zerolog.New(&log).Level(zerolog.DebugLevel)
	tlsD := NewTLSDesyncer(
		logger,
		&recordingWriter{},
		stubHops{},
		nil,
		testGate,
	)
	udpD := NewUDPDesyncer(logger, &udpWriter{}, stubHops{}, testGate)

	assert.Zero(t, desyncTLS(t, tlsD, "2001:db8::1"))
	assert.Zero(t, desyncUDP(t, udpD, "2001:db8::1"))
	assert.Zero(t, desyncTLS(t, tlsD, "2001:db8::3"))

	assert.Equal(t, []string{"warn", "debug", "debug"}, cannotFakeLevels(t, &log))
}

// A skipped fake logs its destination and reason, and a new reason warns
// again.
func TestDesync_CannotFakeLogsReasons(t *testing.T) {
	resetCannotFakeWarning(t)

	var log bytes.Buffer
	logger := zerolog.New(&log).Level(zerolog.DebugLevel)
	other := packet.NewStaticGate(nil, errors.New("no route"))
	udpA := NewUDPDesyncer(logger, &udpWriter{}, stubHops{}, testGate)
	udpB := NewUDPDesyncer(logger, &udpWriter{}, stubHops{}, other)

	assert.Zero(t, desyncUDP(t, udpA, "2001:db8::1"))
	assert.Zero(t, desyncUDP(t, udpB, "2001:db8::1"))
	assert.Zero(t, desyncUDP(t, udpA, "2001:db8::2"))

	var entries []map[string]any
	lines := bufio.NewScanner(&log)
	for lines.Scan() {
		var e map[string]any
		require.NoError(t, json.Unmarshal(lines.Bytes(), &e))
		entries = append(entries, e)
	}
	require.Len(t, entries, 3)
	assert.Equal(t, "warn", entries[0]["level"])
	assert.Equal(t, "2001:db8::1", entries[0]["dst"])
	assert.Equal(t, "IPv6 fakes are not supported yet", entries[0]["reason"])
	assert.Equal(t, "warn", entries[1]["level"])
	assert.Equal(t, "no route", entries[1]["reason"])
	assert.Equal(t, "debug", entries[2]["level"])
}
