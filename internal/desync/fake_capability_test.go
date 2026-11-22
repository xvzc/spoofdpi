package desync

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/packet"
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
	cannotFakeWarned.Store(false)
	t.Cleanup(func() { cannotFakeWarned.Store(false) })
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
			d := NewTLSDesyncer(zerolog.Nop(), w, stubHops{}, nil, &packet.TCPStack{})
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
			d := NewUDPDesyncer(zerolog.Nop(), w, stubHops{}, &packet.UDPStack{})
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
		switch entry.Message {
		case "fake packets are not sent to IPv6 servers yet, skipping them",
			"fake packets cannot be sent to this server, skipping them":
			levels = append(levels, entry.Level)
		}
	}
	require.NoError(t, lines.Err())
	return levels
}

// The first skipped fake in the process is a warning, whichever desyncer
// skips it; every later one is logged at debug level.
func TestDesync_CannotFakeWarnsOncePerProcess(t *testing.T) {
	resetCannotFakeWarning(t)

	var log bytes.Buffer
	logger := zerolog.New(&log).Level(zerolog.DebugLevel)
	tlsD := NewTLSDesyncer(
		logger,
		&recordingWriter{},
		stubHops{},
		nil,
		&packet.TCPStack{},
	)
	udpD := NewUDPDesyncer(logger, &udpWriter{}, stubHops{}, &packet.UDPStack{})

	assert.Zero(t, desyncTLS(t, tlsD, "2001:db8::1"))
	assert.Zero(t, desyncUDP(t, udpD, "2001:db8::1"))
	assert.Zero(t, desyncTLS(t, tlsD, "2001:db8::3"))

	assert.Equal(t, []string{"warn", "debug", "debug"}, cannotFakeLevels(t, &log))
}
