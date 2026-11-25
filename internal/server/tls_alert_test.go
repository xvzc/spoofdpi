package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// consoleLogger returns a logger that renders as the app's console logger
// does, at debug level, and the buffer it writes to.
func consoleLogger(t *testing.T) (zerolog.Logger, *bytes.Buffer) {
	t.Helper()

	prevLogger, prevLevel := log.Logger, zerolog.GlobalLevel()
	t.Cleanup(func() {
		log.Logger = prevLogger
		zerolog.SetGlobalLevel(prevLevel)
	})

	out := &bytes.Buffer{}
	ctx := logging.ContextWithTraceID(context.Background(), logging.NewTraceID())
	logging.SetGlobalLogger(ctx, zerolog.DebugLevel, out)

	return logging.WithLocalScope(ctx, log.Logger, "https"), out
}

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// logLines returns the lines in out, without the console colors.
func logLines(out *bytes.Buffer) []string {
	text := strings.TrimSpace(ansiEscape.ReplaceAllString(out.String(), ""))
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// alertRecord returns a plaintext alert record of description.
func alertRecord(description byte) []byte {
	return []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, description}
}

// watchedRead relays what a server at dstIP sends as replies, one write
// each, through RelayBidirectional with w's inspector, and returns what
// the client reads.
func watchedRead(
	t *testing.T,
	w *TLSAlertWatcher,
	logger zerolog.Logger,
	sni, host string,
	dstIP net.IP,
	replies ...[]byte,
) []byte {
	t.Helper()

	// The relay logs its summary at trace level.
	prevLevel := zerolog.GlobalLevel()
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	t.Cleanup(func() { zerolog.SetGlobalLevel(prevLevel) })

	upstream, rEnd := net.Pipe()
	lEnd, client := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() {
		for _, reply := range replies {
			_, _ = upstream.Write(reply)
		}
		_ = upstream.Close()
	}()

	// The watcher keys on the address the conn reports, so a conn that
	// reports dstIP stands in for the server.
	rConn := &remoteAddrConn{Conn: rEnd, remote: &net.TCPAddr{IP: dstIP, Port: 443}}
	var logs bytes.Buffer
	relayLogger := zerolog.New(&logs).Level(zerolog.TraceLevel)
	done := make(chan error, 1)
	go func() {
		done <- netutil.RelayBidirectional(
			context.Background(), relayLogger, lEnd, rConn, netutil.RelayOptions{
				OnFirstReply: w.Inspector(logger, rConn, sni, host),
			},
		)
	}()

	got, err := io.ReadAll(client)
	require.NoError(t, err)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay outlived the end of the replies")
	}
	var closed struct {
		In   int64 `json:"in"`
		Errs int   `json:"errs"`
	}
	require.NoError(t, json.Unmarshal(logs.Bytes(), &closed))
	assert.Equal(t, int64(len(got)), closed.In)
	// Only the client-to-remote direction fails: it reads lEnd, a pipe
	// that the reply direction closed, which a pipe reports as
	// io.ErrClosedPipe.
	assert.Equal(t, 1, closed.Errs)

	return got
}

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

func TestTLSAlertWatcher_Inspector(t *testing.T) {
	const hint = "; if fake packets are on, they may have reached the server: " +
		"try a lower connection.hop-count-offset (default -1)"
	const msg = "the server answered the Client Hello with a TLS alert"
	ip := net.ParseIP("172.66.147.243")

	t.Run(
		"a rejecting alert warns with the hint, then logs at debug",
		func(t *testing.T) {
			logger, out := consoleLogger(t)
			w := NewTLSAlertWatcher()

			got := watchedRead(
				t,
				w,
				logger,
				"example.com",
				"example.com",
				ip,
				alertRecord(50),
			)
			assert.Equal(t, alertRecord(50), got)

			lines := logLines(out)
			require.Len(t, lines, 1)
			assert.Contains(t, lines[0], "WRN")
			assert.Contains(t, lines[0], "https; "+msg+hint+
				", or check with 'spoofdpi probe example.com'; "+
				"alert=decode_error dst=172.66.147.243:443 sni=example.com")

			out.Reset()
			watchedRead(t, w, logger, "example.com", "example.com", ip, alertRecord(50))
			lines = logLines(out)
			require.Len(t, lines, 1)
			assert.Contains(t, lines[0], "DBG")
			assert.Contains(t, lines[0], "https; "+msg+"; "+
				"alert=decode_error dst=172.66.147.243:443 sni=example.com")
			assert.NotContains(t, lines[0], "fake packets")
		},
	)

	t.Run("another alert warns without the hint", func(t *testing.T) {
		logger, out := consoleLogger(t)
		w := NewTLSAlertWatcher()

		watchedRead(t, w, logger, "example.com", "", ip, alertRecord(118))

		line := strings.Join(logLines(out), "\n")
		assert.Contains(t, line, "WRN")
		assert.Contains(t, line, "https; "+msg+"; "+
			"alert=118 dst=172.66.147.243:443 sni=example.com")
		assert.NotContains(t, line, "fake packets")
	})

	t.Run("the warning is once per destination ip", func(t *testing.T) {
		logger, out := consoleLogger(t)
		w := NewTLSAlertWatcher()

		watchedRead(t, w, logger, "a.test", "", ip, alertRecord(40))
		watchedRead(t, w, logger, "b.test", "", ip, alertRecord(50))
		watchedRead(t, w, logger, "c.test", "", net.ParseIP("2001:db8::1"), alertRecord(50))

		lines := logLines(out)
		require.Len(t, lines, 3)
		assert.Contains(t, lines[0], "WRN")
		assert.Contains(t, lines[1], "DBG", "the first warning took the ip")
		assert.Contains(t, lines[2], "WRN")
		assert.Contains(t, lines[2], "dst=[2001:db8::1]:443")
	})

	t.Run("without an sni the host names the site", func(t *testing.T) {
		logger, out := consoleLogger(t)
		watchedRead(t, NewTLSAlertWatcher(), logger, "", "host.test", ip, alertRecord(47))

		assert.Contains(
			t,
			strings.Join(logLines(out), "\n"),
			"or check with 'spoofdpi probe host.test'; "+
				"alert=illegal_parameter dst=172.66.147.243:443 host=host.test",
		)
	})

	t.Run("without a name there is nothing to probe", func(t *testing.T) {
		for _, host := range []string{"", "203.0.113.7"} {
			logger, out := consoleLogger(t)
			watchedRead(t, NewTLSAlertWatcher(), logger, "", host, ip, alertRecord(10))

			line := strings.Join(logLines(out), "\n")
			assert.Contains(t, line, "lower connection.hop-count-offset (default -1); "+
				"alert=unexpected_message dst=172.66.147.243:443")
			assert.NotContains(t, line, "probe")
			assert.NotContains(t, line, "host=")
		}
	})

	t.Run("replies other than an alert are not logged", func(t *testing.T) {
		logger, out := consoleLogger(t)
		w := NewTLSAlertWatcher()

		hello := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00}
		assert.Equal(t, hello, watchedRead(t, w, logger, "x.test", "", ip, hello))
		assert.Empty(t, logLines(out))
	})

	t.Run("only the first read is checked", func(t *testing.T) {
		logger, out := consoleLogger(t)
		short := []byte{0x15, 0x03, 0x03}
		rest := append(alertRecord(50)[3:], alertRecord(50)...)

		got := watchedRead(t, NewTLSAlertWatcher(), logger, "x.test", "", ip, short, rest)
		assert.Equal(t, append(short, rest...), got)
		assert.Empty(t, logLines(out))
	})

	t.Run("later chunks follow the alert unchanged", func(t *testing.T) {
		logger, out := consoleLogger(t)
		later := []byte("later bytes")

		got := watchedRead(
			t,
			NewTLSAlertWatcher(),
			logger,
			"x.test",
			"",
			ip,
			alertRecord(50),
			later,
		)
		assert.Equal(t, append(alertRecord(50), later...), got)
		assert.Len(t, logLines(out), 1)
	})

	t.Run("a conn without a tcp address has no inspector", func(t *testing.T) {
		a, b := net.Pipe()
		defer func() { _ = a.Close(); _ = b.Close() }()
		assert.Nil(t, NewTLSAlertWatcher().Inspector(zerolog.Nop(), a, "", ""))
	})
}

func TestSNI(t *testing.T) {
	msg := proto.NewFakeTLSMessage([]byte(config.FakeClientHello))
	assert.NotEmpty(t, SNI(msg))
	assert.Empty(
		t,
		SNI(proto.NewFakeTLSMessage([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01})),
	)
}
