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
)

// localLinkWarnings returns the dst of each warning in log that fake
// packets were skipped for a server on the local link.
func localLinkWarnings(t *testing.T, log *bytes.Buffer) []string {
	t.Helper()

	var dsts []string
	lines := bufio.NewScanner(bytes.NewReader(log.Bytes()))
	for lines.Scan() {
		var entry struct {
			Level   string `json:"level"`
			Message string `json:"message"`
			Dst     string `json:"dst"`
		}
		require.NoError(t, json.Unmarshal(lines.Bytes(), &entry))
		if entry.Level == "warn" &&
			entry.Message == "server is on the local link, skipping fake packets" {
			dsts = append(dsts, entry.Dst)
		}
	}
	require.NoError(t, lines.Err())
	return dsts
}

// hopStoreWith returns a store that learned hops for each server over p.
func hopStoreWith(p Proto, hops uint8, servers ...string) *HopStore {
	store := NewHopStore()
	for _, s := range servers {
		ip := net.ParseIP(s)
		store.Register(p, []net.IP{ip})
		store.Learn(p, ip, hops)
	}
	return store
}

// desyncTLS runs a TLS desync with one fake to server, and returns the
// number of fake packets sent.
func desyncTLS(t *testing.T, d *TLSDesyncer, server string) int {
	t.Helper()

	w := d.writer.(*recordingWriter)
	before := len(w.packets)
	opts := tlsOpts(1, 100)
	opts.SynAckTimeout = 0
	_, err := d.Desync(
		context.Background(),
		newStubConn(server),
		fakeMsg(),
		opts,
		baseConnOpts(),
	)
	require.NoError(t, err)
	return len(w.packets) - before
}

// desyncUDP runs a UDP desync with one fake to server, and returns the
// number of fake packets sent.
func desyncUDP(t *testing.T, d *UDPDesyncer, server string) int {
	t.Helper()

	w := d.writer.(*udpWriter)
	before := w.n
	conn := udpConn{
		local:  &net.UDPAddr{IP: net.ParseIP("192.168.1.11"), Port: 50000},
		remote: &net.UDPAddr{IP: net.ParseIP(server), Port: 443},
	}
	_, err := d.Desync(
		context.Background(),
		conn,
		&config.UDPOptions{FakePreflight: 1, FakePacket: make([]byte, 8)},
		baseConnOpts(),
	)
	require.NoError(t, err)
	return w.n - before
}

func TestDesync_WarnsOncePerLocalLinkDestination(t *testing.T) {
	const serverA, serverB = "192.168.1.20", "192.168.1.21"

	t.Run("tls", func(t *testing.T) {
		var log bytes.Buffer
		d := NewTLSDesyncer(
			zerolog.New(&log),
			&recordingWriter{},
			hopStoreWith(ProtoTCP, 0, serverA, serverB),
			nil,
			nil,
		)

		for _, server := range []string{serverA, serverA, serverB, serverA, serverB} {
			assert.Zero(t, desyncTLS(t, d, server), "fakes are skipped")
		}
		assert.Equal(t, []string{serverA, serverB}, localLinkWarnings(t, &log))
	})

	t.Run("udp", func(t *testing.T) {
		var log bytes.Buffer
		d := NewUDPDesyncer(
			zerolog.New(&log),
			&udpWriter{},
			hopStoreWith(ProtoUDP, 0, serverA, serverB),
			nil,
		)

		for _, server := range []string{serverA, serverA, serverB, serverA, serverB} {
			assert.Zero(t, desyncUDP(t, d, server), "fakes are skipped")
		}
		assert.Equal(t, []string{serverA, serverB}, localLinkWarnings(t, &log))
	})
}

func TestDesync_NoLocalLinkWarningWhenFakesAreSent(t *testing.T) {
	const server = "203.0.113.1"

	for _, tc := range []struct {
		name  string
		store func(p Proto) *HopStore
	}{
		{"learned one hop away", func(p Proto) *HopStore {
			return hopStoreWith(p, 1, server)
		}},
		{"registered, not learned", func(p Proto) *HopStore {
			store := NewHopStore()
			store.Register(p, []net.IP{net.ParseIP(server)})
			return store
		}},
		{"not in the store", func(Proto) *HopStore {
			return NewHopStore()
		}},
	} {
		t.Run(tc.name+"/tls", func(t *testing.T) {
			var log bytes.Buffer
			d := NewTLSDesyncer(
				zerolog.New(&log),
				&recordingWriter{},
				tc.store(ProtoTCP),
				nil,
				nil,
			)
			assert.NotZero(t, desyncTLS(t, d, server))
			assert.Empty(t, localLinkWarnings(t, &log))
		})

		t.Run(tc.name+"/udp", func(t *testing.T) {
			var log bytes.Buffer
			d := NewUDPDesyncer(
				zerolog.New(&log),
				&udpWriter{},
				tc.store(ProtoUDP),
				nil,
			)
			assert.NotZero(t, desyncUDP(t, d, server))
			assert.Empty(t, localLinkWarnings(t, &log))
		})
	}
}
