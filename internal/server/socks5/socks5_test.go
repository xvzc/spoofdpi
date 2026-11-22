package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
)

func TestSOCKS5Proxy_HandleConnection_UDPAssociateWithName(t *testing.T) {
	// Neither name resolves: one is too short to be looked up, the other is
	// reserved. UDP ASSOCIATE doesn't use the request's address, so either
	// sets up the association.
	for _, name := range []string{"x", "unresolvable.invalid"} {
		t.Run(name, func(t *testing.T) {
			pool := netutil.NewConnRegistry[netutil.NATKey](16)
			p := &SOCKS5Proxy{
				logger: zerolog.Nop(),
				udpAssociateHandler: newRelayingUdpAssociateHandler(
					t,
					pool,
					&config.RuntimeConfig{},
				),
			}

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer func() { _ = ln.Close() }()

			client, err := net.Dial("tcp", ln.Addr().String())
			require.NoError(t, err)
			srvConn, err := ln.Accept()
			require.NoError(t, err)

			done := make(chan struct{})
			go func() {
				p.handleConnection(context.Background(), srvConn)
				close(done)
			}()
			t.Cleanup(func() {
				_ = client.Close()
				<-done
			})

			// Negotiation: VER NMETHODS METHODS
			_, err = client.Write([]byte{proto.SOCKSVersion, 1, proto.SOCKS5AuthNone})
			require.NoError(t, err)
			method := make([]byte, 2)
			_, err = client.Read(method)
			require.NoError(t, err)

			// VER CMD RSV ATYP(FQDN) LEN NAME PORT
			req := []byte{
				proto.SOCKSVersion, proto.SOCKS5CmdUDPAssociate, 0,
				proto.SOCKS5AddrTypeFQDN, byte(len(name)),
			}
			req = append(req, name...)
			req = binary.BigEndian.AppendUint16(req, 53)
			_, err = client.Write(req)
			require.NoError(t, err)

			assert.Equal(t, byte(proto.SOCKS5RCodeSuccess), readReply(t, client))
		})
	}
}

// socks5Request performs the negotiation and sends a request for cmd with the
// address 0.0.0.0:0, then returns the address of the server's reply.
func socks5Request(t *testing.T, client net.Conn, cmd byte) *net.TCPAddr {
	t.Helper()

	_, err := client.Write([]byte{proto.SOCKSVersion, 1, proto.SOCKS5AuthNone})
	require.NoError(t, err)
	method := make([]byte, 2)
	_, err = io.ReadFull(client, method)
	require.NoError(t, err)

	// VER CMD RSV ATYP(IPv4) ADDR(4) PORT(2)
	_, err = client.Write([]byte{
		proto.SOCKSVersion, cmd, 0, proto.SOCKS5AddrTypeIPv4, 0, 0, 0, 0, 0, 0,
	})
	require.NoError(t, err)

	require.NoError(t, client.SetReadDeadline(time.Now().Add(5*time.Second)))
	reply := make([]byte, 10)
	_, err = io.ReadFull(client, reply)
	require.NoError(t, err)
	require.NoError(t, client.SetReadDeadline(time.Time{}))
	require.Equal(t, byte(proto.SOCKS5RCodeSuccess), reply[1])

	return &net.TCPAddr{
		IP:   net.IP(reply[4:8]),
		Port: int(binary.BigEndian.Uint16(reply[8:10])),
	}
}

func TestSOCKS5Proxy_ServeStopsWithOpenConnection(t *testing.T) {
	tcs := []struct {
		name string
		// open brings the client's connection to the state where its
		// handler waits, and returns a func that reports whether the
		// handler's own socket is released.
		open func(t *testing.T, client net.Conn) func() error
	}{
		{
			name: "idle in negotiation",
			open: func(t *testing.T, client net.Conn) func() error {
				return func() error { return nil }
			},
		},
		{
			name: "idle after negotiation",
			open: func(t *testing.T, client net.Conn) func() error {
				_, err := client.Write(
					[]byte{proto.SOCKSVersion, 1, proto.SOCKS5AuthNone},
				)
				require.NoError(t, err)
				_, err = io.ReadFull(client, make([]byte, 2))
				require.NoError(t, err)
				return func() error { return nil }
			},
		},
		{
			name: "bind waiting for the incoming connection",
			open: func(t *testing.T, client net.Conn) func() error {
				addr := socks5Request(t, client, proto.SOCKS5CmdBind)
				return func() error {
					ln, err := net.ListenTCP("tcp", addr)
					if err == nil {
						_ = ln.Close()
					}
					return err
				}
			},
		},
		{
			name: "udp association",
			open: func(t *testing.T, client net.Conn) func() error {
				addr := socks5Request(t, client, proto.SOCKS5CmdUDPAssociate)
				return func() error {
					conn, err := net.ListenUDP(
						"udp",
						&net.UDPAddr{IP: addr.IP, Port: addr.Port},
					)
					if err == nil {
						_ = conn.Close()
					}
					return err
				}
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := zerolog.New(zerolog.SyncWriter(&logs))
			p := &SOCKS5Proxy{
				logger:      logger,
				bindHandler: NewBindHandler(logger),
				udpAssociateHandler: newRelayingUdpAssociateHandler(
					t,
					netutil.NewConnRegistry[netutil.NATKey](16),
					&config.RuntimeConfig{},
				),
				listenAddr: net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			require.NoError(t, p.Listen(ctx))

			served := make(chan error, 1)
			go func() { served <- p.Serve(ctx) }()

			client, err := net.Dial("tcp", p.listener.Addr().String())
			require.NoError(t, err)
			defer func() { _ = client.Close() }()
			released := tc.open(t, client)
			require.Eventually(t, func() bool { return p.conns.Active() == 1 },
				time.Second, 5*time.Millisecond)

			start := time.Now()
			cancel()

			select {
			case err := <-served:
				assert.NoError(t, err)
				assert.Less(t, time.Since(start), 2*time.Second)
			case <-time.After(5 * time.Second):
				t.Fatal("Serve did not return after ctx was cancelled")
			}

			require.NoError(t, client.SetReadDeadline(time.Now().Add(time.Second)))
			_, err = client.Read(make([]byte, 1))
			require.Error(t, err)
			var netErr net.Error
			if errors.As(err, &netErr) {
				assert.False(t, netErr.Timeout(), "the client must see the conn closed")
			}

			assert.NoError(t, released(), "the handler's own socket must be closed")
			// Serve has returned, so every handler has finished logging.
			assert.NotContains(t, logs.String(), `"level":"warn"`,
				"closing a conn at shutdown logs no warning")
		})
	}
}

func TestSOCKS5Proxy_ListenAddressInUse(t *testing.T) {
	taken, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer func() { _ = taken.Close() }()

	p := &SOCKS5Proxy{
		logger:     zerolog.Nop(),
		listenAddr: *taken.Addr().(*net.TCPAddr),
	}

	assert.Error(t, p.Listen(context.Background()))
}
