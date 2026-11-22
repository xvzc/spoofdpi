package socks5

import (
	"context"
	"encoding/binary"
	"net"
	"testing"

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
