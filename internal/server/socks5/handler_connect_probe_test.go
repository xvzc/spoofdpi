package socks5

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/proto"
	"github.com/xvzc/spoofdpi/internal/rule"
	"github.com/xvzc/spoofdpi/internal/server"
)

// A CONNECT whose FQDN does not resolve gets a host-unreachable reply,
// instead of the connection being closed without a reply.
func TestConnectHandler_Handle_LookupErrorReplies(t *testing.T) {
	errLookup := errors.New("lookup failed")
	h := NewConnectHandler(
		zerolog.Nop(),
		desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil),
		server.NewTLSAlertWatcher(),
		&stubResolver{errs: map[string]error{"fail.test": errLookup}},
		rule.NewRuleSet(),
		net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1},
		&config.RuntimeConfig{},
	)

	client, done := runConnect(t, h, &proto.SOCKS5Request{
		Cmd:  proto.SOCKS5CmdConnect,
		ATYP: proto.SOCKS5AddrTypeFQDN,
		FQDN: "fail.test",
		Port: 443,
	})
	require.ErrorIs(t, <-done, errLookup)

	require.NoError(t, client.SetReadDeadline(time.Now().Add(2*time.Second)))
	reply := make([]byte, 10)
	_, err := io.ReadFull(client, reply)
	require.NoError(t, err, "the client gets a reply for the failed lookup")
	assert.Equal(t, byte(proto.SOCKSVersion), reply[0])
	assert.Equal(t, byte(proto.SOCKS5RCodeHostUnreachable), reply[1])
	assert.Equal(t, byte(0), reply[2], "RSV")
	assert.Equal(t, byte(proto.SOCKS5AddrTypeIPv4), reply[3], "ATYP")
	assert.Equal(t, make([]byte, 6), reply[4:10], "BND.ADDR and BND.PORT")
}
