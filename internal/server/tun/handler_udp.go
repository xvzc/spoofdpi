package tun

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
)

type UDPHandler struct {
	logger   zerolog.Logger
	rt       *config.RuntimeConfig
	desyncer *desync.UDPDesyncer
	sniffer  packet.Sniffer
}

func NewUDPHandler(
	logger zerolog.Logger,
	desyncer *desync.UDPDesyncer,
	sniffer packet.Sniffer,
	rt *config.RuntimeConfig,
) *UDPHandler {
	return &UDPHandler{
		logger:   logger,
		desyncer: desyncer,
		sniffer:  sniffer,
		rt:       rt,
	}
}

func (h *UDPHandler) Handle(
	ctx context.Context,
	sysNet TUNSystemNetwork,
	lConn net.Conn,
	rule *config.Rule,
) {
	logger := logging.WithLocalScope(ctx, h.logger, "udp")

	defer netutil.CloseConns(lConn)

	host, portStr, err := net.SplitHostPort(lConn.LocalAddr().String())
	if err != nil {
		return
	}
	port, _ := strconv.Atoi(portStr)

	dst := &netutil.Destination{
		Domain: host,
		Port:   port,
	}
	if ip := net.ParseIP(host); ip != nil {
		dst.Addrs = []net.IP{ip}
	}

	// Apply rule if matched in server.go
	rt := h.rt
	if rule != nil {
		logger.Trace().RawJSON("summary", rule.JSON()).Msg("match")
		rt = &rule.Config
	}

	// Register destination for TTL learning when fakes will be sent.
	if h.sniffer != nil && rt.UDP.FakeCount > 0 {
		h.sniffer.RegisterUntracked(dst.Addrs)
	}

	// Dial remote connection
	rawConn, err := netutil.DialFastest(ctx, dst, "udp", 0, sysNet.BindDialer)
	if err != nil {
		logger.Error().Msgf("error dialing to %s", dst.String())
		return
	}

	timeout := rt.Conn.UDPIdleTimeout

	// Wrap rConn with IdleTimeoutConn
	rConnWrapped := netutil.NewIdleTimeoutConn(rawConn, timeout)

	// Wrap lConn with IdleTimeoutConn as well
	lConnWrapped := netutil.NewIdleTimeoutConn(lConn, timeout)

	// Desync
	_, _ = h.desyncer.Desync(ctx, lConnWrapped, rConnWrapped, &rt.UDP)

	logger.Debug().
		Msgf("new remote conn (%s -> %s)", lConn.RemoteAddr(), rConnWrapped.RemoteAddr())

	resCh := make(chan netutil.TransferResult, 2)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	startedAt := time.Now()
	go netutil.TunnelConns(ctx, resCh, lConnWrapped, rConnWrapped, netutil.TunnelDirOut)
	go netutil.TunnelConns(ctx, resCh, rConnWrapped, lConnWrapped, netutil.TunnelDirIn)

	err = netutil.WaitForTunnelCompletion(
		ctx,
		logger,
		resCh,
		startedAt,
		netutil.DescribeRoute(lConnWrapped, rConnWrapped),
		nil,
	)
	if err != nil {
		logger.Error().Err(err).Msg("error handling request")
	}
}
