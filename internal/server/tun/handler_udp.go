package tun

import (
	"context"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
	"github.com/xvzc/spoofdpi/internal/rule"
)

type UDPHandler struct {
	logger   zerolog.Logger
	desyncer *desync.UDPDesyncer
	sniffer  packet.Sniffer
	ruleSet  *rule.RuleSet
	rt       *config.RuntimeConfig
}

func NewUDPHandler(
	logger zerolog.Logger,
	desyncer *desync.UDPDesyncer,
	sniffer packet.Sniffer,
	ruleSet *rule.RuleSet,
	rt *config.RuntimeConfig,
) *UDPHandler {
	return &UDPHandler{
		logger:   logger,
		desyncer: desyncer,
		sniffer:  sniffer,
		ruleSet:  ruleSet,
		rt:       rt,
	}
}

func (h *UDPHandler) Handle(
	ctx context.Context,
	lConn net.Conn,
	dst *netutil.Destination,
	sysNet TUNSystemNetwork,
) {
	defer netutil.CloseConns(lConn)

	logger := logging.WithLocalScope(ctx, h.logger, "udp")

	// Addr-based rule matching
	rt := h.rt
	if h.ruleSet != nil {
		if matched := h.ruleSet.Search(
			[]rule.Query{{Type: rule.MatchTypeAddr, Value: dst.Addrs[0].String()}},
		); matched != nil {
			logger.Trace().RawJSON("summary", matched.JSON()).Msg("match")
			rt = &matched.Config
		}
	}

	// Register destination for TTL learning when fakes will be sent.
	if h.sniffer != nil && !rt.UDP.Skip && rt.UDP.FakeCount > 0 {
		h.sniffer.RegisterUntracked(dst.Addrs)
	}

	// Dial remote connection
	rawConn, err := netutil.DialFastest(ctx, dst, "udp", 0, sysNet.BindDialer)
	if err != nil {
		logger.Error().Msgf("error dialing to %s", dst.String())
		return
	}

	timeout := rt.Conn.UDPIdleTimeout

	rConnWrapped := netutil.NewIdleTimeoutConn(rawConn, timeout)
	lConnWrapped := netutil.NewIdleTimeoutConn(lConn, timeout)

	if !rt.UDP.Skip {
		_, _ = h.desyncer.Desync(ctx, lConnWrapped, rConnWrapped, &rt.UDP)
	}

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
