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
	"github.com/xvzc/spoofdpi/internal/rule"
)

type UDPHandler struct {
	logger   zerolog.Logger
	desyncer *desync.UDPDesyncer
	ruleSet  *rule.RuleSet
	cfg      *config.RuntimeConfig
}

func NewUDPHandler(
	logger zerolog.Logger,
	desyncer *desync.UDPDesyncer,
	ruleSet *rule.RuleSet,
	cfg *config.RuntimeConfig,
) *UDPHandler {
	return &UDPHandler{
		logger:   logger,
		desyncer: desyncer,
		ruleSet:  ruleSet,
		cfg:      cfg,
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
	cfg := h.cfg
	if h.ruleSet != nil {
		if matched := h.ruleSet.Search(
			[]rule.Query{{Type: rule.MatchTypeAddr, Value: dst.Addrs[0].String()}},
		); matched != nil {
			logger.Trace().RawJSON("summary", matched.JSON()).Msg("match")
			cfg = &matched.Config
		}
	}

	// Register destination for TTL learning when fakes will be sent.
	h.desyncer.PrepareHopTrack(dst.Addrs, &cfg.UDP)

	// Dial remote connection
	rawConn, err := netutil.DialFastest(ctx, dst, "udp", 0, sysNet.BindDialer)
	if err != nil {
		logger.Error().Msgf("error dialing to %s", dst.String())
		return
	}

	timeout := cfg.Conn.UDPIdleTimeout

	rConnWrapped := netutil.NewIdleTimeoutConn(rawConn, timeout)
	lConnWrapped := netutil.NewIdleTimeoutConn(lConn, timeout)

	if !cfg.UDP.Skip {
		_, _ = h.desyncer.Desync(ctx, lConnWrapped, rConnWrapped, &cfg.UDP)
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
