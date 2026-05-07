package dns

import (
	"context"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
)

type udpResolver struct {
	logger zerolog.Logger
	client *dns.Client
}

func newUDPResolver(logger zerolog.Logger, cfg *config.RuntimeConfig) *udpResolver {
	return &udpResolver{
		client: &dns.Client{
			Timeout: cfg.Conn.DNSTimeout,
		},
		logger: logger,
	}
}

func (ur *udpResolver) resolve(
	ctx context.Context,
	server string,
	domain string,
	qTypes []uint16,
) ([]netip.Addr, uint32, error) {
	resCh := lookupAllTypes(ctx, domain, server, qTypes, ur.exchange)
	return processMessages(ctx, resCh)
}

func (ur *udpResolver) exchange(
	ctx context.Context,
	msg *dns.Msg,
	upstream string,
) (*dns.Msg, error) {
	logger := logging.WithLocalScope(ctx, ur.logger, "udp_exchange")

	resp, _, err := ur.client.ExchangeContext(ctx, msg, upstream)
	if err != nil {
		logger.Trace().Err(err).Msgf("client returned error")
	}

	return resp, err
}
