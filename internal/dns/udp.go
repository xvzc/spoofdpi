package dns

import (
	"context"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
)

var _ Resolver = (*udpResolver)(nil)

type udpResolver struct {
	logger zerolog.Logger
	client *dns.Client
	rt     *config.RuntimeConfig
}

func newUDPResolver(logger zerolog.Logger, rt *config.RuntimeConfig) *udpResolver {
	return &udpResolver{
		client: &dns.Client{
			Timeout: rt.Conn.DNSTimeout,
		},
		rt:     rt,
		logger: logger,
	}
}

func (ur *udpResolver) Resolve(
	ctx context.Context,
	domain string,
	rule *config.Rule,
) (*RecordSet, error) {
	rt := ur.rt
	if rule != nil {
		rt = &rule.Config
	}

	resCh := lookupAllTypes(
		ctx,
		domain,
		rt.DNS.Addr.String(),
		parseQueryTypes(rt.DNS.QType),
		ur.exchange,
	)

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
