package dns

import (
	"context"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/logging"
)

type udpResolver struct {
	logger zerolog.Logger
}

func newUDPResolver(logger zerolog.Logger) *udpResolver {
	return &udpResolver{
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

	// dns.Client applies its own default timeouts when Timeout is 0, which
	// would cut a longer lookup deadline short, so it is set from ctx.
	client := &dns.Client{}
	if deadline, ok := ctx.Deadline(); ok {
		client.Timeout = time.Until(deadline)
	}

	resp, _, err := client.ExchangeContext(ctx, msg, upstream)
	if err != nil {
		logger.Trace().Err(err).Msgf("client returned error")
	}

	return resp, err
}
