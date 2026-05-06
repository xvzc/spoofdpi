package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
)

var _ Resolver = (*muxResolver)(nil)

type muxResolver struct {
	logger zerolog.Logger
	https  *httpsResolver
	udp    *udpResolver
	system *systemResolver
	cache  cache.Cache[string]
	rt     *config.RuntimeConfig
}

func NewMuxResolver(
	logger zerolog.Logger,
	c cache.Cache[string],
	rt *config.RuntimeConfig,
) Resolver {
	https := newHTTPSResolver(logger, rt)
	udp := newUDPResolver(logger, rt)
	system := newSystemResolver(logger, rt)

	logger.Info().Msg("dns info")
	logger.Info().Msgf(" query type '%s'", rt.DNS.QType.String())
	logger.Info().Msgf(" resolvers")
	for _, info := range []struct{ name, dst string }{
		{"udp", rt.DNS.Addr.String()},
		{"https", rt.DNS.HTTPSURL},
		{"system", "builtin"},
		{"cache", "dynamic"},
	} {
		logger.Info().Str("dst", info.dst).Msgf("  %s", info.name)
	}

	return &muxResolver{
		logger: logger,
		https:  https,
		udp:    udp,
		system: system,
		cache:  c,
		rt:     rt,
	}
}

func (mr *muxResolver) Resolve(
	ctx context.Context,
	domain string,
	rule *config.Rule,
) (*RecordSet, error) {
	rt := mr.rt
	if rule != nil {
		rt = &rule.Config
	}

	logger := logging.WithLocalScope(ctx, mr.logger, "mux")

	if ip := net.ParseIP(domain); ip != nil {
		return &RecordSet{Addrs: []net.IP{ip}, TTL: 0}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	resolver := mr.pick(rt.DNS.Mode)
	if resolver == nil {
		return nil, fmt.Errorf("no resolver available for mode %s", rt.DNS.Mode)
	}

	useCache := rt.DNS.Cache && rt.DNS.Mode != config.DNSModeSystem
	if useCache {
		if item, ok := mr.cache.Get(domain); ok {
			logger.Debug().Str("domain", domain).Msg("cache hit")
			return item.(*RecordSet).Clone(), nil
		}
		logger.Debug().Str("domain", domain).Msg("cache miss")
	}

	t1 := time.Now()
	rSet, err := resolver.Resolve(ctx, domain, rule)
	if err != nil {
		return nil, err
	}

	logger.Debug().
		Str("domain", domain).
		Int("len", len(rSet.Addrs)).
		Str("took", fmt.Sprintf("%.3fms", float64(time.Since(t1).Microseconds())/1000.0)).
		Msg("dns lookup ok")

	if useCache {
		_ = mr.cache.Set(domain, rSet, cache.Options().WithTTL(time.Duration(rSet.TTL)*time.Second))
	}

	return rSet, nil
}

func (mr *muxResolver) pick(mode config.DNSModeType) Resolver {
	switch mode {
	case config.DNSModeHTTPS:
		return mr.https
	case config.DNSModeUDP:
		return mr.udp
	default:
		return mr.system
	}
}
