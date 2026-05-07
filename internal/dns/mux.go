package dns

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
)

// internalResolver is the interface implemented by the three DNS backends.
type internalResolver interface {
	resolve(
		ctx context.Context,
		server, domain string,
		qTypes []uint16,
	) ([]netip.Addr, uint32, error)
}

// Client is the top-level DNS resolver. It holds the three backends, a shared
// cache, and the runtime config. Callers hold *Client directly — it does not
// implement an interface.
type Client struct {
	logger zerolog.Logger
	https  *httpsResolver
	udp    *udpResolver
	system *systemResolver
	cache  cache.Cache[string, []netip.Addr]
	cfg    *config.RuntimeConfig
}

func NewClient(
	logger zerolog.Logger,
	c cache.Cache[string, []netip.Addr],
	cfg *config.RuntimeConfig,
) *Client {
	https := newHTTPSResolver(logger, cfg)
	udp := newUDPResolver(logger, cfg)
	system := newSystemResolver(logger, cfg)

	logger.Info().Msg("dns info")
	logger.Info().Msgf(" query type '%s'", cfg.DNS.QType.String())
	logger.Info().Msgf(" resolvers")
	for _, info := range []struct{ name, dst string }{
		{"udp", cfg.DNS.Addr.String()},
		{"https", cfg.DNS.HTTPSURL},
		{"system", "builtin"},
		{"cache", "dynamic"},
	} {
		logger.Info().Str("dst", info.dst).Msgf("  %s", info.name)
	}

	return &Client{
		logger: logger,
		https:  https,
		udp:    udp,
		system: system,
		cache:  c,
		cfg:    cfg,
	}
}

func (c *Client) Resolve(
	ctx context.Context,
	rule *config.Rule,
	domain string,
) ([]netip.Addr, error) {
	cfg := c.cfg
	if rule != nil {
		cfg = &rule.Config
	}

	logger := logging.WithLocalScope(ctx, c.logger, "mux")

	if ip, err := netip.ParseAddr(domain); err == nil {
		return []netip.Addr{ip}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	resolver := c.pick(cfg.DNS.Mode)
	qTypes := parseQueryTypes(cfg.DNS.QType)

	useCache := cfg.DNS.Cache && cfg.DNS.Mode != config.DNSModeSystem
	if useCache {
		if addrs, ok := c.cache.Get(domain); ok {
			logger.Debug().Str("domain", domain).Msg("cache hit")
			return addrs, nil
		}
		logger.Debug().Str("domain", domain).Msg("cache miss")
	}

	t1 := time.Now()
	addrs, ttl, err := resolver.resolve(ctx, c.serverFor(cfg), domain, qTypes)
	if err != nil {
		return nil, err
	}

	logger.Debug().
		Str("domain", domain).
		Int("len", len(addrs)).
		Str("took", fmt.Sprintf("%.3fms", float64(time.Since(t1).Microseconds())/1000.0)).
		Msg("dns lookup ok")

	if useCache {
		_ = c.cache.Set(
			domain,
			addrs,
			cache.Options().WithTTL(time.Duration(ttl)*time.Second),
		)
	}

	return addrs, nil
}

func (c *Client) pick(mode config.DNSModeType) internalResolver {
	switch mode {
	case config.DNSModeHTTPS:
		return c.https
	case config.DNSModeUDP:
		return c.udp
	default:
		return c.system
	}
}

func (c *Client) serverFor(cfg *config.RuntimeConfig) string {
	switch cfg.DNS.Mode {
	case config.DNSModeHTTPS:
		upstream := cfg.DNS.HTTPSURL
		if !strings.HasPrefix(upstream, "https://") {
			upstream = "https://" + upstream + "/dns-query"
		}
		return upstream
	case config.DNSModeUDP:
		return cfg.DNS.Addr.String()
	default:
		return ""
	}
}
