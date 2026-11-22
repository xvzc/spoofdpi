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

type hostname string

func (h hostname) Bytes() []byte { return []byte(h) }

// Resolver looks up the addresses of a domain name with the given options.
type Resolver interface {
	Resolve(
		ctx context.Context,
		opts *config.DNSOptions,
		domain string,
	) ([]netip.Addr, error)
}

var _ Resolver = (*Client)(nil)

// Client is the top-level DNS resolver. It holds the three backends and a
// shared cache; the options of each lookup are passed to Resolve.
type Client struct {
	logger zerolog.Logger
	https  *httpsResolver
	udp    *udpResolver
	system *systemResolver
	cache  cache.Cache[hostname, []netip.Addr]
}

// NewClient creates a Client. opts is only used for the startup log; each
// lookup uses the options passed to Resolve.
func NewClient(
	logger zerolog.Logger,
	opts *config.DNSOptions,
) *Client {
	https := newHTTPSResolver(logger)
	udp := newUDPResolver(logger)
	system := newSystemResolver(logger)

	logger.Info().Msg("dns info")
	logger.Info().Msgf(" query type '%s'", opts.QType.String())
	logger.Info().Msgf(" resolvers")
	for _, info := range []struct{ name, dst string }{
		{"udp", opts.Addr.String()},
		{"https", opts.HTTPSURL},
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
		cache: cache.NewTTLCache[hostname, []netip.Addr](cache.TTLCacheAttrs{
			NumOfShards:     64,
			CleanupInterval: 3 * time.Minute,
		}),
	}
}

// Resolve returns the addresses of domain, looked up as opts says. An IP
// literal is returned as is. The lookup is bounded by opts.Timeout (an
// unset, zero Timeout leaves it unbounded).
func (c *Client) Resolve(
	ctx context.Context,
	opts *config.DNSOptions,
	domain string,
) ([]netip.Addr, error) {
	logger := logging.WithLocalScope(ctx, c.logger, "client")

	if ip, err := netip.ParseAddr(domain); err == nil {
		return []netip.Addr{ip}, nil
	}

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	resolver := c.pick(opts.Mode)
	qTypes := parseQueryTypes(opts.QType)

	useCache := opts.Cache && opts.Mode != config.DNSModeSystem
	if useCache {
		if addrs, ok := c.cache.Get(hostname(domain)); ok {
			logger.Debug().Str("domain", domain).Msg("cache hit")
			return addrs, nil
		}
		logger.Debug().Str("domain", domain).Msg("cache miss")
	}

	t1 := time.Now()
	addrs, ttl, err := resolver.resolve(ctx, c.serverFor(opts), domain, qTypes)
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
			hostname(domain),
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

func (c *Client) serverFor(opts *config.DNSOptions) string {
	switch opts.Mode {
	case config.DNSModeHTTPS:
		upstream := opts.HTTPSURL
		if !strings.HasPrefix(upstream, "https://") {
			upstream = "https://" + upstream + "/dns-query"
		}
		return upstream
	case config.DNSModeUDP:
		return opts.Addr.String()
	default:
		return ""
	}
}
