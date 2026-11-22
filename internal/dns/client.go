package dns

import (
	"context"
	"fmt"
	"math"
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

// cacheKey identifies a cached answer: the name and the options that
// decide which answer a lookup gets. Rules can resolve the same name with
// different DNS options, and must not be served each other's answers, for
// example a DoH rule an answer obtained over plain UDP, or a rule with
// ipv6 off the IPv6 addresses of a lookup for a rule with ipv6 on. The
// qtype follows the ipv6 option (config.DNSOptions.QType).
type cacheKey struct {
	domain string
	mode   config.DNSModeType
	server string
	qtype  config.DNSQueryType
}

// Bytes returns the bytes the cache picks the key's shard by. The mode and
// qtype are left out: they only select the shard, and keys that differ
// only in them still compare unequal.
func (k cacheKey) Bytes() []byte { return []byte(k.domain + "\x00" + k.server) }

// systemCacheTTL is how long an answer of the system resolver is cached.
// Neither getaddrinfo nor the Go resolver reports the records' TTLs. The
// answer is cached anyway, as the Go resolver, which builds without cgo
// use on Linux and FreeBSD, has no cache of its own, and many servers,
// routers, containers and default FreeBSD installs run no local caching
// resolver. 30s keeps a stale answer short where the system does cache.
const systemCacheTTL = 30 * time.Second

// partialAnswerTTL caps how long an answer is cached when some of its
// queries failed, such as an AAAA query that got SERVFAIL while the A query
// succeeded, so that the missing addresses are asked for again soon.
const partialAnswerTTL = 30 * time.Second

// maxCacheTTL caps how long any answer is cached, so that a poisoned or
// broken answer with a huge TTL does not stick for the life of the
// process.
const maxCacheTTL = 24 * time.Hour

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
//
// Every answer is cached, keyed by the name and the options that decide
// it (see cacheKey): with the records' TTL for the udp and https modes,
// and for systemCacheTTL for the system mode. Caching is not optional, as
// callers resolve per connection and per datagram: SOCKS5 UDP ASSOCIATE
// resolves the name of every datagram, which would otherwise send a DNS
// query for each one.
type Client struct {
	logger zerolog.Logger
	https  internalResolver
	udp    internalResolver
	system internalResolver
	cache  cache.Cache[cacheKey, []netip.Addr]
	// systemTTL is how long an answer of the system resolver is cached.
	systemTTL time.Duration
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
		cache: cache.NewTTLCache[cacheKey, []netip.Addr](cache.TTLCacheAttrs{
			NumOfShards:     64,
			CleanupInterval: 3 * time.Minute,
		}),
		systemTTL: systemCacheTTL,
	}
}

// Resolve returns the addresses of domain, looked up as opts says, or as
// cached from an earlier lookup with the same options. An IP literal is
// returned as is. The lookup is bounded by opts.Timeout (an unset, zero
// Timeout leaves it unbounded).
func (c *Client) Resolve(
	ctx context.Context,
	opts *config.DNSOptions,
	domain string,
) ([]netip.Addr, error) {
	logger := logging.WithLocalScope(ctx, c.logger, "client")

	if ip, err := netip.ParseAddr(domain); err == nil {
		return []netip.Addr{ip}, nil
	}

	key := cacheKey{
		domain: domain,
		mode:   opts.Mode,
		server: c.serverFor(opts),
		qtype:  opts.QType,
	}
	if addrs, ok := c.cache.Get(key); ok {
		logger.Debug().Str("domain", domain).Msg("cache hit")
		return addrs, nil
	}
	logger.Debug().Str("domain", domain).Msg("cache miss")

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	resolver := c.pick(opts.Mode)
	qTypes := parseQueryTypes(opts.QType)

	t1 := time.Now()
	addrs, ttl, err := resolver.resolve(ctx, key.server, domain, qTypes)
	if err != nil {
		return nil, err
	}

	logger.Debug().
		Str("domain", domain).
		Int("len", len(addrs)).
		Str("took", fmt.Sprintf("%.3fms", float64(time.Since(t1).Microseconds())/1000.0)).
		Msg("dns lookup ok")

	// An empty answer, and one with a zero TTL, is not cached.
	cacheTTL := recordCacheTTL(ttl)
	if resolver == c.system {
		cacheTTL = c.systemTTL
	}
	if len(addrs) > 0 {
		_ = c.cache.Set(key, addrs, cache.Options().WithTTL(cacheTTL))
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

// recordCacheTTL returns how long to cache an answer whose records have the
// TTL ttl, in seconds. A TTL above 2^31-1 counts as 0 (RFC 2181, section
// 8), and a TTL longer than maxCacheTTL is cut to it.
func recordCacheTTL(ttl uint32) time.Duration {
	if ttl > math.MaxInt32 {
		return 0
	}
	return min(time.Duration(ttl)*time.Second, maxCacheTTL)
}
