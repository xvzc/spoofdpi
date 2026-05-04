package dns

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
)

// CacheResolver is a decorator that adds caching functionality to another Resolver.
type CacheResolver struct {
	logger zerolog.Logger

	ttlCache cache.Cache[string] // Owns the cache
}

// NewCacheResolver wraps a "worker" resolver with a cache.
func NewCacheResolver(
	logger zerolog.Logger,
	cache cache.Cache[string],
) *CacheResolver {
	return &CacheResolver{
		logger:   logger,
		ttlCache: cache,
	}
}

func (cr *CacheResolver) Info() []ResolverInfo {
	return []ResolverInfo{
		{
			Name: "cache",
			Dst:  "dynamic",
		},
	}
}

// Resolve implements the Resolver interface.
// This is where all the cache checking logic resides.
func (cr *CacheResolver) Resolve(
	ctx context.Context,
	domain string,
	fallback Resolver,
	rule *config.Rule,
) (*RecordSet, error) {
	logger := logging.WithLocalScope(ctx, cr.logger, "cache")
	// 1. [Cache Read]
	// Cache key might need to include spec info if spec changes the result for the same domain.
	// However, current cache key is just `domain`. If different specs map same domain to different IPs,
	// the cache might return the wrong one.
	// For now, assuming simplistic cache key = domain, but awareness of potential issue.
	// Ideally: key = domain + qtypes + spec-related-things
	if item, ok := cr.ttlCache.Fetch(domain); ok {
		logger.Debug().Str("domain", domain).Msgf("hit")
		return item.(*RecordSet).Clone(), nil
	}

	if fallback == nil {
		return nil, fmt.Errorf("no fallback resolver specified")
	}

	// 2. [Cache Miss]
	//    Delegate the actual network request to 'r.next' (the worker).
	logger.Debug().Str("domain", domain).Str("fallback", fallback.Info()[0].Name).
		Msgf("miss")

	rSet, err := fallback.Resolve(ctx, domain, nil, rule)
	if err != nil {
		return nil, err
	}

	// 3. [Cache Write]
	// (Assuming the actual TTL is parsed from the DNS response)
	// realTTL := 5 * time.Second
	logger.Debug().
		Str("domain", domain).
		Int("len", len(rSet.Addrs)).
		Uint32("ttl", rSet.TTL).
		Msg("set")

	_ = cr.ttlCache.Store(
		domain,
		rSet,
		cache.Options().WithTTL(time.Duration(rSet.TTL)*time.Second),
	)

	return rSet, nil
}
