package cache

import "time"

// options holds all possible settings for a Set operation.
// Both caches will use this, but will only read what they need.
type options struct {
	ttl                time.Duration
	skipExisting       bool
	updateExistingOnly bool
}

func Options() *options {
	return &options{}
}

func (o *options) WithTTL(ttl time.Duration) *options {
	o.ttl = ttl
	return o
}

func (o *options) WithUpdateExistingOnly(updateOnly bool) *options {
	o.updateExistingOnly = updateOnly
	return o
}

func (o *options) WithSkipExisting(skipExisting bool) *options {
	o.skipExisting = skipExisting
	return o
}

// Key is the constraint for cache keys. Bytes() is required instead of String() because
// sharded caches use it to compute the shard index, and raw bytes are significantly cheaper
// to hash than a formatted string — e.g. IPKey.String() formats an IP address and allocates,
// while IPKey.Bytes() returns the underlying array slice with zero allocation.
type Key interface {
	comparable
	Bytes() []byte
}

// Cache is the unified interface for all cache implementations.
type Cache[K Key, V any] interface {
	Get(key K) (V, bool)
	Set(key K, value V, opts *options) bool
	Delete(key K)
	Has(key K) bool
	ForEach(f func(key K, value V) error) error
	Size() int
}
