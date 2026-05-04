package cache

import "time"

// options holds all possible settings for a Set operation.
// Both caches will use this, but will only read what they need.
type options struct {
	ttl                time.Duration
	skipExisting       bool
	updateExistingOnly bool
	// We could add other options here later, e.g.:
	// cost int
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

// Cache is the unified interface for all cache implementations.
// The Set method accepts a variadic list of options.
type Cache[K comparable] interface {
	// Get retrieves a value from the cache.
	Get(key K) (any, bool)
	// Set adds a value to the cache, applying any provided options.
	Set(key K, value any, opts *options) bool
	Delete(key K)
	Has(key K) bool
	// ForEach iterates over the cache items.
	ForEach(f func(key K, value any) error) error
	// Size returns the number of items in the cache.
	Size() int
}
