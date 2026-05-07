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

// Cache is the unified interface for all cache implementations.
type Cache[K comparable, V any] interface {
	Get(key K) (V, bool)
	Set(key K, value V, opts *options) bool
	Delete(key K)
	Has(key K) bool
	ForEach(f func(key K, value V) error) error
	Size() int
}
