package cache

// FNV-1a is used for shard selection because it is fast, allocation-free, and
// produces good distribution for small fixed-size keys (e.g. IP addresses, NAT tuples).
// Cryptographic strength is not required here — keys come from internal network state,
// not external input, so hash-flooding attacks are not a concern.
const (
	fnvOffset64 = uint64(14695981039346656037)
	fnvPrime64  = uint64(1099511628211)
)

func fnv1aBytes(b []byte) uint64 {
	h := fnvOffset64
	for _, c := range b {
		h ^= uint64(c)
		h *= fnvPrime64
	}
	return h
}
