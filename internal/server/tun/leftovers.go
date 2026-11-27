package tun

// CleanupOptions holds what CleanLeftovers needs from the configuration to
// find the network configuration that an earlier run left behind.
type CleanupOptions struct {
	// FreeBSDFIB is the FIB set by freebsd-fib, or 0 when it is not set.
	// Only FreeBSD uses it.
	FreeBSDFIB int
}
