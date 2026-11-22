package dns

import (
	"context"
	"net"
	"net/netip"

	"github.com/xvzc/spoofdpi/internal/config"
)

// SystemResolver resolves names with the operating system's resolver to the
// single address net.ResolveUDPAddr would pick for them.
type SystemResolver struct{}

var _ Resolver = SystemResolver{}

// Resolve ignores opts. It returns one address: the first IPv4 address the
// system resolver returns, else its first address.
func (SystemResolver) Resolve(
	ctx context.Context,
	_ *config.DNSOptions,
	domain string,
) ([]netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}

	addr, ok := preferIPv4(addrs)
	if !ok {
		return nil, &net.AddrError{Err: "no suitable address found", Addr: domain}
	}

	return []netip.Addr{addr}, nil
}

// preferIPv4 returns the first IPv4 address of addrs, unmapped, else the
// first address; ok is false when addrs is empty.
func preferIPv4(addrs []netip.Addr) (addr netip.Addr, ok bool) {
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap(), true
		}
	}
	if len(addrs) == 0 {
		return netip.Addr{}, false
	}

	return addrs[0], true
}
