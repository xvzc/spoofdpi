package dns

import (
	"context"
	"net"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)

// systemResolver resolves names the way the operating system does, with
// the net package's default resolver rather than PreferGo. On darwin, Go
// sends lookups to libSystem's getaddrinfo even without cgo, so
// mDNSResponder's cache, split DNS and /etc/resolver/* apply; PreferGo
// would bypass them, and the Go team notes that darwin dislikes programs
// that do their own DNS. On Linux and FreeBSD, builds without cgo, such as
// the official Linux release binaries, use the Go resolver either way,
// which reads /etc/hosts and /etc/resolv.conf but applies no NSS modules,
// such as mDNS. Builds with cgo may use getaddrinfo instead, as
// /etc/nsswitch.conf decides.
type systemResolver struct {
	logger zerolog.Logger
	*net.Resolver
}

func newSystemResolver(logger zerolog.Logger) *systemResolver {
	return &systemResolver{
		logger:   logger,
		Resolver: &net.Resolver{},
	}
}

// resolve looks domain up for the address families of qTypes. server is
// unused. It reports a TTL of 0, as the system resolver reports none.
func (sr *systemResolver) resolve(
	ctx context.Context,
	_ string,
	domain string,
	qTypes []uint16,
) ([]netip.Addr, uint32, error) {
	addrs, err := sr.LookupNetIP(ctx, systemNetwork(qTypes), domain)
	if err != nil {
		return nil, 0, err
	}

	// The network already selects the families, so nothing is filtered.
	// LookupNetIP can return an IPv4 address in its IPv4-mapped form, which
	// the other resolvers never return.
	for i, a := range addrs {
		addrs[i] = a.Unmap()
	}
	return addrs, 0, nil
}

// systemNetwork returns the network to look up the record types qTypes
// with: "ip4" for A only, "ip6" for AAAA only, else "ip".
func systemNetwork(qTypes []uint16) string {
	wantsA, wantsAAAA := false, false
	for _, qType := range qTypes {
		switch qType {
		case dns.TypeA:
			wantsA = true
		case dns.TypeAAAA:
			wantsAAAA = true
		}
	}

	switch {
	case wantsA && !wantsAAAA:
		return "ip4"
	case wantsAAAA && !wantsA:
		return "ip6"
	default:
		return "ip"
	}
}
