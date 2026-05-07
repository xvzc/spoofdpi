package dns

import (
	"context"
	"net"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
)

type systemResolver struct {
	logger zerolog.Logger
	*net.Resolver
}

func newSystemResolver(
	logger zerolog.Logger,
	_ *config.RuntimeConfig,
) *systemResolver {
	return &systemResolver{
		logger:   logger,
		Resolver: &net.Resolver{PreferGo: true},
	}
}

func (sr *systemResolver) resolve(
	ctx context.Context,
	_ string,
	domain string,
	qTypes []uint16,
) ([]netip.Addr, uint32, error) {
	ips, err := sr.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, 0, err
	}

	return filtterAddrs(ips, qTypes), 0, nil
}

func filtterAddrs(ips []net.IP, qTypes []uint16) []netip.Addr {
	wantsA, wantsAAAA := false, false
	for _, qType := range qTypes {
		switch qType {
		case dns.TypeA:
			wantsA = true
		case dns.TypeAAAA:
			wantsAAAA = true
		}

		if wantsA && wantsAAAA {
			break
		}
	}

	if !wantsA && !wantsAAAA {
		return []netip.Addr{}
	}

	seen := make(map[string]struct{})
	filtered := make([]netip.Addr, 0, len(ips))

	for _, ip := range ips {
		addrStr := ip.String()
		if _, exists := seen[addrStr]; exists {
			continue
		}

		isIPv4 := ip.To4() != nil

		if wantsA && isIPv4 {
			if a, ok := netip.AddrFromSlice(ip.To4()); ok {
				seen[addrStr] = struct{}{}
				filtered = append(filtered, a)
			}
		} else if wantsAAAA && !isIPv4 {
			if a, ok := netip.AddrFromSlice(ip); ok {
				seen[addrStr] = struct{}{}
				filtered = append(filtered, a)
			}
		}
	}

	return filtered
}
