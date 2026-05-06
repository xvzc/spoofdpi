package dns

import (
	"context"
	"net"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
)

var _ Resolver = (*systemResolver)(nil)

type systemResolver struct {
	logger zerolog.Logger
	*net.Resolver
	rt *config.RuntimeConfig
}

func newSystemResolver(
	logger zerolog.Logger,
	rt *config.RuntimeConfig,
) *systemResolver {
	return &systemResolver{
		logger:   logger,
		Resolver: &net.Resolver{PreferGo: true},
		rt:       rt,
	}
}

func (sr *systemResolver) Resolve(
	ctx context.Context,
	domain string,
	rule *config.Rule,
) (*RecordSet, error) {
	rt := sr.rt
	if rule != nil {
		rt = &rule.Config
	}

	ips, err := sr.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}

	return &RecordSet{
		Addrs: filtterAddrs(ips, parseQueryTypes(rt.DNS.QType)),
		TTL:   0,
	}, nil
}

func filtterAddrs(ips []net.IP, qTypes []uint16) []net.IP {
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
		return []net.IP{}
	}

	filteredMap := make(map[string]net.IP)

	for _, ip := range ips {
		addrStr := ip.String()
		if _, exists := filteredMap[addrStr]; exists {
			continue
		}

		isIPv4 := ip.To4() != nil

		if wantsA && isIPv4 {
			filteredMap[addrStr] = ip
		}

		if wantsAAAA && !isIPv4 {
			filteredMap[addrStr] = ip
		}
	}

	filtered := make([]net.IP, 0, len(filteredMap))
	for _, ip := range filteredMap {
		filtered = append(filtered, ip)
	}

	return filtered
}
