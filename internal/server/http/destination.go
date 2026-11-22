package http

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/dns"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/rule"
	"github.com/xvzc/spoofdpi/internal/server"
)

// resolveDestination resolves host and selects the rule for it with
// server.SelectRule. An IP literal is not looked up, and its zone, if any,
// is the zone of the destination. A domain name is
// resolved with the DNS options of the domain rule it matches, else with
// base's. It returns the destination at port, the selected rule (nil when
// none matches) and the config to apply. An empty host is an error.
func resolveDestination(
	ctx context.Context,
	logger zerolog.Logger,
	resolver dns.Resolver,
	rules *rule.RuleSet,
	base *config.RuntimeConfig,
	host string,
	port int,
) (*netutil.Destination, *config.Rule, *config.RuntimeConfig, error) {
	var addrs []net.IP
	var zone string
	var hostRule *config.Rule

	if ip, err := netip.ParseAddr(host); err == nil {
		logger.Trace().Msgf("skipping dns lookup for non-domain host %q", host)
		addrs = []net.IP{ip.AsSlice()}
		zone = ip.Zone()
	} else {
		if host == "" {
			return nil, nil, nil, errors.New("no host to look up")
		}

		// Matching the host alone gives the DNS options to resolve it with.
		var hostCfg *config.RuntimeConfig
		hostRule, hostCfg = server.SelectRule(rules, base, host, nil)
		resolved, err := resolver.Resolve(ctx, &hostCfg.DNS, host)
		if err != nil {
			return nil, nil, nil, err
		}
		addrs = netutil.IPsFromAddrs(resolved)
	}

	matched, cfg := server.SelectRule(rules, base, "", addrs, hostRule)

	if matched != nil && logger.GetLevel() == zerolog.TraceLevel {
		logger.Trace().RawJSON("summary", matched.JSON()).Msg("match")
	}

	dst := &netutil.Destination{
		Host:  host,
		Addrs: addrs,
		Zone:  zone,
		Port:  port,
	}

	return dst, matched, cfg, nil
}

// destinationVerdict is what verifyDestination decides about a destination.
type destinationVerdict int

const (
	destinationAllowed destinationVerdict = iota
	// destinationSelf is a destination at the proxy's own address, which the
	// proxy refuses so it doesn't query itself recursively.
	destinationSelf
	// destinationBlocked is a destination the selected rule blocks.
	destinationBlocked
)

// verifyDestination decides whether a request may go on to dst, given the
// proxy's listenAddr and the rule matched for dst (nil when none matches).
func verifyDestination(
	logger zerolog.Logger,
	dst *netutil.Destination,
	matched *config.Rule,
	listenAddr *net.TCPAddr,
) destinationVerdict {
	if ok, err := dst.IsValid(listenAddr); !ok {
		logger.Debug().Err(err).Msg("error validating dst addrs")
		return destinationSelf
	}

	if matched != nil && matched.Block {
		logger.Debug().Msg("request is blocked by policy")
		return destinationBlocked
	}

	return destinationAllowed
}
