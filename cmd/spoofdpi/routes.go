package main

import (
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
)

// routeFinder discovers the egress of the host. Tests replace it to fake
// the host.
type routeFinder struct {
	// egress discovers the egress of fam, as route.DiscoverEgress does.
	egress func(fam netutil.Family) (*route.Egress, error)
	// hasIPv6Egress reports whether the host has an IPv6 route to the
	// internet.
	hasIPv6Egress func() bool
}

var osRouteFinder = routeFinder{
	egress: route.DiscoverEgress,
	hasIPv6Egress: func() bool {
		_, ok := route.IPv6Egress()
		return ok
	},
}

// ipv6OffCause is why discoverEgresses turned IPv6 off in the config.
type ipv6OffCause uint8

const (
	// ipv6StayedOn: discoverEgresses did not turn IPv6 off.
	ipv6StayedOn ipv6OffCause = iota
	// ipv6OffNoRoute: no usable IPv6 route was found.
	ipv6OffNoRoute
)

// startupNet is what discoverEgresses found at startup.
type startupNet struct {
	// V4 is the IPv4 egress, or nil when the config needs none.
	V4 *route.Egress
	// V6 is the IPv6 egress, or nil when IPv6 is off.
	V6 *route.Egress
	// FakesV6 says why fake packets are off for IPv6.
	FakesV6 error
	// IPv6Off is why discoverEgresses turned IPv6 off in the config for
	// this run, or ipv6StayedOn.
	IPv6Off ipv6OffCause
}

// discoverEgresses discovers the egress of each address family that cfg
// needs.
//
// The IPv4 egress is discovered only when cfg needs it: for fake packets
// or TUN mode.
//
// The IPv6 egress is discovered only when IPv6 is enabled. When none is
// usable, discoverEgresses turns IPv6 off in cfg for this run. Fake
// packets are off for IPv6.
func discoverEgresses(
	logger zerolog.Logger,
	cfg *config.Config,
	f routeFinder,
) (startupNet, error) {
	v4, err := discoverEgressV4(logger, cfg, f)
	if err != nil {
		return startupNet{}, err
	}
	v6, ipv6Off := discoverEgressV6(logger, cfg, f)
	return startupNet{
		V4: v4,
		V6: v6,
		FakesV6: &desync.FakesOffError{
			Family: netutil.FamilyV6,
			Kind:   desync.FakesOffIPv6Unsupported,
			Reason: "IPv6 fakes are not supported yet",
		},
		IPv6Off: ipv6Off,
	}, nil
}

// discoverEgressV4 discovers the IPv4 egress when cfg needs it.
func discoverEgressV4(
	logger zerolog.Logger,
	cfg *config.Config,
	f routeFinder,
) (*route.Egress, error) {
	if !cfg.NeedsRoute() {
		return nil, nil
	}

	egress, err := f.egress(netutil.FamilyV4)
	if errors.Is(err, route.ErrNoIPv4) {
		return nil, noIPv4RouteError(err, f.hasIPv6Egress())
	}
	if err != nil {
		return nil, fmt.Errorf(
			"failed to find default route: %w; "+
				"disable fake packets and use HTTP or SOCKS5 mode to run without it",
			err,
		)
	}
	logEgress(logger, netutil.FamilyV4, egress)
	return egress, nil
}

// discoverEgressV6 discovers the IPv6 egress when IPv6 is enabled, and
// reports why it turned IPv6 off in cfg instead, if it did.
func discoverEgressV6(
	logger zerolog.Logger,
	cfg *config.Config,
	f routeFinder,
) (*route.Egress, ipv6OffCause) {
	if !cfg.IPv6Enabled() {
		return nil, ipv6StayedOn
	}

	egress, err := f.egress(netutil.FamilyV6)
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("IPv6 is enabled but no usable IPv6 route was found; " +
				"running with IPv6 disabled")
		cfg.DisableIPv6()
		return nil, ipv6OffNoRoute
	}
	logEgress(logger, netutil.FamilyV6, egress)
	return egress, ipv6StayedOn
}

// logEgress logs the egress of fam.
func logEgress(logger zerolog.Logger, fam netutil.Family, egress *route.Egress) {
	rt := &egress.Route
	gateway := "-"
	if rt.Gateway != nil {
		gateway = rt.GatewayString()
	}
	src := "-"
	if rt.LocalIP != nil {
		src = rt.LocalIP.String()
	}
	logger.Info().
		Str("family", fam.String()).
		Str("interface", rt.Iface.Name).
		Str("gateway", gateway).
		Str("src", src).
		Msg("egress")
}
