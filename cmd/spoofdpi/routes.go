package main

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
)

// routeFinder discovers the egress of the host. Tests replace it to fake
// the host.
type routeFinder struct {
	// egress discovers and classifies the egress of fam, as
	// route.DiscoverEgress does.
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
	// ipv6OffVPN: a full-tunnel VPN carries IPv6 in TUN mode.
	ipv6OffVPN
)

// startupNet is what discoverEgresses found at startup.
type startupNet struct {
	// V4 is the IPv4 egress, or nil when the config needs none.
	V4 *route.Egress
	// V6 is the IPv6 egress, or nil when IPv6 is off.
	V6 *route.Egress
	// FakesV4 and FakesV6 say why fake packets are off for IPv4 and IPv6,
	// and are nil when they are on.
	FakesV4 error
	FakesV6 error
	// IPv6Off is why discoverEgresses turned IPv6 off in the config for
	// this run, or ipv6StayedOn.
	IPv6Off ipv6OffCause
}

// discoverEgresses discovers and classifies the egress of each address
// family that cfg needs, and decides whether fake packets can be sent
// through them.
//
// The IPv4 egress is discovered only when cfg needs it: for fake packets
// or TUN mode. A full-tunnel VPN there is fatal in TUN mode and turns
// fake packets off otherwise.
//
// The IPv6 egress is discovered only when IPv6 is enabled. When none is
// usable, or a full-tunnel VPN carries IPv6 in TUN mode, discoverEgresses
// turns IPv6 off in cfg for this run. Fake packets are off for IPv6.
func discoverEgresses(
	logger zerolog.Logger,
	cfg *config.Config,
	f routeFinder,
) (startupNet, error) {
	v4, fakesV4, err := discoverEgressV4(logger, cfg, f)
	if err != nil {
		return startupNet{}, err
	}
	v6, ipv6Off, err := discoverEgressV6(logger, cfg, f)
	if err != nil {
		return startupNet{}, err
	}
	return startupNet{
		V4:      v4,
		V6:      v6,
		FakesV4: fakesV4,
		FakesV6: &desync.FakesOffError{
			Family: netutil.FamilyV6,
			Kind:   desync.FakesOffIPv6Unsupported,
			Reason: "IPv6 fakes are not supported yet",
		},
		IPv6Off: ipv6Off,
	}, nil
}

// discoverEgressV4 discovers the IPv4 egress when cfg needs it, and
// returns it with the reason fake packets are off for IPv4, if they are.
func discoverEgressV4(
	logger zerolog.Logger,
	cfg *config.Config,
	f routeFinder,
) (*route.Egress, error, error) {
	if !cfg.NeedsRoute() {
		return nil, nil, nil
	}

	egress, err := f.egress(netutil.FamilyV4)
	if errors.Is(err, route.ErrNoIPv4) {
		return nil, nil, noIPv4RouteError(err, f.hasIPv6Egress())
	}
	if err != nil {
		return nil, nil, fmt.Errorf(
			"failed to find default route: %w; "+
				"disable fake packets and use HTTP or SOCKS5 mode to run without it",
			err,
		)
	}
	logEgress(logger, netutil.FamilyV4, egress)

	switch egress.Class {
	case route.EgressVPN:
		if cfg.App.Mode == config.AppModeTUN {
			return nil, nil, tunVPNError(egress)
		}
		// Fake packets would leave through the VPN, whose far end, not
		// the censor, would see them.
		logger.Warn().Msgf(
			"a full-tunnel VPN (%s) carries the traffic; fake packets are disabled",
			egress.Reason,
		)
		return egress, &desync.FakesOffError{
			Family:    netutil.FamilyV4,
			Kind:      desync.FakesOffVPNAtStartup,
			Interface: egress.Route.Iface.Name,
			Reason: fmt.Sprintf(
				"a full-tunnel VPN (%s) carries the traffic",
				egress.Reason,
			),
		}, nil
	case route.EgressUnknown:
		warnUnknownEgress(logger, egress)
	}
	return egress, nil, nil
}

// tunVPNError is the error of TUN mode on an IPv4 egress that is a
// full-tunnel VPN.
func tunVPNError(egress *route.Egress) error {
	return fmt.Errorf(
		"TUN mode cannot run while a full-tunnel VPN carries the traffic (%s); "+
			"disconnect the VPN or use the HTTP or SOCKS5 mode",
		egress.Reason,
	)
}

// discoverEgressV6 discovers the IPv6 egress when IPv6 is enabled, and
// reports why it turned IPv6 off in cfg instead, if it did.
func discoverEgressV6(
	logger zerolog.Logger,
	cfg *config.Config,
	f routeFinder,
) (*route.Egress, ipv6OffCause, error) {
	if !cfg.IPv6Enabled() {
		return nil, ipv6StayedOn, nil
	}

	egress, err := f.egress(netutil.FamilyV6)
	if err != nil {
		logger.Warn().
			Err(err).
			Msg("IPv6 is enabled but no usable IPv6 route was found; " +
				"running with IPv6 disabled")
		cfg.DisableIPv6()
		return nil, ipv6OffNoRoute, nil
	}

	tun := cfg.App.Mode == config.AppModeTUN
	switch {
	case egress.Class == route.EgressVPN && tun:
		logger.Warn().Msgf(
			"a full-tunnel VPN (%s) carries IPv6; running with IPv6 disabled",
			egress.Reason,
		)
		cfg.DisableIPv6()
		return nil, ipv6OffVPN, nil
	case egress.Class == route.EgressVPN:
		logger.Info().Msgf("IPv6 goes through a full-tunnel VPN (%s)", egress.Reason)
		return egress, ipv6StayedOn, nil
	}

	logEgress(logger, netutil.FamilyV6, egress)
	// Outside TUN mode, the class of the IPv6 egress decides nothing.
	if egress.Class == route.EgressUnknown && tun {
		warnUnknownEgress(logger, egress)
	}
	return egress, ipv6StayedOn, nil
}

// dstFakeCheck returns the lookup of a desync.RouteGate in the proxy
// modes: fake packets to a destination are off when the kernel routes it
// through a VPN, as a split-tunnel VPN does for some destinations, since
// the VPN's far end, not the censor, would see them. start is the IPv4
// egress found at startup, or nil; a destination routed through the
// interface of start is not classified again. routeTo and classify find
// and classify the route to a destination, as route.Lookup and
// route.ClassifyPath do.
//
// A route that cannot be found or classified allows fake packets, with a
// debug log.
func dstFakeCheck(
	logger zerolog.Logger,
	start *route.Egress,
	routeTo func(netip.Addr) (*route.Path, error),
	classify func(*route.Path) (*route.Egress, error),
) func(netip.Addr) error {
	return func(dst netip.Addr) error {
		path, err := routeTo(dst)
		if err != nil {
			logger.Debug().
				Str("dst", dst.String()).
				Err(err).
				Msg("route lookup failed; allowing fake packets")
			return nil
		}
		if start != nil && path.Iface.Index == start.Route.Iface.Index {
			return nil
		}
		egress, err := classify(path)
		if err != nil {
			logger.Debug().
				Str("dst", dst.String()).
				Str("interface", path.Iface.Name).
				Err(err).
				Msg("route classification failed; allowing fake packets")
			return nil
		}
		if egress.Class != route.EgressVPN {
			return nil
		}
		return &desync.FakesOffError{
			Family:    path.Family,
			Kind:      desync.FakesOffDstViaVPN,
			Interface: path.Iface.Name,
			Reason: fmt.Sprintf(
				"the route to %s goes through a VPN (%s)", dst, path.Iface.Name,
			),
		}
	}
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
	link := egress.Link.Kind.String()
	if egress.Link.Detail != "" {
		link += " (" + egress.Link.Detail + ")"
	}
	logger.Info().
		Str("family", fam.String()).
		Str("interface", rt.Iface.Name).
		Str("class", egress.Class.String()).
		Str("link", link).
		Str("gateway", gateway).
		Str("src", src).
		Msg("egress")
}

// warnUnknownEgress warns that the class of egress is unknown: it may be
// a full-tunnel VPN, which spoofdpi cannot work through, but spoofdpi
// proceeds as if it were not.
func warnUnknownEgress(logger zerolog.Logger, egress *route.Egress) {
	logger.Warn().Msgf(
		"%s; proceeding as if it were not; fake packets and TUN mode do not "+
			"work through a full-tunnel VPN, so if it is one, disconnect it, "+
			"or disable fake packets and use HTTP or SOCKS5 mode",
		egress.Reason,
	)
}
