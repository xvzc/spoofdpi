package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// routeFinder discovers the egress of the host. Tests replace it to fake
// the host.
type routeFinder struct {
	// egress discovers and classifies the egress of fam, as
	// netutil.DiscoverEgress does.
	egress func(fam netutil.Family, gateway net.IP, zone string) (*netutil.Egress, error)
	// hasIPv6Egress reports whether the host has an IPv6 route to the
	// internet.
	hasIPv6Egress func() bool
}

var osRouteFinder = routeFinder{
	egress: netutil.DiscoverEgress,
	hasIPv6Egress: func() bool {
		_, ok := netutil.IPv6Egress()
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
	V4 *netutil.Egress
	// V6 is the IPv6 egress, or nil when IPv6 is off.
	V6 *netutil.Egress
	// FakesV4 and FakesV6 say why fake packets are off for IPv4 and IPv6,
	// and are nil when they are on.
	FakesV4 error
	FakesV6 error
	// IPv6Off is why discoverEgresses turned IPv6 off in the config for
	// this run, or ipv6StayedOn.
	IPv6Off ipv6OffCause
}

// discoverEgresses discovers and classifies the egress of each address
// family that cfg needs, using the gateways it sets, and decides whether
// fake packets can be sent through them.
//
// The IPv4 egress is discovered only when cfg needs it: for fake packets
// or TUN mode. A full-tunnel VPN there is fatal in TUN mode and turns
// fake packets off otherwise.
//
// The IPv6 egress is discovered only when IPv6 is enabled. When none is
// usable and no IPv6 gateway is set, or a full-tunnel VPN carries IPv6 in
// TUN mode, discoverEgresses turns IPv6 off in cfg for this run. Fake
// packets are off for IPv6.
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
) (*netutil.Egress, error, error) {
	gateway := cfg.App.Gateway.V4
	if !cfg.NeedsRoute() {
		if gateway != nil {
			logger.Warn().
				Str("gateway", gateway.String()).
				Msg("gateway is ignored; only fake packets and tun mode use it")
		}
		return nil, nil, nil
	}

	egress, err := f.egress(netutil.FamilyV4, gateway, "")
	if errors.Is(err, netutil.ErrNoIPv4Route) {
		return nil, nil, noIPv4RouteError(err, f.hasIPv6Egress())
	}
	if errors.Is(err, netutil.ErrBadGateway) {
		return nil, nil, fmt.Errorf(
			"failed to find default route: %w; check --gateway, "+
				"or remove it to use the system's default route",
			err,
		)
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
	case netutil.EgressVPN:
		if cfg.App.Mode == config.AppModeTUN {
			return nil, nil, tunVPNError(egress, gateway)
		}
		// Fake packets would leave through the VPN, whose far end, not
		// the censor, would see them.
		warn := fmt.Sprintf(
			"a full-tunnel VPN (%s) carries the traffic; fake packets are disabled",
			egress.Reason,
		)
		if gateway != nil {
			warn += fmt.Sprintf(" (gateway %s is ignored)", gateway)
		}
		logger.Warn().Msg(warn)
		return egress, &desync.FakesOffError{
			Family:    netutil.FamilyV4,
			Kind:      desync.FakesOffVPNAtStartup,
			Interface: egress.Route.Iface.Name,
			Reason: fmt.Sprintf(
				"a full-tunnel VPN (%s) carries the traffic",
				egress.Reason,
			),
		}, nil
	case netutil.EgressUnknown:
		warnUnknownEgress(logger, egress)
	}
	return egress, nil, nil
}

// tunVPNError is the error of TUN mode on an IPv4 egress that is a
// full-tunnel VPN. gateway is the IPv4 gateway option, or nil.
func tunVPNError(egress *netutil.Egress, gateway net.IP) error {
	var note string
	if gateway != nil {
		note = "; the gateway option does not override this"
	}
	return fmt.Errorf(
		"TUN mode cannot run while a full-tunnel VPN carries the traffic (%s); "+
			"disconnect the VPN or use the HTTP or SOCKS5 mode%s",
		egress.Reason,
		note,
	)
}

// discoverEgressV6 discovers the IPv6 egress when IPv6 is enabled, and
// reports why it turned IPv6 off in cfg instead, if it did.
func discoverEgressV6(
	logger zerolog.Logger,
	cfg *config.Config,
	f routeFinder,
) (*netutil.Egress, ipv6OffCause, error) {
	gateways := cfg.App.Gateway
	if !cfg.IPv6Enabled() {
		if gateways.V6 != nil {
			v6 := config.Gateways{V6: gateways.V6, V6Zone: gateways.V6Zone}
			logger.Warn().Msgf(
				"IPv6 gateway %s is ignored; it is used only when ipv6 is enabled",
				v6,
			)
		}
		return nil, ipv6StayedOn, nil
	}

	egress, err := f.egress(netutil.FamilyV6, gateways.V6, gateways.V6Zone)
	switch {
	case err != nil && gateways.V6 != nil:
		return nil, ipv6StayedOn, fmt.Errorf(
			"failed to use IPv6 gateway: %w; check the IPv6 address of --gateway, "+
				"or remove it to use the system's IPv6 default route",
			err,
		)
	case err != nil:
		logger.Warn().
			Err(err).
			Msg("IPv6 is enabled but no usable IPv6 route was found; " +
				"running with IPv6 disabled")
		cfg.DisableIPv6()
		return nil, ipv6OffNoRoute, nil
	}

	tun := cfg.App.Mode == config.AppModeTUN
	switch {
	case egress.Class == netutil.EgressVPN && tun:
		warn := fmt.Sprintf(
			"a full-tunnel VPN (%s) carries IPv6; running with IPv6 disabled",
			egress.Reason,
		)
		if gateways.V6 != nil {
			v6 := config.Gateways{V6: gateways.V6, V6Zone: gateways.V6Zone}
			warn += fmt.Sprintf(" (gateway %s is ignored)", v6)
		}
		logger.Warn().Msg(warn)
		cfg.DisableIPv6()
		return nil, ipv6OffVPN, nil
	case egress.Class == netutil.EgressVPN:
		logger.Info().Msgf("IPv6 goes through a full-tunnel VPN (%s)", egress.Reason)
		return egress, ipv6StayedOn, nil
	}

	logEgress(logger, netutil.FamilyV6, egress)
	// Outside TUN mode, the class of the IPv6 egress decides nothing.
	if egress.Class == netutil.EgressUnknown && tun {
		warnUnknownEgress(logger, egress)
	}
	return egress, ipv6StayedOn, nil
}

// dstFakeCheck returns the lookup of a desync.RouteGate in the proxy
// modes: fake packets to a destination are off when the kernel routes it
// through a VPN, as a split-tunnel VPN does for some destinations, since
// the VPN's far end, not the censor, would see them. start is the IPv4
// egress found at startup, or nil; a destination routed through the
// interface of start, or through the link of its kernel route (which an
// explicit gateway on another interface leaves different), is not
// classified again. routeTo and classify find and classify the
// route to a destination, as netutil.RouteTo and netutil.ClassifyPath do.
//
// A route that cannot be found or classified allows fake packets, with a
// debug log.
func dstFakeCheck(
	logger zerolog.Logger,
	start *netutil.Egress,
	routeTo func(netip.Addr) (*netutil.Path, error),
	classify func(*netutil.Path) (*netutil.Egress, error),
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
		if start != nil &&
			(path.Iface.Index == start.Route.Iface.Index ||
				path.Iface.Index == start.Link.Index) {
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
		if egress.Class != netutil.EgressVPN {
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
func logEgress(logger zerolog.Logger, fam netutil.Family, egress *netutil.Egress) {
	route := &egress.Route
	gateway := "-"
	if route.Gateway != nil {
		gateway = route.GatewayString()
	}
	src := "-"
	if route.LocalIP != nil {
		src = route.LocalIP.String()
	}
	link := egress.Link.Kind.String()
	if egress.Link.Detail != "" {
		link += " (" + egress.Link.Detail + ")"
	}
	logger.Info().
		Str("family", fam.String()).
		Str("interface", route.Iface.Name).
		Str("class", egress.Class.String()).
		Str("link", link).
		Str("gateway", gateway).
		Str("src", src).
		Msg("egress")
}

// warnUnknownEgress warns that the class of egress is unknown: it may be
// a full-tunnel VPN, which spoofdpi cannot work through, but spoofdpi
// proceeds as if it were not.
func warnUnknownEgress(logger zerolog.Logger, egress *netutil.Egress) {
	logger.Warn().Msgf(
		"%s; proceeding as if it were not; fake packets and TUN mode do not "+
			"work through a full-tunnel VPN, so if it is one, disconnect it, "+
			"or disable fake packets and use HTTP or SOCKS5 mode",
		egress.Reason,
	)
}
