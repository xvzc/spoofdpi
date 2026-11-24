package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
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
	// IPv6Disabled reports that discoverEgresses turned IPv6 off in the
	// config for this run.
	IPv6Disabled bool
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
	v6, ipv6Disabled, err := discoverEgressV6(logger, cfg, f)
	if err != nil {
		return startupNet{}, err
	}
	return startupNet{
		V4:      v4,
		V6:      v6,
		FakesV4: fakesV4,
		FakesV6: &packet.FakesOffError{
			Family: netutil.FamilyV6,
			Reason: "IPv6 fakes are not supported yet",
		},
		IPv6Disabled: ipv6Disabled,
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
	if err != nil {
		if gateway != nil {
			return nil, nil, fmt.Errorf(
				"failed to find default route: %w; check --gateway, "+
					"or remove it to use the system's default route",
				err,
			)
		}
		return nil, nil, fmt.Errorf(
			"failed to find default route: %w; set --gateway, "+
				"or disable fake packets and use HTTP/SOCKS5 mode",
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
		return egress, &packet.FakesOffError{
			Family: netutil.FamilyV4,
			Reason: fmt.Sprintf("a full-tunnel VPN (%s) carries the traffic", egress.Reason),
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
// reports whether it turned IPv6 off in cfg instead.
func discoverEgressV6(
	logger zerolog.Logger,
	cfg *config.Config,
	f routeFinder,
) (*netutil.Egress, bool, error) {
	gateways := cfg.App.Gateway
	if !cfg.IPv6Enabled() {
		if gateways.V6 != nil {
			v6 := config.Gateways{V6: gateways.V6, V6Zone: gateways.V6Zone}
			logger.Warn().Msgf(
				"IPv6 gateway %s is ignored; it is used only when ipv6 is enabled",
				v6,
			)
		}
		return nil, false, nil
	}

	egress, err := f.egress(netutil.FamilyV6, gateways.V6, gateways.V6Zone)
	switch {
	case err != nil && gateways.V6 != nil:
		return nil, false, fmt.Errorf(
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
		return nil, true, nil
	}

	tun := cfg.App.Mode == config.AppModeTUN
	switch {
	case egress.Class == netutil.EgressVPN && tun:
		logger.Warn().Msgf(
			"a full-tunnel VPN (%s) carries IPv6; running with IPv6 disabled",
			egress.Reason,
		)
		cfg.DisableIPv6()
		return nil, true, nil
	case egress.Class == netutil.EgressVPN:
		logger.Info().Msgf("IPv6 goes through a full-tunnel VPN (%s)", egress.Reason)
		return egress, false, nil
	}

	logEgress(logger, netutil.FamilyV6, egress)
	// Outside TUN mode, the class of the IPv6 egress decides nothing.
	if egress.Class == netutil.EgressUnknown && tun {
		warnUnknownEgress(logger, egress)
	}
	return egress, false, nil
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
		"%s; proceeding as if it were not; if it is a full-tunnel VPN, "+
			"fake packets and TUN mode do not work through it",
		egress.Reason,
	)
}
