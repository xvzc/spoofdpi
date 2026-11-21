package probe

import (
	"github.com/xvzc/spoofdpi/internal/config"
)

// dnsOptions returns the DNS options probe resolves with, and the config
// file they were read from ("" if none): the defaults overlaid with the
// [dns] section of the config file that spoofdpi run would load, unless
// clean is set, then with the given flag overrides. Lookups are always
// IPv4 and uncached, since only an IPv4 address is probed and each run
// should see the resolver's current answer.
func dnsOptions(
	clean bool,
	configFile string,
	overrides []func(*config.DNSOptions),
) (config.DNSOptions, string, error) {
	opts := config.DefaultConfig().DNS
	path := ""
	if !clean {
		var err error
		opts, path, err = config.LoadDNS(configFile)
		if err != nil {
			return config.DNSOptions{}, "", err
		}
	}
	for _, apply := range overrides {
		apply(&opts)
	}
	opts.QType = config.DNSQueryIPv4
	opts.Cache = false
	return opts, path, nil
}

// describeDNS describes the DNS options opts, read from configFile, for
// the line Run prints, such as "https (https://1.1.1.1/dns-query), config
// /etc/spoofdpi.toml".
func describeDNS(opts config.DNSOptions, configFile string, clean bool) string {
	s := opts.Mode.String()
	switch opts.Mode {
	case config.DNSModeHTTPS:
		s += " (" + opts.HTTPSURL + ")"
	case config.DNSModeUDP:
		s += " (" + opts.Addr.String() + ")"
	}
	switch {
	case clean:
		return s + ", no config file (--clean)"
	case configFile != "":
		return s + ", config " + configFile
	default:
		return s + ", no config file"
	}
}
