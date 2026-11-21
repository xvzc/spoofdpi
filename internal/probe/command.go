package probe

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/urfave/cli/v3"
	"github.com/xvzc/spoofdpi/internal/config"
)

const helpTemplate = `NAME:
  {{.Name}} - {{.Usage}}
USAGE:
  {{.Name}} [options]
DESCRIPTION:
  {{.Description}}
OPTIONS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
`

// NewCommand returns the probe command.
func NewCommand() *cli.Command {
	return newCommand(os.Stderr)
}

// newCommand is NewCommand with the writer for the DNS line and
// warnings.
func newCommand(stderr io.Writer) *cli.Command {
	var dnsOverrides []func(*config.DNSOptions)
	var dnsFlags []cli.Flag
	for _, f := range config.DNSFlags(func(apply func(*config.DNSOptions)) {
		dnsOverrides = append(dnsOverrides, apply)
	}) {
		// Only IPv4 is probed.
		if f.Names()[0] == "dns-qtype" {
			continue
		}
		// Their usage already states the default, which is not the flag's
		// zero value: the server's help does not print the latter either.
		switch f := f.(type) {
		case *cli.StringFlag:
			f.HideDefault = true
		case *cli.Int64Flag:
			f.HideDefault = true
		}
		dnsFlags = append(dnsFlags, f)
	}

	return &cli.Command{
		Name:  "probe",
		Usage: "Measure hop counts and DPI behavior of sites",
		Description: `Measures the actual hop count to each --url, a host name or IPv4
  address, over TCP and over UDP, both on port 443, and the hop count
  spoofdpi learns from the server's SYN/ACK and UDP reply. UDP reaches the
  server when it answers a QUIC probe with a Version Negotiation packet or
  an ICMP port unreachable. Hop counts are numbers of routers, as spoofdpi
  learns them. It then checks whether the server answers a QUIC v1 Initial
  for the site, compared with one for example.com, for the quic section of
  the report. Then, for the https section, it checks how a DPI blocks the
  site's ClientHello: whether it resets the connection or drops it
  silently, whether the ClientHello gets through in small chunks, with
  disorder or after a fake ClientHello, and the hop the DPI is at, then how
  the server handles fake ClientHellos that reach it. A blocked site can
  take minutes. Host names are resolved to IPv4 with the [dns]
  settings of the config file and the --dns-* options; rules are not
  applied. The learned hop counts, the hop of a DPI that blocks silently,
  and the fake checks need packet capture, usually root.`,
		CustomRootCommandHelpTemplate: helpTemplate,
		ErrWriter:                     io.Discard,
		OnUsageError: func(ctx context.Context, cmd *cli.Command, err error, sub bool) error {
			return err
		},
		// Keep a comma in a URL.
		DisableSliceFlagSeparator: true,
		Flags: append([]cli.Flag{
			&cli.StringSliceFlag{
				Name: "url",
				Usage: "site to probe: a host name or IPv4 address, without scheme, " +
					"port or path (repeatable, at least one)",
				Validator: checkTargets,
			},
			&cli.IntFlag{
				Name:     "max-ttl",
				Usage:    "highest TTL to try, 1 to 255",
				Value:    32,
				OnlyOnce: true,
			},
			&cli.DurationFlag{
				Name: "timeout",
				Usage: "timeout of each connection attempt, each wait for a UDP reply, " +
					"and each wait for an answer in the DPI checks",
				Value:    2 * time.Second,
				OnlyOnce: true,
			},
			&cli.StringFlag{
				Name: "config",
				Usage: "spoofdpi config file to read the [dns] section from " +
					"(default: the default locations)",
				OnlyOnce: true,
				Sources:  cli.EnvVars("SPOOFDPI_CONFIG"),
			},
			&cli.BoolFlag{
				Name:     "clean",
				Usage:    "do not read a config file",
				OnlyOnce: true,
			},
		}, dnsFlags...),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Present() {
				return fmt.Errorf("unexpected arguments: %q", cmd.Args().Slice())
			}
			clean := cmd.Bool("clean")
			dnsOpts, configFile, err := dnsOptions(clean, cmd.String("config"), dnsOverrides)
			if err != nil {
				return err
			}
			opts := Options{
				URLs: cmd.StringSlice("url"),
				Config: Config{
					MaxTTL:  cmd.Int("max-ttl"),
					Timeout: cmd.Duration("timeout"),
				},
				DNS:       dnsOpts,
				DNSSource: describeDNS(dnsOpts, configFile, clean),
			}
			return Run(ctx, opts, cmd.Root().Writer, stderr)
		},
	}
}
