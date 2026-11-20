package config

import (
	"context"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"os/user"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/urfave/cli/v3"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// DefaultConfig returns a fully-populated Config with default values for
// every field. Used as the starting point of the load pipeline
// (defaults → TOML → CLI → Finalize → Validate). Tests that need a
// single section (e.g. base RuntimeConfig for resolveRules) reach in
// via DefaultConfig().RuntimeConfig / .App.
func DefaultConfig() *Config { //exhaustruct:enforce
	return &Config{
		App: AppOptions{ //exhaustruct:enforce
			NoTUI:                false,
			LogLevel:             zerolog.InfoLevel,
			Silent:               false,
			AutoConfigureNetwork: false,
			Mode:                 AppModeHTTP,
			ListenAddr:           net.TCPAddr{},
			Gateway:              nil,
			FreebsdFIB:           1,
		},
		Rules: nil,
		RuntimeConfig: RuntimeConfig{ //exhaustruct:enforce
			Conn: ConnOptions{ //exhaustruct:enforce
				HopCountDefault: 8,
				HopCountMin:     0,
				HopCountMax:     255,
				HopCountOffset:  0,
				DNSTimeout:      5000 * time.Millisecond,
				TCPTimeout:      10000 * time.Millisecond,
				UDPIdleTimeout:  25000 * time.Millisecond,
			},
			DNS: DNSOptions{ //exhaustruct:enforce
				Mode:     DNSModeUDP,
				Addr:     net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53, Zone: ""},
				HTTPSURL: "https://dns.google/dns-query",
				QType:    DNSQueryIPv4,
				Cache:    false,
			},
			HTTPS: HTTPSOptions{ //exhaustruct:enforce
				Disorder:           false,
				FakeCount:          0,
				FakePacket:         proto.NewFakeTLSMessage([]byte(FakeClientHello)),
				FakeSeq:            SeqMode{Random: false, Offset: 0},
				FakeAck:            SeqMode{Random: false, Offset: 0},
				SynAckTimeout:      100 * time.Millisecond,
				SplitMode:          HTTPSSplitModeSNI,
				ChunkSize:          35,
				CustomSegmentPlans: nil,
				Skip:               false,
			},
			UDP: UDPOptions{ //exhaustruct:enforce
				Skip:       false,
				FakeCount:  0,
				FakePacket: make([]byte, 64),
			},
		},
	}
}

func CreateCommand(
	runFunc func(ctx context.Context, configDir string, cfg *Config) error,
	version string,
	commit string,
	build string,
) *cli.Command {
	cli.RootCommandHelpTemplate = createHelpTemplate()

	// cliOverrides is appended to by Flag.Action below — once per flag the
	// user actually sets. Load applies them after loadTOML so CLI wins.
	var cliOverrides []func(*Config)
	// deprecatedOverrides holds the overrides from deprecated flag names.
	// They are applied before cliOverrides so the current names win.
	var deprecatedOverrides []func(*Config)
	defaultCfg := DefaultConfig()

	cmd := &cli.Command{
		Name:        "spoofdpi",
		Description: "Simple and fast anti-censorship tool to bypass DPI",
		Copyright:   "Apache License, Version 2.0, January 2004",
		ErrWriter:   io.Discard,
		OnUsageError: func(ctx context.Context, cmd *cli.Command, err error, sub bool) error {
			return err
		},
		Flags: slices.Concat([]cli.Flag{
			&cli.StringFlag{
				Name: "app-mode",
				Usage: fmt.Sprintf(`%s
				Specifies the proxy mode.
				Note that 'socks5' and 'tun' modes are currently experimental.
				(default: %q)`,
					enumUsage(availableAppModeValues),
					defaultCfg.App.Mode.String(),
				),
				OnlyOnce:  true,
				Validator: checkAppMode,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					mode := MustParseServerModeType(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.App.Mode = mode
					})
					return nil
				},
			},

			&cli.BoolFlag{
				Name: "clean",
				Usage: `
				if set, all configuration files will be ignored (default: false)`,
				OnlyOnce: true,
			},

			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage: `
				Custom location of the config file to load. Options given through the command 
				line flags will override the options set in this file.`,
				OnlyOnce: true,
				Sources:  cli.EnvVars("SPOOFDPI_CONFIG"),
			},

			&cli.Int64Flag{
				Name: "hop-count-default",
				Usage: fmt.Sprintf(`
				Hop count to the server assumed until it is learned. Fake packets
				are sent with a TTL of the hop count minus 1. (default: %v)`,
					defaultCfg.Conn.HopCountDefault,
				),
				OnlyOnce:  true,
				Validator: checkUint8NonZero,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					n := uint8(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Conn.HopCountDefault = n
					})
					return nil
				},
			},

			// Deprecated name of --hop-count-default.
			&cli.Int64Flag{
				Name:      "default-fake-ttl",
				Hidden:    true,
				OnlyOnce:  true,
				Validator: checkUint8NonZero,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					AddWarnMsg("'--default-fake-ttl' is deprecated; use '--hop-count-default'")
					n := uint8(v)
					deprecatedOverrides = append(deprecatedOverrides, func(cfg *Config) {
						cfg.Conn.HopCountDefault = n
					})
					return nil
				},
			},

			&cli.Int64Flag{
				Name: "hop-count-min",
				Usage: fmt.Sprintf(`
				Lower bound of the hop count used for fake packets. (default: %v)`,
					defaultCfg.Conn.HopCountMin,
				),
				OnlyOnce:  true,
				Validator: checkUint8,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					n := uint8(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Conn.HopCountMin = n
					})
					return nil
				},
			},

			&cli.Int64Flag{
				Name: "hop-count-max",
				Usage: fmt.Sprintf(`
				Upper bound of the hop count used for fake packets. (default: %v)`,
					defaultCfg.Conn.HopCountMax,
				),
				OnlyOnce:  true,
				Validator: checkUint8NonZero,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					n := uint8(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Conn.HopCountMax = n
					})
					return nil
				},
			},

			&cli.Int64Flag{
				Name: "hop-count-offset",
				Usage: fmt.Sprintf(`
				Added to a learned hop count to correct estimation errors; use
				'--hop-count-offset=-N' for negative values. (default: %v)`,
					defaultCfg.Conn.HopCountOffset,
				),
				OnlyOnce:  true,
				Validator: checkInt8,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					n := int8(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Conn.HopCountOffset = n
					})
					return nil
				},
			},

			&cli.StringFlag{
				Name: "dns-addr",
				Usage: fmt.Sprintf(`<ip:port>
				Upstream DNS server address for standard UDP queries. (default: %v)`,
					defaultCfg.DNS.Addr.String(),
				),
				OnlyOnce:  true,
				Validator: checkHostPort,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					addr := MustParseTCPAddr(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.DNS.Addr = addr
					})
					return nil
				},
			},

			&cli.BoolFlag{
				Name: "dns-cache",
				Usage: fmt.Sprintf(`
				If set, DNS records will be cached. (default: %v)`,
					defaultCfg.DNS.Cache,
				),
				Value:    false,
				OnlyOnce: true,
				Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
					cache := v
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.DNS.Cache = cache
					})
					return nil
				},
			},

			&cli.StringFlag{
				Name: "dns-mode",
				Usage: fmt.Sprintf(`%s
				Default resolution mode for domains that do not match any specific rule.
				(default: %q)`,
					enumUsage(availableDNSModeValues),
					defaultCfg.DNS.Mode.String(),
				),
				Value:     "udp",
				OnlyOnce:  true,
				Validator: checkDNSMode,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					mode := MustParseDNSModeType(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.DNS.Mode = mode
					})
					return nil
				},
			},

			&cli.StringFlag{
				Name: "dns-https-url",
				Usage: fmt.Sprintf(`<https_url>
				Endpoint URL for DNS over HTTPS (DoH) queries. 
				(default: %q)`,
					defaultCfg.DNS.HTTPSURL,
				),
				Value:     "https://dns.google/dns-query",
				OnlyOnce:  true,
				Validator: checkHTTPSEndpoint,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					url := v
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.DNS.HTTPSURL = url
					})
					return nil
				},
			},

			&cli.StringFlag{
				Name: "dns-qtype",
				Usage: fmt.Sprintf(`%s
				Filters DNS queries by record type (A for IPv4, AAAA for IPv6).
				(default: %q)`,
					enumUsage(availableDNSQueryValues),
					defaultCfg.DNS.QType.String(),
				),
				Value:     "ipv4",
				OnlyOnce:  true,
				Validator: checkDNSQueryType,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					qtype := MustParseDNSQueryType(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.DNS.QType = qtype
					})
					return nil
				},
			},

			&cli.Int64Flag{
				Name: "dns-timeout",
				Usage: fmt.Sprintf(`
				Timeout for dns connection in milliseconds. 
				No effect when the value is 0 (default: %v, max: %v)`,
					defaultCfg.Conn.DNSTimeout.Milliseconds(),
					math.MaxUint16,
				),
				Value:     0,
				OnlyOnce:  true,
				Validator: checkUint16,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					dur := time.Duration(v * int64(time.Millisecond))
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Conn.DNSTimeout = dur
					})
					return nil
				},
			},
		},
			tlsFlags("tls-", false, defaultCfg, &cliOverrides),
			tlsFlags("https-", true, defaultCfg, &deprecatedOverrides),
			[]cli.Flag{
				&cli.Int64Flag{
					Name: "udp-fake-count",
					Usage: fmt.Sprintf(`
				Number of fake packets to be sent. (default: %v)`,
						defaultCfg.UDP.FakeCount,
					),
					Value:     0,
					OnlyOnce:  true,
					Validator: int64Range(0, math.MaxUint8),
					Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
						n := uint8(v)
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.UDP.FakeCount = n
						})
						return nil
					},
				},

				&cli.StringFlag{
					Name: "udp-fake-packet",
					Usage: `<byte_array>
				Comma-separated hexadecimal byte array used for fake packet. 
				(default: built-in fake packet)`,
					Value:     MustParseHexCSV(defaultCfg.UDP.FakePacket),
					OnlyOnce:  true,
					Validator: checkHexBytesStr,
					Action: func(ctx context.Context, cmd *cli.Command, v string) error {
						pkt := MustParseBytes(v)
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.UDP.FakePacket = pkt
						})
						return nil
					},
				},

				&cli.BoolFlag{
					Name: "udp-skip",
					Usage: fmt.Sprintf(`
				If set, UDP traffic will be processed without any DPI bypass techniques.
				(default: %v)`,
						defaultCfg.UDP.Skip,
					),
					OnlyOnce: true,
					Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
						skip := v
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.UDP.Skip = skip
						})
						return nil
					},
				},

				&cli.Int64Flag{
					Name: "udp-idle-timeout",
					Usage: fmt.Sprintf(`
				Idle timeout for udp connection in milliseconds. 
				No effect when the value is 0 (default: %v, max: %v)`,
						defaultCfg.Conn.UDPIdleTimeout.Milliseconds(),
						math.MaxUint16,
					),
					Value:     0,
					OnlyOnce:  true,
					Validator: checkUint16,
					Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
						dur := time.Duration(v * int64(time.Millisecond))
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.Conn.UDPIdleTimeout = dur
						})
						return nil
					},
				},

				&cli.StringFlag{
					Name: "listen-addr",
					Usage: `
				IP address to listen on (default: 127.0.0.1:8080 for http, or 127.0.0.1:1080 for socks5)`,
					OnlyOnce:  true,
					Validator: checkHostPort,
					Action: func(ctx context.Context, cmd *cli.Command, v string) error {
						if v == "" {
							return nil
						}
						addr := MustParseTCPAddr(v)
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.App.ListenAddr = addr
						})
						return nil
					},
				},

				&cli.StringFlag{
					Name: "gateway",
					Usage: `
				IPv4 address of the default gateway, skipping automatic discovery.
				Only used with fake packets or tun mode (default: auto-detect)`,
					OnlyOnce:  true,
					Validator: checkGateway,
					Action: func(ctx context.Context, cmd *cli.Command, v string) error {
						gateway := MustParseIPv4(v)
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.App.Gateway = gateway
						})
						return nil
					},
				},

				&cli.StringFlag{
					Name: "log-level",
					Usage: `
				Set log level (default: "info")`,
					OnlyOnce:  true,
					Validator: checkLogLevel,
					Action: func(ctx context.Context, cmd *cli.Command, v string) error {
						level := MustParseLogLevel(v)
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.App.LogLevel = level
						})
						return nil
					},
				},

				&cli.BoolFlag{
					Name: "no-tui",
					Usage: fmt.Sprintf(`
				Disable TUI and run in headless mode. (default: %v)`,
						defaultCfg.App.NoTUI,
					),
					OnlyOnce: true,
					Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
						noTUI := v
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.App.NoTUI = noTUI
						})
						return nil
					},
				},

				&cli.BoolFlag{
					Name: "auto-configure-network",
					Usage: fmt.Sprintf(`
				Automatically set system-wide proxy configuration (default: %v)`,
						defaultCfg.App.AutoConfigureNetwork,
					),
					OnlyOnce: true,
					Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
						auto := v
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.App.AutoConfigureNetwork = auto
						})
						return nil
					},
				},

				&cli.Int64Flag{
					Name: "tcp-timeout",
					Usage: fmt.Sprintf(`
				Timeout for tcp connection in milliseconds. 
				No effect when the value is 0 (default: %v, max: %v)`,
						defaultCfg.Conn.TCPTimeout.Milliseconds(),
						math.MaxUint16,
					),
					Value:     0,
					OnlyOnce:  true,
					Validator: checkUint16,
					Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
						dur := time.Duration(v * int64(time.Millisecond))
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.Conn.TCPTimeout = dur
						})
						return nil
					},
				},

				&cli.Int64Flag{
					Name: "freebsd-fib",
					Usage: fmt.Sprintf(`
				FIB ID for FreeBSD routing table (1-15). (default: %v)`,
						1,
					),
					Value:     1,
					OnlyOnce:  true,
					Validator: checkFreeBSDFibID,
					Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
						fib := int(v)
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.App.FreebsdFIB = fib
						})
						return nil
					},
				},

				&cli.BoolFlag{
					Name: "version",
					Usage: `
				Print version; this may contain some other relevant information`,
					Aliases:  []string{"v"},
					OnlyOnce: true,
				},
			}),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Bool("version") {
				fmt.Printf("spoofdpi %s %s (%s)\n", version, commit, build)
				fmt.Println("Official docs at https://spoofdpi.xvzc.dev")
				os.Exit(0)
			}

			cfg, configDir, err := Load(cmd, slices.Concat(deprecatedOverrides, cliOverrides))
			if err != nil {
				return err
			}

			return runFunc(ctx, configDir, cfg)
		},
	}

	cli.HelpFlag = &cli.BoolFlag{
		Name:    "help",
		Aliases: []string{"h"},
		Usage: `
        show help`,
	}

	return cmd
}

// enumUsage renders the accepted values of an enum flag as a usage hint,
// e.g. <"udp"|"https"|"system">. It is derived from the same slice the
// flag's validator checks against, so the help text cannot drift away from
// what the flag actually accepts.
func enumUsage(values []string) string {
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return "<" + strings.Join(quoted, "|") + ">"
}

func determineRealHome() string {
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" {
		u, err := user.Lookup(sudoUser)
		if err == nil {
			return u.HomeDir
		}
	}

	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	return u.HomeDir
}

func createHelpTemplate() string {
	return fmt.Sprintf(`DESCRIPTION:
  %s{{if .Copyright }}
COPYRIGHT:
  {{.Copyright}}{{end}}
USAGE:
  %s {{if .Flags}}%s{{end}}{{if .Commands}}
GLOBAL OPTIONS:
  {{range .VisibleFlags}}%s{{if .Aliases}}{{range .Aliases}}%s{{end}}{{end}} %s %s %s
	{{end}}{{end}}
	`,
		"{{.Name}} - {{.Description}}",
		"{{.Name}}", // spoofdpi
		"[global options]",
		"--{{.Name}}", // --option
		", -{{.}}",    // -o
		"{{.TypeName}}",
		"{{.Usage}}",
		"{{.DefaultText}}",
	)
}

// tlsFlags builds the flags for the [tls] section, named prefix+<option>.
// The deprecated --https-* names are built from the same definitions with
// deprecated set: they are hidden from the help, warn when used, and their
// overrides go to a separate list that Load applies before the --tls-*
// ones, so --tls-* wins when both are given.
func tlsFlags(
	prefix string,
	deprecated bool,
	defaultCfg *Config,
	overrides *[]func(*Config),
) []cli.Flag {
	add := func(name string, fn func(*Config)) {
		if deprecated {
			AddWarnMsg(fmt.Sprintf(
				"'--%s' is deprecated; use '--tls-%s'",
				name,
				strings.TrimPrefix(name, prefix),
			))
		}
		*overrides = append(*overrides, fn)
	}

	flags := []cli.Flag{
		&cli.Int64Flag{
			Name:   prefix + "fake-count",
			Hidden: deprecated,
			Usage: fmt.Sprintf(`
				Number of fake packets to be sent before the Client Hello.
				Requires 'tls-chunk-size' > 0 for fragmentation. (default: %v)`,
				defaultCfg.HTTPS.FakeCount,
			),
			Value:     0,
			OnlyOnce:  true,
			Validator: checkUint8,
			Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
				n := uint8(v)
				add(prefix+"fake-count", func(cfg *Config) {
					cfg.HTTPS.FakeCount = n
				})
				return nil
			},
		},

		&cli.StringFlag{
			Name:   prefix + "fake-packet",
			Hidden: deprecated,
			Usage: `<byte_array>
				Comma-separated hexadecimal byte array used for fake Client Hello. 
				(default: built-in fake packet)`,
			Value:     MustParseHexCSV([]byte(FakeClientHello)),
			OnlyOnce:  true,
			Validator: checkHexBytesStr,
			Action: func(ctx context.Context, cmd *cli.Command, v string) error {
				pkt := proto.NewFakeTLSMessage(MustParseBytes(v))
				add(prefix+"fake-packet", func(cfg *Config) {
					cfg.HTTPS.FakePacket = pkt
				})
				return nil
			},
		},

		&cli.BoolFlag{
			Name:   prefix + "disorder",
			Hidden: deprecated,
			Usage: fmt.Sprintf(`
				If set, sends fragmented Client Hello packets out-of-order. (default: %v)`,
				defaultCfg.HTTPS.Disorder,
			),
			OnlyOnce: true,
			Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
				disorder := v
				add(prefix+"disorder", func(cfg *Config) {
					cfg.HTTPS.Disorder = disorder
				})
				return nil
			},
		},

		&cli.StringFlag{
			Name:   prefix + "split-mode",
			Hidden: deprecated,
			Usage: fmt.Sprintf(`%s
				Specifies the default packet fragmentation strategy to use. (default: %q)`,
				enumUsage(availableHTTPSModeValues),
				defaultCfg.HTTPS.SplitMode.String(),
			),
			Value:     "chunk",
			OnlyOnce:  true,
			Validator: checkHTTPSSplitMode,
			Action: func(ctx context.Context, cmd *cli.Command, v string) error {
				mode := mustParseHTTPSSplitModeType(v)
				add(prefix+"split-mode", func(cfg *Config) {
					cfg.HTTPS.SplitMode = mode
				})
				return nil
			},
		},

		&cli.BoolFlag{
			Name:   prefix + "skip",
			Hidden: deprecated,
			Usage: fmt.Sprintf(`
				If set, TLS traffic will be processed without any DPI bypass techniques. 
				(default: %v)`,
				defaultCfg.HTTPS.Skip,
			),
			OnlyOnce: true,
			Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
				skip := v
				add(prefix+"skip", func(cfg *Config) {
					cfg.HTTPS.Skip = skip
				})
				return nil
			},
		},

		&cli.Int64Flag{
			Name:   prefix + "chunk-size",
			Hidden: deprecated,
			Usage: fmt.Sprintf(`
				The chunk size (in bytes) for packet fragmentation. This value is only applied 
				when 'tls-split-mode' is 'chunk'. While setting the size to '0' internally 
				disables fragmentation (to avoid division-by-zero errors), you should set 
				'tls-split-mode' to 'none' to disable the feature cleanly.
				(default: %v, max: %v)`,
				defaultCfg.HTTPS.ChunkSize,
				math.MaxUint8,
			),
			OnlyOnce:  true,
			Validator: checkUint8NonZero,
			Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
				sz := uint8(v)
				add(prefix+"chunk-size", func(cfg *Config) {
					cfg.HTTPS.ChunkSize = sz
				})
				return nil
			},
		},
	}

	// Options added after the rename have no deprecated --https-* name.
	if deprecated {
		return flags
	}

	return append(flags,
		&cli.StringFlag{
			Name: prefix + "fake-seq",
			Usage: fmt.Sprintf(`<"rand"|"offset:N">
				Sequence number of fake packets. 'offset:N' adds N to the
				connection's real number; 'rand' picks one per connection.
				(default: %q)`,
				defaultCfg.HTTPS.FakeSeq.String(),
			),
			OnlyOnce:  true,
			Validator: checkSeqMode,
			Action: func(ctx context.Context, cmd *cli.Command, v string) error {
				mode := mustParseSeqMode(v)
				add(prefix+"fake-seq", func(cfg *Config) {
					cfg.HTTPS.FakeSeq = mode
				})
				return nil
			},
		},

		&cli.StringFlag{
			Name: prefix + "fake-ack",
			Usage: fmt.Sprintf(`<"rand"|"offset:N">
				Acknowledgment number of fake packets, set like 'tls-fake-seq'.
				(default: %q)`,
				defaultCfg.HTTPS.FakeAck.String(),
			),
			OnlyOnce:  true,
			Validator: checkSeqMode,
			Action: func(ctx context.Context, cmd *cli.Command, v string) error {
				mode := mustParseSeqMode(v)
				add(prefix+"fake-ack", func(cfg *Config) {
					cfg.HTTPS.FakeAck = mode
				})
				return nil
			},
		},

		&cli.Int64Flag{
			Name: prefix + "syn-ack-timeout",
			Usage: fmt.Sprintf(`
				Maximum time in milliseconds to wait for the server's SYN/ACK
				to learn sequence numbers and the hop count before sending
				fake packets. 0 disables waiting. (default: %v, max: %v)`,
				defaultCfg.HTTPS.SynAckTimeout.Milliseconds(),
				math.MaxUint16,
			),
			OnlyOnce:  true,
			Validator: checkUint16,
			Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
				dur := time.Duration(v) * time.Millisecond
				add(prefix+"syn-ack-timeout", func(cfg *Config) {
					cfg.HTTPS.SynAckTimeout = dur
				})
				return nil
			},
		},
	)
}
