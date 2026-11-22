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
				HopCountOffset:  -1,
				TCPTimeout:      10000 * time.Millisecond,
				UDPIdleTimeout:  25000 * time.Millisecond,
			},
			DNS: DNSOptions{ //exhaustruct:enforce
				Mode:     DNSModeUDP,
				Addr:     net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53, Zone: ""},
				HTTPSURL: "https://dns.google/dns-query",
				QType:    DNSQueryIPv4,
				Timeout:  5000 * time.Millisecond,
			},
			HTTPS: HTTPSOptions{ //exhaustruct:enforce
				Disorder:      false,
				FakePreflight: 0,
				FakeStutter:   0,
				FakePacket:    proto.NewFakeTLSMessage([]byte(FakeClientHello)),
				FakeSeqOffset: 0,
				FakeAckOffset: 0,
				FakeBadMD5Sig: false,
				SynAckTimeout: 100 * time.Millisecond,
				SplitMode:     HTTPSSplitModeSNI,
				ChunkSize:     DefaultChunkSize,
				CustomSplit:   nil,
				Skip:          false,
			},
			UDP: UDPOptions{ //exhaustruct:enforce
				Skip:          false,
				FakePreflight: 0,
				FakePacket:    make([]byte, 64),
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
	//
	// TODO(deprecated): remove once no deprecated flag names are left
	// (--https-*, --default-fake-ttl).
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
				are sent with a TTL of the hop count plus --hop-count-offset.
				(default: %v)`,
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
			//
			// TODO(deprecated): renamed to --hop-count-default after v1.6.0;
			// remove with the default-fake-ttl TOML key (types.go).
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
				Added to the hop count, learned or default, to set the TTL of fake
				packets; use '--hop-count-offset=-N' for negative values.
				(default: %v)`,
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

			// Deprecated and ignored: DNS answers are always cached.
			//
			// TODO(deprecated): removed after v1.6.0; remove with the
			// 'cache' key of DNSOptions (types.go).
			&cli.BoolFlag{
				Name:     "dns-cache",
				Hidden:   true,
				OnlyOnce: true,
				Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
					AddWarnMsg(
						"'--dns-cache' is deprecated and ignored; DNS answers are always cached",
					)
					return nil
				},
			},
		},
			DNSFlags(func(apply func(*DNSOptions)) {
				cliOverrides = append(cliOverrides, func(cfg *Config) {
					apply(&cfg.DNS)
				})
			}),
			tlsFlags("tls-", false, defaultCfg, &cliOverrides),
			// TODO(deprecated): --https-* were renamed to --tls-* after
			// v1.6.0; remove with the [https] fallback (config.go), then
			// drop tlsFlags' deprecated parameter.
			tlsFlags("https-", true, defaultCfg, &deprecatedOverrides),
			[]cli.Flag{
				&cli.Int64Flag{
					Name: "udp-fake-preflight",
					Usage: fmt.Sprintf(`
				Number of fake packets to be sent before the first datagram.
				(default: %v)`,
						defaultCfg.UDP.FakePreflight,
					),
					Value:     0,
					OnlyOnce:  true,
					Validator: int64Range(0, math.MaxUint8),
					Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
						n := uint8(v)
						cliOverrides = append(cliOverrides, func(cfg *Config) {
							cfg.UDP.FakePreflight = n
						})
						return nil
					},
				},

				// Deprecated flags renamed after v1.6.0.
				//
				// TODO(deprecated): remove --udp-fake-count and --tls-fake-count
				// with the TOML fallbacks in types.go.
				&cli.Int64Flag{
					Name:      "udp-fake-count",
					Hidden:    true,
					OnlyOnce:  true,
					Validator: int64Range(0, math.MaxUint8),
					Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
						AddWarnMsg("'--udp-fake-count' is deprecated; use '--udp-fake-preflight'")
						n := uint8(v)
						deprecatedOverrides = append(deprecatedOverrides, func(cfg *Config) {
							cfg.UDP.FakePreflight = n
						})
						return nil
					},
				},

				&cli.Int64Flag{
					Name:      "tls-fake-count",
					Hidden:    true,
					OnlyOnce:  true,
					Validator: checkUint8,
					Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
						AddWarnMsg("'--tls-fake-count' is deprecated; use '--tls-fake-preflight'")
						n := uint8(v)
						deprecatedOverrides = append(deprecatedOverrides, func(cfg *Config) {
							cfg.HTTPS.FakePreflight = n
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
				Must be at least 1 (default: %v, max: %v)`,
						defaultCfg.Conn.UDPIdleTimeout.Milliseconds(),
						math.MaxUint16,
					),
					Value:     0,
					OnlyOnce:  true,
					Validator: checkConnTimeout,
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
				Must be at least 1 (default: %v, max: %v)`,
						defaultCfg.Conn.TCPTimeout.Milliseconds(),
						math.MaxUint16,
					),
					Value:     0,
					OnlyOnce:  true,
					Validator: checkConnTimeout,
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

// DNSFlags builds the --dns-addr, --dns-mode, --dns-https-url, --dns-qtype
// and --dns-timeout flags. Each flag the user sets validates its value and
// passes a closure that writes the parsed value to override; the caller
// decides when to run it, e.g. after the TOML is loaded so the flags win.
func DNSFlags(override func(apply func(*DNSOptions))) []cli.Flag {
	defaultDNS := DefaultConfig().DNS

	return []cli.Flag{
		&cli.StringFlag{
			Name: "dns-addr",
			Usage: fmt.Sprintf(`<ip:port>
				Upstream DNS server address for standard UDP queries. (default: %v)`,
				defaultDNS.Addr.String(),
			),
			OnlyOnce:  true,
			Validator: checkHostPort,
			Action: func(ctx context.Context, cmd *cli.Command, v string) error {
				addr := MustParseTCPAddr(v)
				override(func(o *DNSOptions) {
					o.Addr = addr
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
				defaultDNS.Mode.String(),
			),
			Value:     "udp",
			OnlyOnce:  true,
			Validator: checkDNSMode,
			Action: func(ctx context.Context, cmd *cli.Command, v string) error {
				mode := MustParseDNSModeType(v)
				override(func(o *DNSOptions) {
					o.Mode = mode
				})
				return nil
			},
		},

		&cli.StringFlag{
			Name: "dns-https-url",
			Usage: fmt.Sprintf(`<https_url>
				Endpoint URL for DNS over HTTPS (DoH) queries. 
				(default: %q)`,
				defaultDNS.HTTPSURL,
			),
			Value:     "https://dns.google/dns-query",
			OnlyOnce:  true,
			Validator: checkHTTPSEndpoint,
			Action: func(ctx context.Context, cmd *cli.Command, v string) error {
				url := v
				override(func(o *DNSOptions) {
					o.HTTPSURL = url
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
				defaultDNS.QType.String(),
			),
			Value:     "ipv4",
			OnlyOnce:  true,
			Validator: checkDNSQueryType,
			Action: func(ctx context.Context, cmd *cli.Command, v string) error {
				qtype := MustParseDNSQueryType(v)
				override(func(o *DNSOptions) {
					o.QType = qtype
				})
				return nil
			},
		},

		&cli.Int64Flag{
			Name: "dns-timeout",
			Usage: fmt.Sprintf(`
				Timeout for each DNS lookup in milliseconds.
				Must be at least 1 (default: %v, max: %v)`,
				defaultDNS.Timeout.Milliseconds(),
				math.MaxUint16,
			),
			Value:     0,
			OnlyOnce:  true,
			Validator: checkDNSTimeout,
			Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
				dur := time.Duration(v * int64(time.Millisecond))
				override(func(o *DNSOptions) {
					o.Timeout = dur
				})
				return nil
			},
		},
	}
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
	// The deprecated --https-* flags keep the option names they had, so
	// some of them point to a renamed --tls-* flag.
	renamed := map[string]string{
		"fake-count": "fake-preflight",
	}
	add := func(name string, fn func(*Config)) {
		if deprecated {
			opt := strings.TrimPrefix(name, prefix)
			if r, ok := renamed[opt]; ok {
				opt = r
			}
			AddWarnMsg(fmt.Sprintf("'--%s' is deprecated; use '--tls-%s'", name, opt))
		}
		*overrides = append(*overrides, fn)
	}
	preflight := "fake-preflight"
	if deprecated {
		preflight = "fake-count"
	}

	flags := []cli.Flag{
		&cli.Int64Flag{
			Name:   prefix + preflight,
			Hidden: deprecated,
			Usage: fmt.Sprintf(`
				Number of fake packets to be sent before the Client Hello.
				(default: %v)`,
				defaultCfg.HTTPS.FakePreflight,
			),
			Value:     0,
			OnlyOnce:  true,
			Validator: checkUint8,
			Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
				n := uint8(v)
				add(prefix+preflight, func(cfg *Config) {
					cfg.HTTPS.FakePreflight = n
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
				Specifies the default packet fragmentation strategy to use.
				'chunk:N' splits into chunks of N bytes; 'chunk' alone uses %v.
				(default: %q)`,
				enumUsage(availableHTTPSModeValues),
				defaultCfg.HTTPS.ChunkSize,
				defaultCfg.HTTPS.SplitMode.String(),
			),
			Value:     "chunk",
			OnlyOnce:  true,
			Validator: checkHTTPSSplitMode,
			Action: func(ctx context.Context, cmd *cli.Command, v string) error {
				mode, size := mustParseSplitMode(v)
				add(prefix+"split-mode", func(cfg *Config) {
					cfg.HTTPS.SplitMode = mode
					if size > 0 {
						cfg.HTTPS.ChunkSize = size
					}
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
	}

	// Options added after the rename have no deprecated --https-* name.
	if deprecated {
		// --https-chunk-size is no longer supported: chunk sizes are part
		// of --tls-split-mode now. The flag is kept only to warn.
		//
		// TODO(deprecated): remove with the chunk-size warning in types.go.
		return append(flags,
			&cli.Int64Flag{
				Name:     prefix + "chunk-size",
				Hidden:   true,
				OnlyOnce: true,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					AddWarnMsg(
						"'--https-chunk-size' is no longer supported and is ignored; " +
							"use '--tls-split-mode chunk:N'",
					)
					return nil
				},
			},
		)
	}

	return append(flags,
		&cli.Int64Flag{
			Name: prefix + "fake-stutter",
			Usage: fmt.Sprintf(`
				Number of fake segments to be sent before each segment of the
				Client Hello, covering the same bytes. (default: %v)`,
				defaultCfg.HTTPS.FakeStutter,
			),
			OnlyOnce:  true,
			Validator: checkUint8,
			Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
				n := uint8(v)
				add(prefix+"fake-stutter", func(cfg *Config) {
					cfg.HTTPS.FakeStutter = n
				})
				return nil
			},
		},

		&cli.Int64Flag{
			Name: prefix + "fake-seq-offset",
			Usage: fmt.Sprintf(`
				Offset added (mod 2^32) to the connection's real sequence number
				in fake packets. With fake-stutter, keep it 0 and use
				'tls-fake-ack-offset' instead. (default: %v)`,
				defaultCfg.HTTPS.FakeSeqOffset,
			),
			OnlyOnce:  true,
			Validator: checkSeqOffset,
			Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
				add(prefix+"fake-seq-offset", func(cfg *Config) {
					cfg.HTTPS.FakeSeqOffset = v
				})
				return nil
			},
		},

		&cli.Int64Flag{
			Name: prefix + "fake-ack-offset",
			Usage: fmt.Sprintf(`
				Offset added (mod 2^32) to the connection's real acknowledgment
				number in fake packets. (default: %v)`,
				defaultCfg.HTTPS.FakeAckOffset,
			),
			OnlyOnce:  true,
			Validator: checkSeqOffset,
			Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
				add(prefix+"fake-ack-offset", func(cfg *Config) {
					cfg.HTTPS.FakeAckOffset = v
				})
				return nil
			},
		},

		&cli.BoolFlag{
			Name: prefix + "fake-bad-md5sig",
			Usage: fmt.Sprintf(`
				If set, fake packets carry a TCP MD5 signature option with a
				random digest, so that a server they reach may drop them.
				(default: %v)`,
				defaultCfg.HTTPS.FakeBadMD5Sig,
			),
			OnlyOnce: true,
			Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
				add(prefix+"fake-bad-md5sig", func(cfg *Config) {
					cfg.HTTPS.FakeBadMD5Sig = v
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
