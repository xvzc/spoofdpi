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
	"time"

	"github.com/rs/zerolog"
	"github.com/urfave/cli/v3"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// DefaultConfig returns a fully-populated Config with default values for
// every field. Used as the starting point of the load pipeline
// (defaults → TOML → CLI → Finalize → Validate). Tests that need a
// single section (e.g. base RuntimeConfig for resolveRules) reach in
// via DefaultConfig().Runtime / .Startup.
func DefaultConfig() *Config { //exhaustruct:enforce
	return &Config{
		WarnMsgs: nil,
		Startup: StartupConfig{ //exhaustruct:enforce
			App: AppOptions{ //exhaustruct:enforce
				NoTUI:                false,
				LogLevel:             zerolog.InfoLevel,
				Silent:               false,
				AutoConfigureNetwork: false,
				Mode:                 AppModeHTTP,
				ListenAddr:           net.TCPAddr{},
				FreebsdFIB:           1,
			},
			Rules: nil,
		},
		Runtime: RuntimeConfig{ //exhaustruct:enforce
			Conn: ConnOptions{ //exhaustruct:enforce
				DefaultFakeTTL: 8,
				DNSTimeout:     5000 * time.Millisecond,
				TCPTimeout:     10000 * time.Millisecond,
				UDPIdleTimeout: 25000 * time.Millisecond,
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
				SplitMode:          HTTPSSplitModeSNI,
				ChunkSize:          35,
				CustomSegmentPlans: nil,
				Skip:               false,
			},
			UDP: UDPOptions{ //exhaustruct:enforce
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
	defaultCfg := DefaultConfig()

	cmd := &cli.Command{
		Name:        "spoofdpi",
		Description: "Simple and fast anti-censorship tool to bypass DPI",
		Copyright:   "Apache License, Version 2.0, January 2004",
		ErrWriter:   io.Discard,
		OnUsageError: func(ctx context.Context, cmd *cli.Command, err error, sub bool) error {
			return err
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name: "app-mode",
				Usage: fmt.Sprintf(`<"http"|"socks5"|"tun">
				Specifies the proxy mode.
				Note that 'socks5' and 'tun' modes are currently experimental.
				(default: %q)`,
					defaultCfg.Startup.App.Mode.String(),
				),
				OnlyOnce:  true,
				Validator: checkAppMode,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					mode := MustParseServerModeType(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Startup.App.Mode = mode
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
				Name: "default-fake-ttl",
				Usage: fmt.Sprintf(`
				Default TTL value for fake packets. (default: %v)`,
					defaultCfg.Runtime.Conn.DefaultFakeTTL,
				),
				OnlyOnce:  true,
				Validator: checkUint8NonZero,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					ttl := uint8(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.Conn.DefaultFakeTTL = ttl
					})
					return nil
				},
			},

			&cli.StringFlag{
				Name: "dns-addr",
				Usage: fmt.Sprintf(`<ip:port>
				Upstream DNS server address for standard UDP queries. (default: %v)`,
					defaultCfg.Runtime.DNS.Addr.String(),
				),
				OnlyOnce:  true,
				Validator: checkHostPort,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					addr := MustParseTCPAddr(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.DNS.Addr = addr
					})
					return nil
				},
			},

			&cli.BoolFlag{
				Name: "dns-cache",
				Usage: fmt.Sprintf(`
				If set, DNS records will be cached. (default: %v)`,
					defaultCfg.Runtime.DNS.Cache,
				),
				Value:    false,
				OnlyOnce: true,
				Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
					cache := v
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.DNS.Cache = cache
					})
					return nil
				},
			},

			&cli.StringFlag{
				Name: "dns-mode",
				Usage: fmt.Sprintf(`<"udp"|"doh"|"sys">
				Default resolution mode for domains that do not match any specific rule.
				(default: %q)`,
					defaultCfg.Runtime.DNS.Mode.String(),
				),
				Value:     "udp",
				OnlyOnce:  true,
				Validator: checkDNSMode,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					mode := MustParseDNSModeType(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.DNS.Mode = mode
					})
					return nil
				},
			},

			&cli.StringFlag{
				Name: "dns-https-url",
				Usage: fmt.Sprintf(`<https_url>
				Endpoint URL for DNS over HTTPS (DoH) queries. 
				(default: %q)`,
					defaultCfg.Runtime.DNS.HTTPSURL,
				),
				Value:     "https://dns.google/dns-query",
				OnlyOnce:  true,
				Validator: checkHTTPSEndpoint,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					url := v
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.DNS.HTTPSURL = url
					})
					return nil
				},
			},

			&cli.StringFlag{
				Name: "dns-qtype",
				Usage: fmt.Sprintf(`<"ipv4"|"ipv6"|"all">
				Filters DNS queries by record type (A for IPv4, AAAA for IPv6).
				(default: %q)`,
					defaultCfg.Runtime.DNS.QType.String(),
				),
				Value:     "ipv4",
				OnlyOnce:  true,
				Validator: checkDNSQueryType,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					qtype := MustParseDNSQueryType(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.DNS.QType = qtype
					})
					return nil
				},
			},

			&cli.Int64Flag{
				Name: "dns-timeout",
				Usage: fmt.Sprintf(`
				Timeout for dns connection in milliseconds. 
				No effect when the value is 0 (default: %v, max: %v)`,
					defaultCfg.Runtime.Conn.DNSTimeout.Milliseconds(),
					math.MaxUint16,
				),
				Value:     0,
				OnlyOnce:  true,
				Validator: checkUint16,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					dur := time.Duration(v * int64(time.Millisecond))
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.Conn.DNSTimeout = dur
					})
					return nil
				},
			},

			&cli.Int64Flag{
				Name: "https-fake-count",
				Usage: fmt.Sprintf(`
				Number of fake packets to be sent before the Client Hello.
				Requires 'https-chunk-size' > 0 for fragmentation. (default: %v)`,
					defaultCfg.Runtime.HTTPS.FakeCount,
				),
				Value:     0,
				OnlyOnce:  true,
				Validator: checkUint8,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					n := uint8(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.HTTPS.FakeCount = n
					})
					return nil
				},
			},

			&cli.StringFlag{
				Name: "https-fake-packet",
				Usage: `<byte_array>
				Comma-separated hexadecimal byte array used for fake Client Hello. 
				(default: built-in fake packet)`,
				Value:     MustParseHexCSV([]byte(FakeClientHello)),
				OnlyOnce:  true,
				Validator: checkHexBytesStr,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					pkt := proto.NewFakeTLSMessage(MustParseBytes(v))
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.HTTPS.FakePacket = pkt
					})
					return nil
				},
			},

			&cli.BoolFlag{
				Name: "https-disorder",
				Usage: fmt.Sprintf(`
				If set, sends fragmented Client Hello packets out-of-order. (default: %v)`,
					defaultCfg.Runtime.HTTPS.Disorder,
				),
				OnlyOnce: true,
				Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
					disorder := v
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.HTTPS.Disorder = disorder
					})
					return nil
				},
			},

			&cli.StringFlag{
				Name: "https-split-mode",
				Usage: fmt.Sprintf(`<"sni"|"random"|"chunk"|"sni"|"custom"|"none">
				Specifies the default packet fragmentation strategy to use. (default: %q)`,
					defaultCfg.Runtime.HTTPS.SplitMode.String(),
				),
				Value:     "chunk",
				OnlyOnce:  true,
				Validator: checkHTTPSSplitMode,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					mode := mustParseHTTPSSplitModeType(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.HTTPS.SplitMode = mode
					})
					return nil
				},
			},

			&cli.BoolFlag{
				Name: "https-skip",
				Usage: fmt.Sprintf(`
				If set, HTTPS traffic will be processed without any DPI bypass techniques. 
				(default: %v)`,
					defaultCfg.Runtime.HTTPS.Skip,
				),
				OnlyOnce: true,
				Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
					skip := v
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.HTTPS.Skip = skip
					})
					return nil
				},
			},

			&cli.Int64Flag{
				Name: "https-chunk-size",
				Usage: fmt.Sprintf(`
				The chunk size (in bytes) for packet fragmentation. This value is only applied 
				when 'https-split-default' is 'chunk'. While setting the size to '0' internally 
				disables fragmentation (to avoid division-by-zero errors), you should set 
				'https-split-default' to 'none' to disable the feature cleanly.
				(default: %v, max: %v)`,
					defaultCfg.Runtime.HTTPS.ChunkSize,
					math.MaxUint8,
				),
				OnlyOnce:  true,
				Validator: checkUint8NonZero,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					sz := uint8(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.HTTPS.ChunkSize = sz
					})
					return nil
				},
			},

			&cli.Int64Flag{
				Name: "udp-fake-count",
				Usage: fmt.Sprintf(`
				Number of fake packets to be sent. (default: %v)`,
					defaultCfg.Runtime.UDP.FakeCount,
				),
				Value:     0,
				OnlyOnce:  true,
				Validator: int64Range(0, math.MaxInt),
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					n := int(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.UDP.FakeCount = n
					})
					return nil
				},
			},

			&cli.StringFlag{
				Name: "udp-fake-packet",
				Usage: `<byte_array>
				Comma-separated hexadecimal byte array used for fake packet. 
				(default: built-in fake packet)`,
				Value:     MustParseHexCSV(defaultCfg.Runtime.UDP.FakePacket),
				OnlyOnce:  true,
				Validator: checkHexBytesStr,
				Action: func(ctx context.Context, cmd *cli.Command, v string) error {
					pkt := MustParseBytes(v)
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.UDP.FakePacket = pkt
					})
					return nil
				},
			},

			&cli.Int64Flag{
				Name: "udp-idle-timeout",
				Usage: fmt.Sprintf(`
				Idle timeout for udp connection in milliseconds. 
				No effect when the value is 0 (default: %v, max: %v)`,
					defaultCfg.Runtime.Conn.UDPIdleTimeout.Milliseconds(),
					math.MaxUint16,
				),
				Value:     0,
				OnlyOnce:  true,
				Validator: checkUint16,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					dur := time.Duration(v * int64(time.Millisecond))
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.Conn.UDPIdleTimeout = dur
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
						cfg.Startup.App.ListenAddr = addr
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
						cfg.Startup.App.LogLevel = level
					})
					return nil
				},
			},

			&cli.BoolFlag{
				Name: "no-tui",
				Usage: fmt.Sprintf(`
				Disable TUI and run in headless mode. (default: %v)`,
					defaultCfg.Startup.App.NoTUI,
				),
				OnlyOnce: true,
				Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
					noTUI := v
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Startup.App.NoTUI = noTUI
					})
					return nil
				},
			},

			&cli.BoolFlag{
				Name: "auto-configure-network",
				Usage: fmt.Sprintf(`
				Automatically set system-wide proxy configuration (default: %v)`,
					defaultCfg.Startup.App.AutoConfigureNetwork,
				),
				OnlyOnce: true,
				Action: func(ctx context.Context, cmd *cli.Command, v bool) error {
					auto := v
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Startup.App.AutoConfigureNetwork = auto
					})
					return nil
				},
			},

			&cli.Int64Flag{
				Name: "tcp-timeout",
				Usage: fmt.Sprintf(`
				Timeout for tcp connection in milliseconds. 
				No effect when the value is 0 (default: %v, max: %v)`,
					defaultCfg.Runtime.Conn.TCPTimeout.Milliseconds(),
					math.MaxUint16,
				),
				Value:     0,
				OnlyOnce:  true,
				Validator: checkUint16,
				Action: func(ctx context.Context, cmd *cli.Command, v int64) error {
					dur := time.Duration(v * int64(time.Millisecond))
					cliOverrides = append(cliOverrides, func(cfg *Config) {
						cfg.Runtime.Conn.TCPTimeout = dur
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
						cfg.Startup.App.FreebsdFIB = fib
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
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Bool("version") {
				fmt.Printf("spoofdpi %s %s (%s)\n", version, commit, build)
				fmt.Println("Official docs at https://spoofdpi.xvzc.dev")
				os.Exit(0)
			}

			cfg, configDir, err := Load(cmd, cliOverrides)
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
