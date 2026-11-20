package livetest

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/urfave/cli/v3"
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

// NewCommand returns the livetest command. executable returns the spoofdpi
// binary each case runs, normally the running binary itself. caseFlags are
// the server flags a case may set.
func NewCommand(executable func() (string, error), caseFlags CaseFlags) *cli.Command {
	return newCommand(executable, caseFlags, os.Stderr)
}

// newCommand is NewCommand with the writer for progress and warnings.
func newCommand(
	executable func() (string, error),
	caseFlags CaseFlags,
	stderr io.Writer,
) *cli.Command {
	return &cli.Command{
		Name:  "livetest",
		Usage: "Test DPI-bypass options against real sites",
		Description: `Runs spoofdpi once per case, sends requests to every --url through it,
  and reports how many succeed. The baseline case ("config") runs first
  with your config file; each --add adds a case.
  --add takes "label:NAME, ARGS" or "ARGS". The label ends at the first
  comma; ARGS are split on white space and quotes are not interpreted.
  Flags in ARGS that livetest sets itself, such as --config, unknown flags
  and arguments that are not option values are ignored with a warning.`,
		CustomRootCommandHelpTemplate: helpTemplate,
		ErrWriter:                     io.Discard,
		OnUsageError: func(ctx context.Context, cmd *cli.Command, err error, sub bool) error {
			return err
		},
		// Commas in an --add value belong to spoofdpi's arguments.
		DisableSliceFlagSeparator: true,
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:  "add",
				Usage: `case to test, as "label:NAME, ARGS" or "ARGS" (repeatable, run in order)`,
			},
			&cli.StringSliceFlag{
				Name:      "url",
				Usage:     "http or https URL to request through spoofdpi (repeatable, at least one)",
				Validator: checkURLs,
			},
			&cli.IntFlag{
				Name:     "tries",
				Usage:    "requests per URL and case",
				Value:    10,
				OnlyOnce: true,
			},
			&cli.DurationFlag{
				Name:     "timeout",
				Usage:    "timeout of each request",
				Value:    10 * time.Second,
				OnlyOnce: true,
			},
			&cli.DurationFlag{
				Name:     "start-timeout",
				Usage:    "time to wait for spoofdpi to start",
				Value:    time.Minute,
				OnlyOnce: true,
			},
			&cli.StringFlag{
				Name:     "mode",
				Usage:    `proxy mode spoofdpi runs in: "http" or "socks5"`,
				Value:    "http",
				OnlyOnce: true,
			},
			&cli.StringFlag{
				Name:      "listen",
				Usage:     "ip:port address spoofdpi listens on",
				Value:     "127.0.0.1:18080",
				OnlyOnce:  true,
				Validator: checkListen,
			},
			&cli.StringFlag{
				Name: "config",
				Usage: "spoofdpi config file for every case " +
					"(default: the baseline searches the default locations; other cases use --clean)",
				OnlyOnce:  true,
				Validator: checkConfigFile,
			},
			&cli.StringFlag{
				Name:     "user-agent",
				Usage:    "User-Agent header of each request (must not be empty)",
				Value:    DefaultUserAgent,
				OnlyOnce: true,
			},
			&cli.StringFlag{
				Name:     "out",
				Usage:    "directory to write each case's log to, as <label>.log (default: no logs)",
				OnlyOnce: true,
			},
			&cli.BoolFlag{
				Name:     "no-baseline",
				Usage:    `skip the baseline case ("config")`,
				OnlyOnce: true,
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.Args().Present() {
				return fmt.Errorf("unexpected arguments: %q", cmd.Args().Slice())
			}
			bin, err := executable()
			if err != nil {
				return fmt.Errorf("find the spoofdpi executable: %w", err)
			}
			opts := Options{
				Bin:          bin,
				URLs:         cmd.StringSlice("url"),
				Adds:         cmd.StringSlice("add"),
				NoBaseline:   cmd.Bool("no-baseline"),
				Tries:        cmd.Int("tries"),
				Timeout:      cmd.Duration("timeout"),
				StartTimeout: cmd.Duration("start-timeout"),
				Mode:         cmd.String("mode"),
				Listen:       cmd.String("listen"),
				Config:       cmd.String("config"),
				CaseFlags:    caseFlags,
				UserAgent:    cmd.String("user-agent"),
				OutDir:       cmd.String("out"),
			}
			return Run(ctx, opts, cmd.Root().Writer, stderr)
		},
	}
}
