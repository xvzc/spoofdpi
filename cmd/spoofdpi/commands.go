package main

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/livetest"
	"github.com/xvzc/spoofdpi/internal/probe"
)

// serverRunFunc runs the server with a loaded config.
type serverRunFunc = func(ctx context.Context, configDir string, cfg *config.Config) error

// subcommand is a command run as "spoofdpi <name> ...". Only the selected
// command is built, so that the server command's writes to cli's help
// globals do not happen for other commands. livetest builds a server
// command too, only to read its flags, and restores those globals.
type subcommand struct {
	name  string
	usage string
	build func() *cli.Command
	// runsServer is set for the server command, whose errors keep the
	// server's error output.
	runsServer bool
}

// commandRegistry holds the server command, run when no subcommand is
// given, and the subcommands in the order the help lists them.
type commandRegistry struct {
	newServer   func() *cli.Command
	subcommands []subcommand
}

func newCommandRegistry(
	runServer serverRunFunc,
	executable func() (string, error),
) commandRegistry {
	newServer := func() *cli.Command {
		return config.CreateCommand(runServer, version, commit, build)
	}
	return commandRegistry{
		newServer: newServer,
		subcommands: []subcommand{
			{
				name:       "run",
				usage:      "Run the server",
				build:      newServer,
				runsServer: true,
			},
			{
				name:  "livetest",
				usage: "Test DPI-bypass options against real sites",
				build: func() *cli.Command {
					return livetest.NewCommand(executable, livetestCaseFlags(runServer))
				},
			},
			{
				name:  "probe",
				usage: "Measure hop counts and DPI behavior of sites",
				build: probe.NewCommand,
			},
		},
	}
}

// livetestCaseFlags returns the server flags a livetest case may set,
// read from the server command so that new server flags are covered.
func livetestCaseFlags(runServer serverRunFunc) livetest.CaseFlags {
	// CreateCommand sets cli's help globals for the server; keep them as
	// they are for the livetest command.
	helpFlag, helpTemplate := cli.HelpFlag, cli.RootCommandHelpTemplate
	defer func() { cli.HelpFlag, cli.RootCommandHelpTemplate = helpFlag, helpTemplate }()

	server := config.CreateCommand(runServer, version, commit, build)
	// The help flag is added to the server's flags only when it runs.
	flags := append(slices.Clone(server.Flags), cli.HelpFlag)

	serverFlags := make([]livetest.ServerFlag, 0, len(flags))
	for _, f := range flags {
		doc, ok := f.(cli.DocGenerationFlag)
		serverFlags = append(serverFlags, livetest.ServerFlag{
			Names:      f.Names(),
			TakesValue: ok && doc.TakesValue(),
		})
	}
	return livetest.SplitServerFlags(serverFlags)
}

// selectedCommand is the command to run and the arguments to run it with.
type selectedCommand struct {
	cmd        *cli.Command
	args       []string
	runsServer bool
}

// rootHelpArgs are the arguments that, given alone, show the root help.
var rootHelpArgs = []string{"-h", "--help", "help"}

// selectCommand picks the command for the program arguments args. A
// subcommand is selected only when its name is exactly the first argument,
// or the second after "help", which shows its help. The root help is
// selected only when a help option is the only argument. Everything else
// runs the server command with args unchanged.
func (r commandRegistry) selectCommand(args []string) selectedCommand {
	if len(args) == 2 && slices.Contains(rootHelpArgs, args[1]) {
		return selectedCommand{cmd: r.newRootHelp(), args: []string{args[0], "--help"}}
	}
	if len(args) == 3 && args[1] == "help" {
		if sub, ok := r.subcommand(args[2]); ok {
			return sub.selected([]string{sub.name, "--help"})
		}
	}
	if len(args) > 1 {
		if sub, ok := r.subcommand(args[1]); ok {
			// The subcommand name takes the place of the program name,
			// which cli.Command.Run skips.
			return sub.selected(args[1:])
		}
	}
	return selectedCommand{cmd: r.newServer(), args: args, runsServer: true}
}

func (r commandRegistry) subcommand(name string) (subcommand, bool) {
	for _, sub := range r.subcommands {
		if sub.name == name {
			return sub, true
		}
	}
	return subcommand{}, false
}

// selected builds sub to run with args, which start with its name.
func (sub subcommand) selected(args []string) selectedCommand {
	cmd := sub.build()
	cmd.Name = "spoofdpi " + sub.name
	return selectedCommand{cmd: cmd, args: args, runsServer: sub.runsServer}
}

const rootHelpTemplate = `USAGE:
  {{.Name}} [command] [options]
COMMANDS:
%s

Without a command, {{.Name}} runs 'run'.
Run '{{.Name}} help <command>' or '{{.Name}} <command> --help' for the options of a command.
`

// newRootHelp returns a command that shows the subcommands. It does not
// list the server's flags; "spoofdpi run --help" does.
func (r commandRegistry) newRootHelp() *cli.Command {
	return &cli.Command{
		Name:                          "spoofdpi",
		CustomRootCommandHelpTemplate: fmt.Sprintf(rootHelpTemplate, r.commandsHelp()),
		HideHelpCommand:               true,
		ErrWriter:                     io.Discard,
		Action:                        func(ctx context.Context, cmd *cli.Command) error { return nil },
	}
}

// commandsHelp lists the subcommands, one "  name  usage" line each.
func (r commandRegistry) commandsHelp() string {
	width := 0
	for _, sub := range r.subcommands {
		width = max(width, len(sub.name))
	}
	lines := make([]string, len(r.subcommands))
	for i, sub := range r.subcommands {
		lines[i] = fmt.Sprintf("  %-*s  %s", width, sub.name, sub.usage)
	}
	return strings.Join(lines, "\n")
}
