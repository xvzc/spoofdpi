package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v3"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/livetest"
)

func testExecutable() (string, error) { return "/nonexistent/spoofdpi", nil }

// failServer is a server run function for paths that must not start the
// server.
func failServer(t *testing.T) serverRunFunc {
	return func(context.Context, string, *config.Config) error {
		t.Error("the server was started")
		return nil
	}
}

func TestSelectCommand(t *testing.T) {
	tcs := []struct {
		name     string
		args     []string
		wantName string
		wantArgs []string
		server   bool
	}{
		{
			name:     "no args run the server",
			args:     []string{"spoofdpi"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi"},
			server:   true,
		},
		{
			name:     "server flags run the server",
			args:     []string{"spoofdpi", "--tls-fake-stutter", "1"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi", "--tls-fake-stutter", "1"},
			server:   true,
		},
		{
			name:     "run",
			args:     []string{"spoofdpi", "run"},
			wantName: "spoofdpi run",
			wantArgs: []string{"run"},
			server:   true,
		},
		{
			name:     "run with server flags",
			args:     []string{"spoofdpi", "run", "--tls-fake-stutter", "1"},
			wantName: "spoofdpi run",
			wantArgs: []string{"run", "--tls-fake-stutter", "1"},
			server:   true,
		},
		{
			name:     "run after a flag is an argument of the server",
			args:     []string{"spoofdpi", "--tls-fake-stutter", "1", "run"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi", "--tls-fake-stutter", "1", "run"},
			server:   true,
		},
		{
			name:     "--help",
			args:     []string{"spoofdpi", "--help"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi", "--help"},
			server:   false,
		},
		{
			name:     "-h",
			args:     []string{"spoofdpi", "-h"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi", "--help"},
			server:   false,
		},
		{
			name:     "help",
			args:     []string{"spoofdpi", "help"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi", "--help"},
			server:   false,
		},
		{
			name:     "help run",
			args:     []string{"spoofdpi", "help", "run"},
			wantName: "spoofdpi run",
			wantArgs: []string{"run", "--help"},
			server:   true,
		},
		{
			name:     "help livetest",
			args:     []string{"spoofdpi", "help", "livetest"},
			wantName: "spoofdpi livetest",
			wantArgs: []string{"livetest", "--help"},
			server:   false,
		},
		{
			name:     "help with an unknown command is the server's",
			args:     []string{"spoofdpi", "help", "foo"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi", "help", "foo"},
			server:   true,
		},
		{
			name:     "help run with more arguments is the server's",
			args:     []string{"spoofdpi", "help", "run", "x"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi", "help", "run", "x"},
			server:   true,
		},
		{
			name:     "help after a flag is the server's",
			args:     []string{"spoofdpi", "--tls-fake-stutter", "1", "--help"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi", "--tls-fake-stutter", "1", "--help"},
			server:   true,
		},
		{
			name:     "--version",
			args:     []string{"spoofdpi", "--version"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi", "--version"},
			server:   true,
		},
		{
			name:     "unknown command",
			args:     []string{"spoofdpi", "foo"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi", "foo"},
			server:   true,
		},
		{
			name:     "run after --",
			args:     []string{"spoofdpi", "--", "run"},
			wantName: "spoofdpi",
			wantArgs: []string{"spoofdpi", "--", "run"},
			server:   true,
		},
		{
			name:     "livetest",
			args:     []string{"spoofdpi", "livetest", "--url", "x"},
			wantName: "spoofdpi livetest",
			wantArgs: []string{"livetest", "--url", "x"},
			server:   false,
		},
	}

	registry := newCommandRegistry(failServer(t), testExecutable)
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got := registry.selectCommand(tc.args)
			assert.Equal(t, tc.wantName, got.cmd.Name)
			assert.Equal(t, tc.wantArgs, got.args)
			assert.Equal(t, tc.server, got.runsServer)
		})
	}
}

func TestSelectCommand_ServerPathUsesServerCommand(t *testing.T) {
	registry := newCommandRegistry(failServer(t), testExecutable)
	server := config.CreateCommand(failServer(t), version, commit, build)
	for _, args := range [][]string{
		{"spoofdpi"}, {"spoofdpi", "foo"}, {"spoofdpi", "--tls-fake-stutter", "1"},
	} {
		got := registry.selectCommand(args)
		assert.Equal(t, flagNames(server), flagNames(got.cmd), args)
	}
}

func flagNames(cmd *cli.Command) []string {
	var names []string
	for _, f := range cmd.Flags {
		names = append(names, f.Names()...)
	}
	return names
}

// runServerPath runs the program arguments args through selectCommand and
// returns what the server would run with.
func runServerPath(
	t *testing.T,
	args ...string,
) (cfg *config.Config, configDir string, warns []string, err error) {
	t.Helper()
	capture := func(_ context.Context, dir string, c *config.Config) error {
		cfg, configDir = c, dir
		return nil
	}
	selected := newCommandRegistry(capture, testExecutable).selectCommand(args)
	require.True(t, selected.runsServer)
	return runCapturing(t, selected.cmd, selected.args, &cfg, &configDir)
}

// runCapturing runs cmd, resetting the warnings before, and returns the
// warnings it added along with the cfg and configDir the caller captures.
func runCapturing(
	t *testing.T,
	cmd *cli.Command,
	args []string,
	cfg **config.Config,
	configDir *string,
) (*config.Config, string, []string, error) {
	t.Helper()
	config.WarnMsgs = nil
	t.Cleanup(func() { config.WarnMsgs = nil })
	err := cmd.Run(context.Background(), args)
	return *cfg, *configDir, append([]string(nil), config.WarnMsgs...), err
}

func TestBareInvocationEqualsRun(t *testing.T) {
	t.Setenv("SPOOFDPI_CONFIG", "")
	toml := filepath.Join(t.TempDir(), "spoofdpi.toml")
	require.NoError(t, os.WriteFile(toml, []byte("[https]\ndisorder = true\n"), 0o644))

	for _, args := range [][]string{
		{"--tls-fake-stutter", "1", "--clean"},
		{"--https-disorder", "--clean"},
		{"--config", toml},
		{"--default-fake-ttl", "5", "--clean"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			bareCfg, bareDir, bareWarns, err := runServerPath(t,
				append([]string{"spoofdpi"}, args...)...)
			require.NoError(t, err)
			require.NotNil(t, bareCfg)

			runCfg, runDir, runWarns, err := runServerPath(t,
				append([]string{"spoofdpi", "run"}, args...)...)
			require.NoError(t, err)

			// Today's behavior: the server command run directly.
			var directCfg *config.Config
			var directDir string
			capture := func(_ context.Context, dir string, c *config.Config) error {
				directCfg, directDir = c, dir
				return nil
			}
			_, _, directWarns, err := runCapturing(t,
				config.CreateCommand(capture, version, commit, build),
				append([]string{"spoofdpi"}, args...), &directCfg, &directDir)
			require.NoError(t, err)

			assert.Equal(t, directCfg, bareCfg)
			assert.Equal(t, directCfg, runCfg)
			assert.Equal(t, directDir, bareDir)
			assert.Equal(t, directDir, runDir)
			assert.Equal(t, directWarns, bareWarns)
			assert.Equal(t, directWarns, runWarns)
		})
	}

	t.Run("a flag given twice fails like the bare invocation", func(t *testing.T) {
		args := []string{"--tls-fake-stutter", "1", "--tls-fake-stutter", "2", "--clean"}
		_, _, _, bareErr := runServerPath(t, append([]string{"spoofdpi"}, args...)...)
		_, _, _, runErr := runServerPath(t, append([]string{"spoofdpi", "run"}, args...)...)
		require.Error(t, bareErr)
		require.Error(t, runErr)
		assert.Equal(t, bareErr.Error(), runErr.Error())
	})
}

// helpOutput runs the program arguments args, which must not start the
// server, and returns what they print.
func helpOutput(t *testing.T, args ...string) string {
	t.Helper()
	selected := newCommandRegistry(failServer(t), testExecutable).selectCommand(args)
	var out bytes.Buffer
	selected.cmd.Writer = &out
	require.NoError(t, selected.cmd.Run(context.Background(), selected.args))
	return out.String()
}

// serverFlagNames are the flags the server help lists.
func serverFlagNames(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, f := range config.CreateCommand(failServer(t), version, commit, build).VisibleFlags() {
		names = append(names, f.Names()[0])
	}
	require.NotEmpty(t, names)
	return names
}

func TestRootHelp(t *testing.T) {
	want := "USAGE:\n" +
		"  spoofdpi [command] [options]\n" +
		"COMMANDS:\n" +
		"  run       Run the server\n" +
		"  livetest  Test DPI-bypass options against real sites\n" +
		"\n" +
		"Without a command, spoofdpi runs 'run'.\n" +
		"Run 'spoofdpi help <command>' or 'spoofdpi <command> --help' for the options of a command.\n"

	for _, arg := range []string{"--help", "-h", "help"} {
		t.Run(arg, func(t *testing.T) {
			out := helpOutput(t, "spoofdpi", arg)
			assert.Equal(t, want, out)
			for _, name := range serverFlagNames(t) {
				assert.NotContains(t, out, "--"+name)
			}
		})
	}
}

func TestServerHelp(t *testing.T) {
	run := helpOutput(t, "spoofdpi", "run", "--help")
	assert.Contains(t, run, "USAGE:\n  spoofdpi run [global options]\nGLOBAL OPTIONS:\n")
	for _, name := range serverFlagNames(t) {
		assert.Regexp(t, `(?m)^  --`+name+`[ ,]`, run)
	}

	// A help flag after a server flag is the server's detailed help.
	bare := helpOutput(t, "spoofdpi", "--tls-fake-stutter", "1", "--help")
	assert.Contains(t, bare, "USAGE:\n  spoofdpi [global options]\nGLOBAL OPTIONS:\n")
	_, bareFlags, ok := strings.Cut(bare, "GLOBAL OPTIONS:\n")
	require.True(t, ok)
	_, runFlags, ok := strings.Cut(run, "GLOBAL OPTIONS:\n")
	require.True(t, ok)
	assert.Equal(t, bareFlags, runFlags, "run lists the same flags")
}

func TestHelpCommand(t *testing.T) {
	for _, name := range []string{"run", "livetest"} {
		assert.Equal(t,
			helpOutput(t, "spoofdpi", name, "--help"),
			helpOutput(t, "spoofdpi", "help", name),
			name)
	}
}

func TestLivetestHelp(t *testing.T) {
	out := helpOutput(t, "spoofdpi", "livetest", "--help")
	assert.Contains(t, out, "USAGE:\n  spoofdpi livetest [options]\n")
	assert.Contains(t, out, "--url ")
	assert.NotContains(t, out, "--tls-fake-stutter")
}

func TestLivetestCaseFlags(t *testing.T) {
	helpFlag, helpTemplate := cli.HelpFlag, cli.RootCommandHelpTemplate
	flags := livetestCaseFlags(failServer(t))
	assert.Same(t, helpFlag, cli.HelpFlag, "cli's help flag is kept")
	assert.Equal(
		t,
		helpTemplate,
		cli.RootCommandHelpTemplate,
		"cli's help template is kept",
	)

	byName := func(list []livetest.ServerFlag) map[string]livetest.ServerFlag {
		m := map[string]livetest.ServerFlag{}
		for _, f := range list {
			for _, name := range f.Names {
				m[name] = f
			}
		}
		return m
	}
	allowed, reserved := byName(flags.Allowed), byName(flags.Reserved)

	for name, takesValue := range map[string]bool{
		"tls-fake-stutter":    true,
		"tls-fake-seq-offset": true,
		"tls-fake-packet":     true,
		"tls-disorder":        false,
		"https-disorder":      false,
		"tls-fake-count":      true,
		"default-fake-ttl":    true,
		"dns-mode":            true,
	} {
		f, ok := allowed[name]
		if assert.True(t, ok, "%s is allowed", name) {
			assert.Equal(t, takesValue, f.TakesValue, name)
		}
	}
	for name, takesValue := range map[string]bool{
		"no-tui": false, "app-mode": true, "listen-addr": true, "log-level": true,
		"clean": false, "config": true, "c": true, "auto-configure-network": false,
		"help": false, "h": false, "version": false, "v": false,
	} {
		assert.NotContains(t, allowed, name)
		f, ok := reserved[name]
		if assert.True(t, ok, "%s is reserved", name) {
			assert.Equal(t, takesValue, f.TakesValue, name)
		}
	}

	// Every server flag is in one of the lists.
	server := config.CreateCommand(failServer(t), version, commit, build)
	for _, f := range server.Flags {
		for _, name := range f.Names() {
			_, inAllowed := allowed[name]
			_, inReserved := reserved[name]
			assert.True(t, inAllowed != inReserved, name)
		}
	}
}
