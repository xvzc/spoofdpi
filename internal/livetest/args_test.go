package livetest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// testServerFlags mirror the kinds of flags the server command has; the
// real list is checked in cmd/spoofdpi.
var testServerFlags = []ServerFlag{
	{Names: []string{"tls-fake-stutter"}, TakesValue: true},
	{Names: []string{"tls-fake-seq-offset"}, TakesValue: true},
	{Names: []string{"tls-fake-ack-offset"}, TakesValue: true},
	{Names: []string{"tls-fake-packet"}, TakesValue: true},
	{Names: []string{"tls-fake-preflight"}, TakesValue: true},
	{Names: []string{"tls-disorder"}},
	{Names: []string{"https-disorder"}},
	{Names: []string{"no-tui"}},
	{Names: []string{"app-mode"}, TakesValue: true},
	{Names: []string{"listen-addr"}, TakesValue: true},
	{Names: []string{"log-level"}, TakesValue: true},
	{Names: []string{"clean"}},
	{Names: []string{"config", "c"}, TakesValue: true},
	{Names: []string{"auto-configure-network"}},
	{Names: []string{"version", "v"}},
	{Names: []string{"help", "h"}},
}

var testCaseFlags = SplitServerFlags(testServerFlags)

func TestSplitServerFlags(t *testing.T) {
	names := func(flags []ServerFlag) []string {
		var out []string
		for _, f := range flags {
			out = append(out, f.Names[0])
		}
		return out
	}
	assert.Equal(t, []string{
		"tls-fake-stutter", "tls-fake-seq-offset", "tls-fake-ack-offset",
		"tls-fake-packet", "tls-fake-preflight", "tls-disorder", "https-disorder",
	}, names(testCaseFlags.Allowed))
	assert.Equal(t, []string{
		"no-tui", "app-mode", "listen-addr", "log-level", "clean", "config",
		"auto-configure-network", "version", "help",
	}, names(testCaseFlags.Reserved))
}

func TestArgFilter(t *testing.T) {
	tcs := []struct {
		name        string
		args        []string
		wantKept    []string
		wantIgnored []string
	}{
		{
			name:     "allowed flags and values are kept",
			args:     []string{"--tls-fake-stutter", "1", "--tls-disorder"},
			wantKept: []string{"--tls-fake-stutter", "1", "--tls-disorder"},
		},
		{
			name: "a value that starts with '-' is kept",
			args: []string{
				"--tls-fake-seq-offset",
				"-10",
				"--tls-fake-ack-offset",
				"-1073741824",
			},
			wantKept: []string{
				"--tls-fake-seq-offset",
				"-10",
				"--tls-fake-ack-offset",
				"-1073741824",
			},
		},
		{
			name: "single dash and =v forms of allowed flags are kept",
			args: []string{
				"-tls-fake-stutter=1",
				"-tls-disorder",
				"--tls-fake-preflight=2",
			},
			wantKept: []string{
				"-tls-fake-stutter=1",
				"-tls-disorder",
				"--tls-fake-preflight=2",
			},
		},
		{
			name:     "commas in a value are kept",
			args:     []string{"--tls-fake-packet", "0x16,0x03"},
			wantKept: []string{"--tls-fake-packet", "0x16,0x03"},
		},
		{
			name:        "a bool flag does not take the next argument",
			args:        []string{"--tls-disorder", "true", "--tls-fake-stutter", "1"},
			wantKept:    []string{"--tls-disorder", "--tls-fake-stutter", "1"},
			wantIgnored: []string{"argument true"},
		},
		{
			name: "arguments that are not values are dropped",
			args: []string{
				"help",
				"--tls-disorder",
				"-",
				"-5",
				"--tls-fake-stutter",
				"1",
				"--tls-fake-preflight=2",
			},
			wantKept: []string{
				"--tls-disorder",
				"--tls-fake-stutter",
				"1",
				"--tls-fake-preflight=2",
			},
			wantIgnored: []string{"argument help", "argument -", "argument -5"},
		},
		{
			name:     "deprecated flags are kept",
			args:     []string{"--https-disorder"},
			wantKept: []string{"--https-disorder"},
		},
		{
			name:     "unknown flags are dropped without their value",
			args:     []string{"--tsl-fake-stutter", "1", "--nope=2"},
			wantKept: []string{},
			wantIgnored: []string{
				"unknown flag --tsl-fake-stutter", "argument 1", "unknown flag --nope=2",
			},
		},
		{
			name:        "an unknown flag and its would-be value are both dropped",
			args:        []string{"--tsl-x", "help", "--tls-disorder"},
			wantKept:    []string{"--tls-disorder"},
			wantIgnored: []string{"unknown flag --tsl-x", "argument help"},
		},
		{
			name:        "-- is an unknown flag",
			args:        []string{"--", "--tls-disorder"},
			wantKept:    []string{"--tls-disorder"},
			wantIgnored: []string{"unknown flag --"},
		},
		{
			name:        "a reserved flag at the end has no value to drop",
			args:        []string{"--tls-disorder", "--config"},
			wantKept:    []string{"--tls-disorder"},
			wantIgnored: []string{"--config (set by livetest)"},
		},
	}
	filter := newArgFilter(testCaseFlags)
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			kept, ignored := filter.filter(tc.args)
			assert.Equal(t, tc.wantKept, kept)
			assert.Equal(t, tc.wantIgnored, ignored)
		})
	}
}

func TestArgFilter_ReservedFlags(t *testing.T) {
	tcs := []struct {
		args        []string
		wantIgnored string
	}{
		{[]string{"--config", "F"}, "--config F (set by livetest)"},
		{[]string{"-c", "F"}, "-c F (set by livetest)"},
		{[]string{"--config=F"}, "--config=F (set by livetest)"},
		{[]string{"-config", "F"}, "-config F (set by livetest)"},
		{[]string{"-c=F"}, "-c=F (set by livetest)"},
		{[]string{"--log-level", "debug"}, "--log-level debug (set by livetest)"},
		{[]string{"--log-level=info"}, "--log-level=info (set by livetest)"},
		{[]string{"--app-mode", "socks5"}, "--app-mode socks5 (set by livetest)"},
		{[]string{"-app-mode=socks5"}, "-app-mode=socks5 (set by livetest)"},
		{
			[]string{"--listen-addr", "127.0.0.1:1"},
			"--listen-addr 127.0.0.1:1 (set by livetest)",
		},
		{[]string{"--no-tui"}, "--no-tui (set by livetest)"},
		{[]string{"-no-tui=false"}, "-no-tui=false (set by livetest)"},
		{[]string{"--clean"}, "--clean (set by livetest)"},
		{
			[]string{"--auto-configure-network=true"},
			"--auto-configure-network=true (set by livetest)",
		},
		{[]string{"-auto-configure-network"}, "-auto-configure-network (set by livetest)"},
		{[]string{"-v"}, "-v (a case runs the server)"},
		{[]string{"--version"}, "--version (a case runs the server)"},
		{[]string{"--help"}, "--help (a case runs the server)"},
		{[]string{"-h"}, "-h (a case runs the server)"},
	}
	filter := newArgFilter(testCaseFlags)
	for _, tc := range tcs {
		t.Run(tc.wantIgnored, func(t *testing.T) {
			args := append([]string{"--tls-fake-stutter", "1"}, tc.args...)
			args = append(args, "--tls-disorder")
			kept, ignored := filter.filter(args)
			assert.Equal(t, []string{"--tls-fake-stutter", "1", "--tls-disorder"}, kept)
			assert.Equal(t, []string{tc.wantIgnored}, ignored)
		})
	}
}
