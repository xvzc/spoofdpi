package livetest

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAdds(t *testing.T) {
	tcs := []struct {
		name   string
		values []string
		want   []testCase
	}{
		{
			name: "label and args",
			values: []string{
				"label:stutter, --tls-fake-stutter 1  --tls-fake-seq-offset -10",
			},
			want: []testCase{{label: "stutter", args: []string{
				"--tls-fake-stutter", "1", "--tls-fake-seq-offset", "-10",
			}}},
		},
		{
			name:   "label without args",
			values: []string{"label:plain"},
			want:   []testCase{{label: "plain", args: []string{}}},
		},
		{
			name:   "commas after the first are kept",
			values: []string{"label:pkt, --tls-fake-packet 0x16,0x03"},
			want: []testCase{{label: "pkt", args: []string{
				"--tls-fake-packet", "0x16,0x03",
			}}},
		},
		{
			name:   "args without a label keep their commas",
			values: []string{"--tls-fake-packet 0x16,0x03"},
			want: []testCase{{label: "add-1", args: []string{
				"--tls-fake-packet", "0x16,0x03",
			}}},
		},
		{
			name: "automatic labels count every --add",
			values: []string{
				"--tls-fake-stutter 1",
				"label:named, --tls-disorder",
				"--tls-fake-preflight 2",
			},
			want: []testCase{
				{label: "add-1", args: []string{"--tls-fake-stutter", "1"}},
				{label: "named", args: []string{"--tls-disorder"}},
				{label: "add-3", args: []string{"--tls-fake-preflight", "2"}},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAdds(tc.values, newArgFilter(testCaseFlags))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseAdds_Errors(t *testing.T) {
	tcs := []struct {
		name    string
		values  []string
		wantErr string
	}{
		{
			name:    "reserved label",
			values:  []string{"label:config, --x"},
			wantErr: "reserved",
		},
		{name: "empty label", values: []string{"label:, --x"}, wantErr: "label must be"},
		{
			name:    "label with space",
			values:  []string{"label:a b, --x"},
			wantErr: "label must be",
		},
		{
			name:    "label with slash",
			values:  []string{"label:../x, --x"},
			wantErr: "label must be",
		},
		{
			name:    "duplicate label",
			values:  []string{"label:x, --a", "label:x, --b"},
			wantErr: "duplicate label",
		},
		{
			name:    "label taken by an automatic one",
			values:  []string{"--a", "label:add-1, --b"},
			wantErr: "duplicate label",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAdds(tc.values, newArgFilter(testCaseFlags))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestSpoofdpiArgs(t *testing.T) {
	opts := Options{Mode: "http", Listen: "127.0.0.1:18080"}
	common := []string{
		"run", "--no-tui", "--log-level", "debug", "--app-mode", "http",
		"--listen-addr", "127.0.0.1:18080", "--auto-configure-network=false",
	}
	added := testCase{label: "x", args: []string{"--tls-fake-stutter", "1"}}
	baseline := testCase{label: baselineLabel, baseline: true}

	assert.Equal(t,
		append(append([]string{}, common...), "--clean", "--tls-fake-stutter", "1"),
		spoofdpiArgs(opts, added))
	assert.Equal(
		t,
		common,
		spoofdpiArgs(opts, baseline),
		"baseline loads the user's config",
	)

	opts.Config = "my.toml"
	assert.Equal(
		t,
		append(
			append([]string{}, common...),
			"--config",
			"my.toml",
			"--tls-fake-stutter",
			"1",
		),
		spoofdpiArgs(opts, added),
	)
	assert.Equal(t,
		append(append([]string{}, common...), "--config", "my.toml"),
		spoofdpiArgs(opts, baseline))
}

func TestOptionsCases(t *testing.T) {
	valid := func() Options {
		return Options{
			URLs: []string{"https://a/"}, Tries: 1, Timeout: time.Second,
			StartTimeout: time.Second, Mode: "http", UserAgent: "ua",
			Listen: "127.0.0.1:18080", CaseFlags: testCaseFlags,
		}
	}

	cases, err := valid().cases()
	require.NoError(t, err)
	assert.Equal(t, []testCase{{label: "config", baseline: true}}, cases)

	opts := valid()
	opts.Adds = []string{"--tls-disorder"}
	cases, err = opts.cases()
	require.NoError(t, err)
	require.Len(t, cases, 2)
	assert.True(t, cases[0].baseline, "baseline runs first")
	assert.Equal(t, "add-1", cases[1].label)

	opts.NoBaseline = true
	cases, err = opts.cases()
	require.NoError(t, err)
	require.Len(t, cases, 1)
	assert.Equal(t, "add-1", cases[0].label)

	for name, change := range map[string]func(*Options){
		"no url":             func(o *Options) { o.URLs = nil },
		"zero tries":         func(o *Options) { o.Tries = 0 },
		"zero timeout":       func(o *Options) { o.Timeout = 0 },
		"zero start timeout": func(o *Options) { o.StartTimeout = 0 },
		"tun mode":           func(o *Options) { o.Mode = "tun" },
		"nothing to run":     func(o *Options) { o.NoBaseline = true },
		"empty user agent":   func(o *Options) { o.UserAgent = "" },
		"no case flags":      func(o *Options) { o.CaseFlags = CaseFlags{} },
		"bad url":            func(o *Options) { o.URLs = []string{"example.com"} },
		"bad listen":         func(o *Options) { o.Listen = "foo" },
		"missing config":     func(o *Options) { o.Config = "/nonexistent/spoofdpi.toml" },
	} {
		t.Run(name, func(t *testing.T) {
			opts := valid()
			change(&opts)
			_, err := opts.cases()
			assert.Error(t, err)
		})
	}
}

func TestScanLog(t *testing.T) {
	in := strings.Join([]string{
		"\x1b[32mINF\x1b[0m spoofdpi; version=dev",
		"INF 2026-01-01T00:00:00Z abc [app] \x1b[1mloaded config file;\x1b[0m " +
			"\x1b[36mdir=\x1b[0m/home/u/.config/spoofdpi/spoofdpi.toml",
		"WRN something odd",
		"INF server started on 127.0.0.1:18080",
		"ERR failed to dial",
		"WRN again",
	}, "\n")
	var out bytes.Buffer
	started := make(chan struct{})

	stats := scanLog(strings.NewReader(in), &out, started)

	select {
	case <-started:
	default:
		t.Fatal("started was not closed")
	}
	assert.Equal(t, 1, stats.warns, "warnings before the start do not count")
	assert.Equal(t, 1, stats.errs)
	assert.Equal(t, "WRN again", stats.last)
	assert.True(t, stats.configKnown)
	assert.Equal(t, "/home/u/.config/spoofdpi/spoofdpi.toml", stats.config)
	assert.True(
		t,
		strings.HasPrefix(out.String(), "INF spoofdpi; version=dev\n"),
		"color codes stripped",
	)
}

func TestConfigFromLine(t *testing.T) {
	path, ok := configFromLine("WRN 2026 abc [app] config file not found;")
	assert.True(t, ok)
	assert.Empty(t, path)

	path, ok = configFromLine(
		"INF 2026 abc [app] loaded config file; dir=/etc/spoofdpi.toml",
	)
	assert.True(t, ok)
	assert.Equal(t, "/etc/spoofdpi.toml", path)

	path, ok = configFromLine(
		`INF 2026 abc [app] loaded config file; dir="/home/u/my dir/설정.toml"`,
	)
	assert.True(t, ok)
	assert.Equal(t, "/home/u/my dir/설정.toml", path, "quoted values are unquoted")

	_, ok = configFromLine("INF 2026 abc [app] server started on 127.0.0.1:1")
	assert.False(t, ok)
}

func TestResultSummary(t *testing.T) {
	var r result
	r.add(outcome{status: 200})
	r.add(outcome{status: 200})
	r.add(outcome{err: &url.Error{Op: "Get", URL: "u", Err: context.DeadlineExceeded}})
	r.add(outcome{err: syscall.ECONNRESET})
	r.add(outcome{status: 301})

	assert.Equal(t, 3, r.ok)
	assert.Equal(t, "200x2 timeout reset 301", r.summary())
	assert.Equal(t, "error", outcome{err: errors.New("boom")}.label())

	r.caseLabel, r.url = "base", "https://a/"

	var out bytes.Buffer
	require.NoError(t, writeReport(&out, nil, []result{r}, "out/livetest"))
	assert.Contains(t, out.String(), "base")
	assert.Contains(t, out.String(), "3/5")
	assert.Contains(t, out.String(), "logs: out/livetest/<case>.log")
	assert.NotContains(t, out.String(), "baseline config")

	out.Reset()
	require.NoError(t, writeReport(&out, nil, []result{r}, ""))
	assert.NotContains(t, out.String(), "logs:")

	for stats, want := range map[logStats]string{
		{configKnown: true, config: "/etc/spoofdpi.toml"}: "baseline config: /etc/spoofdpi.toml\n",
		{configKnown: true}: "baseline config: none (defaults)\n",
		{}:                  "baseline config: unknown",
	} {
		out.Reset()
		require.NoError(t, writeReport(&out, &stats, []result{r}, ""))
		assert.True(t, strings.HasPrefix(out.String(), want), out.String())
	}
}

// fakeSpoofdpi writes a script that stands in for spoofdpi: it logs its
// arguments, the given config line and that its server started, then waits
// to be stopped.
func fakeSpoofdpi(t *testing.T, configLine string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "spoofdpi")
	script := "#!/bin/sh\n" +
		"echo \"args: $*\"\n" +
		"echo '" + configLine + "'\n" +
		"echo 'WRN warmup'\n" +
		"echo 'INF server started on test'\n" +
		"echo 'WRN after start'\n" +
		"exec sleep 30\n"
	require.NoError(t, os.WriteFile(bin, []byte(script), 0o755))
	return bin
}

// fakeProxy answers every request itself, failing those for fail.test. It
// checks that each request has the User-Agent wantUA.
func fakeProxy(t *testing.T, wantUA string) string {
	t.Helper()
	proxy := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("User-Agent"); got != wantUA {
				t.Errorf("User-Agent = %q, want %q", got, wantUA)
			}
			if r.URL.Host == "fail.test" {
				hj, ok := w.(http.Hijacker)
				if !ok {
					t.Error("response writer is not a hijacker")
					return
				}
				conn, _, err := hj.Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = conn.Close()
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	)
	t.Cleanup(proxy.Close)
	return strings.TrimPrefix(proxy.URL, "http://")
}

func testOptions(bin, listen string) Options {
	return Options{
		Bin:          bin,
		URLs:         []string{"http://ok.test/"},
		Tries:        2,
		Timeout:      5 * time.Second,
		StartTimeout: 10 * time.Second,
		Mode:         "http",
		Listen:       listen,
		CaseFlags:    testCaseFlags,
		UserAgent:    DefaultUserAgent,
	}
}

// TestRun runs the whole flow without a network: the "spoofdpi" binary is
// a script that only logs that it started, and the address it would listen
// on is a local HTTP proxy that answers every request itself.
func TestRun(t *testing.T) {
	bin := fakeSpoofdpi(t, "INF loaded config file; dir=/home/u/spoofdpi.toml")
	outDir := filepath.Join(t.TempDir(), "logs")
	opts := testOptions(bin, fakeProxy(t, DefaultUserAgent))
	opts.URLs = []string{"http://ok.test/", "http://fail.test/"}
	opts.Adds = []string{"label:a, --tls-fake-stutter 1", "--tls-fake-packet 0x16,0x03"}
	opts.OutDir = outDir

	var stdout, stderr bytes.Buffer
	start := time.Now()
	require.NoError(t, Run(context.Background(), opts, &stdout, &stderr), stderr.String())
	assert.Less(
		t,
		time.Since(start),
		20*time.Second,
		"spoofdpi is stopped after each case",
	)

	report := stdout.String()
	assert.True(t,
		strings.HasPrefix(report, "baseline config: /home/u/spoofdpi.toml\n"), report)
	for _, want := range []string{
		"config  ", "a  ", "add-2  ", "http://ok.test/", "2/2", "204x2", "0/2",
		"logs: " + outDir + "/<case>.log",
	} {
		assert.Contains(t, report, want)
	}
	assert.Regexp(t, `(?m)^a\s+http://ok\.test/\s+2/2\s+204x2\s+1\s+0$`, report,
		"only the warning after the start counts")

	progress := stderr.String()
	iConfig := strings.Index(progress, "livetest: case config: ")
	iA := strings.Index(progress, "livetest: case a: ")
	iAdd2 := strings.Index(progress, "livetest: case add-2: ")
	require.True(t, iConfig >= 0 && iA >= 0 && iAdd2 >= 0, progress)
	assert.Less(t, iConfig, iA, "baseline runs first")
	assert.Less(t, iA, iAdd2, "cases run in --add order")

	log := readLog(t, outDir, "config")
	assert.Contains(t, log, "args: run --no-tui ")
	assert.Contains(t, log, "--auto-configure-network=false")
	assert.NotContains(t, log, "--clean", "baseline loads the user's config")

	log = readLog(t, outDir, "a")
	assert.Contains(t, log, "args: run --no-tui ")
	assert.Contains(t, log, "--auto-configure-network=false --clean --tls-fake-stutter 1")

	log = readLog(t, outDir, "add-2")
	assert.Contains(t, log, "--clean --tls-fake-packet 0x16,0x03")
}

func readLog(t *testing.T, dir, label string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, label+".log"))
	require.NoError(t, err)
	return string(b)
}

func TestRun_NoBaselineWithConfig(t *testing.T) {
	bin := fakeSpoofdpi(t, "INF loaded config file; dir=/x.toml")
	outDir := filepath.Join(t.TempDir(), "logs")
	opts := testOptions(bin, fakeProxy(t, DefaultUserAgent))
	opts.Adds = []string{"label:a, --tls-disorder"}
	opts.NoBaseline = true
	opts.Config = filepath.Join(t.TempDir(), "spoofdpi.toml")
	require.NoError(t, os.WriteFile(opts.Config, nil, 0o644))
	opts.OutDir = outDir

	var stdout, stderr bytes.Buffer
	require.NoError(t, Run(context.Background(), opts, &stdout, &stderr), stderr.String())

	assert.NotContains(t, stdout.String(), "baseline config")
	assert.NotContains(t, stderr.String(), "case config:")
	assert.NoFileExists(t, filepath.Join(outDir, "config.log"))
	log := readLog(t, outDir, "a")
	assert.Contains(t, log, "--config "+opts.Config+" --tls-disorder")
	assert.NotContains(t, log, "--clean")
}

func TestRun_NoOutWritesNoLogs(t *testing.T) {
	bin := fakeSpoofdpi(t, "WRN config file not found")
	opts := testOptions(bin, fakeProxy(t, DefaultUserAgent))

	wd := t.TempDir()
	t.Chdir(wd)

	var stdout, stderr bytes.Buffer
	require.NoError(t, Run(context.Background(), opts, &stdout, &stderr), stderr.String())

	assert.True(
		t,
		strings.HasPrefix(
			stdout.String(),
			"baseline config: none (defaults)\n",
		),
		stdout.String(),
	)
	assert.NotContains(t, stdout.String(), "logs:")
	entries, err := os.ReadDir(wd)
	require.NoError(t, err)
	assert.Empty(t, entries, "no log files without --out")
}

func TestRun_SpoofdpiExitsEarly(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "spoofdpi")
	require.NoError(
		t,
		os.WriteFile(bin, []byte("#!/bin/sh\necho 'FTL bad flag'\nexit 1\n"), 0o755),
	)

	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), testOptions(bin, "127.0.0.1:1"), &stdout, &stderr)
	require.NoError(t, err, "a failed case is reported, not fatal")
	assert.Contains(t, stderr.String(), "exited before starting")
	assert.Contains(t, stderr.String(), "FTL bad flag")
}

func TestRun_IgnoredFlagsAreWarnedAndDropped(t *testing.T) {
	bin := fakeSpoofdpi(t, "WRN config file not found")
	outDir := filepath.Join(t.TempDir(), "logs")
	opts := testOptions(bin, fakeProxy(t, DefaultUserAgent))
	opts.NoBaseline = true
	opts.OutDir = outDir
	opts.Adds = []string{
		"label:x, --config /tmp/a -c /tmp/b --log-level=info --tsl-typo --tls-fake-stutter 1",
	}

	var stdout, stderr bytes.Buffer
	require.NoError(t, Run(context.Background(), opts, &stdout, &stderr), stderr.String())

	progress := stderr.String()
	for _, want := range []string{
		`livetest: case "x": ignored --config /tmp/a (set by livetest)`,
		`livetest: case "x": ignored -c /tmp/b (set by livetest)`,
		`livetest: case "x": ignored --log-level=info (set by livetest)`,
		`livetest: case "x": ignored unknown flag --tsl-typo`,
	} {
		assert.Contains(t, progress, want+"\n")
	}
	assert.Less(t,
		strings.Index(progress, "ignored"), strings.Index(progress, "livetest: case x: "),
		"warnings come before the case runs")

	log := readLog(t, outDir, "x")
	assert.Contains(
		t,
		log,
		"--auto-configure-network=false --clean --tls-fake-stutter 1\n",
	)
	for _, dropped := range []string{"/tmp/a", "/tmp/b", "=info", "--tsl-typo"} {
		assert.NotContains(t, log, dropped)
	}
	assert.Contains(t, stdout.String(), "2/2")
}

func TestRun_UserAgent(t *testing.T) {
	bin := fakeSpoofdpi(t, "WRN config file not found")
	opts := testOptions(bin, fakeProxy(t, "foo"))
	opts.UserAgent = "foo"

	var stdout, stderr bytes.Buffer
	require.NoError(t, Run(context.Background(), opts, &stdout, &stderr), stderr.String())
	assert.Contains(t, stdout.String(), "2/2")
}

func TestRun_CannotCreateOut(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(file, nil, 0o644))
	opts := testOptions("/nonexistent", "127.0.0.1:1")
	opts.OutDir = filepath.Join(file, "logs")

	var stdout, stderr bytes.Buffer
	assert.Error(t, Run(context.Background(), opts, &stdout, &stderr))
}

// TestImportIsolation keeps livetest independent of the server: it runs
// spoofdpi as a separate process instead.
func TestImportIsolation(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go command not found")
	}
	out, err := exec.Command(goBin, "list", "-deps", ".").Output()
	require.NoError(t, err)

	deps := strings.Fields(string(out))
	for _, pkg := range []string{"internal/config", "internal/server", "internal/packet"} {
		for _, dep := range deps {
			assert.False(t,
				strings.HasPrefix(dep, "github.com/xvzc/spoofdpi/"+pkg),
				"livetest imports %s", dep)
		}
	}
	assert.Contains(t, deps, "github.com/xvzc/spoofdpi/internal/livetest")
}
