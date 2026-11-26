package livetest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// baselineLabel is the label of the baseline case. It is reserved so that
// no --add case can take it.
const baselineLabel = "config"

// labelPrefix starts an --add value that names its case.
const labelPrefix = "label:"

// childLogLevel is the log level spoofdpi runs with, so that its log
// always has the messages livetest reads.
const childLogLevel = "debug"

// testCase is one spoofdpi configuration to test.
type testCase struct {
	label string
	args  []string
	// ignored describes each flag dropped from the case's arguments.
	ignored []string
	// baseline is set for the case that runs with the user's config.
	baseline bool
}

var labelRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// parseAdds parses the --add values in order. Cases without a label are
// labeled add-N, where N counts every --add value. filter drops the flags a
// case cannot set from its arguments.
func parseAdds(values []string, filter argFilter) ([]testCase, error) {
	cases := make([]testCase, 0, len(values))
	seen := map[string]bool{baselineLabel: true}
	for i, v := range values {
		c, err := parseAdd(v, "add-"+strconv.Itoa(i+1), filter)
		if err != nil {
			return nil, err
		}
		if c.label == baselineLabel {
			return nil, fmt.Errorf("--add %q: label %q is reserved", v, baselineLabel)
		}
		if seen[c.label] {
			return nil, fmt.Errorf("--add %q: duplicate label %q", v, c.label)
		}
		seen[c.label] = true
		cases = append(cases, c)
	}
	return cases, nil
}

// parseAdd parses "label:NAME, ARGS" or "ARGS", using autoLabel for the
// latter. The label ends at the first comma, so commas in ARGS are kept.
// ARGS are split on white space; quotes are not interpreted.
func parseAdd(value, autoLabel string, filter argFilter) (testCase, error) {
	label, args := autoLabel, value
	if rest, ok := strings.CutPrefix(value, labelPrefix); ok {
		label, args, _ = strings.Cut(rest, ",")
		label = strings.TrimSpace(label)
		if !labelRE.MatchString(label) {
			return testCase{}, fmt.Errorf(
				"--add %q: label must be one or more letters, digits, '.', '_' and '-'",
				value,
			)
		}
	}

	kept, ignored := filter.filter(strings.Fields(args))
	return testCase{label: label, args: kept, ignored: ignored}, nil
}

// spoofdpiArgs returns the command line spoofdpi runs with for c. The
// explicit "run" keeps spoofdpi on the server command whatever c.args are.
func spoofdpiArgs(opts Options, c testCase) []string {
	args := []string{
		"run",
		"--no-tui",
		"--log-level", childLogLevel,
		"--app-mode", opts.Mode,
		"--listen-addr", opts.Listen,
		// A user's config must not change the system proxy during a test.
		"--auto-configure-network=false",
	}
	switch {
	case opts.Config != "":
		args = append(args, "--config", opts.Config)
	case !c.baseline:
		args = append(args, "--clean")
	}
	return append(args, c.args...)
}

var (
	// errExitedEarly reports that spoofdpi exited before its server
	// started.
	errExitedEarly = errors.New("spoofdpi exited before starting")
	// errStartTimeout reports that spoofdpi did not start in time.
	errStartTimeout = errors.New("spoofdpi did not start in time")
)

// runCase starts spoofdpi for c, requests every URL through it and stops it.
// It returns the stats of spoofdpi's log even when it fails.
func runCase(
	ctx context.Context,
	opts Options,
	c testCase,
	stderr io.Writer,
) ([]result, logStats, error) {
	logPath := ""
	logOut := io.Discard
	if opts.OutDir != "" {
		logPath = filepath.Join(opts.OutDir, c.label+".log")
		logFile, err := os.Create(logPath)
		if err != nil {
			return nil, logStats{}, err
		}
		defer func() { _ = logFile.Close() }()
		logOut = logFile
	}
	seeLog := ""
	if logPath != "" {
		seeLog = fmt.Sprintf(" (see %s)", logPath)
	}

	cmd := exec.Command(opts.Bin, spoofdpiArgs(opts, c)...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, logStats{}, err
	}
	cmd.Stderr = cmd.Stdout

	_, _ = fmt.Fprintf(stderr, "livetest: case %s: %s %s\n",
		c.label, opts.Bin, strings.Join(cmd.Args[1:], " "))
	if err := cmd.Start(); err != nil {
		return nil, logStats{}, err
	}

	started := make(chan struct{})
	scanDone := make(chan struct{})
	var stats logStats
	go func() {
		stats = scanLog(out, logOut, started)
		close(scanDone)
	}()

	results, err := requestAll(ctx, opts, c, started, scanDone)

	// Interrupt spoofdpi and wait for it to exit. The log is read to the
	// end before Wait, which closes the pipe.
	grace := opts.stopGrace
	if grace == 0 {
		grace = defaultStopGrace
	}
	_ = cmd.Process.Signal(syscall.SIGINT)
	select {
	case <-scanDone:
	case <-time.After(grace):
		_ = cmd.Process.Kill()
		<-scanDone
	}
	_ = cmd.Wait()

	switch {
	case errors.Is(err, errExitedEarly):
		return nil, stats, fmt.Errorf("%w%s: %s", err, seeLog, stats.last)
	case errors.Is(err, errStartTimeout):
		return nil, stats, fmt.Errorf("spoofdpi did not start within %s%s",
			opts.StartTimeout, seeLog)
	}
	for i := range results {
		results[i].warns = stats.warns
		results[i].errs = stats.errs
	}
	return results, stats, err
}

// requestAll waits for spoofdpi to start, then requests every URL through
// it. scanDone is closed when spoofdpi's output ends. If ctx is cancelled,
// it returns the results so far, including the URL being requested if it
// has any.
func requestAll(
	ctx context.Context,
	opts Options,
	c testCase,
	started, scanDone <-chan struct{},
) ([]result, error) {
	select {
	case <-started:
	case <-scanDone:
		return nil, errExitedEarly
	case <-time.After(opts.StartTimeout):
		return nil, errStartTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	var results []result
	for _, u := range opts.URLs {
		res := result{caseLabel: c.label, url: u}
		for range opts.Tries {
			o := request(ctx, opts, u)
			// A request cut short by the interrupt is not a result.
			if ctx.Err() != nil {
				if res.tries > 0 {
					results = append(results, res)
				}
				return results, ctx.Err()
			}
			res.add(o)
		}
		results = append(results, res)
	}
	return results, nil
}

// logStats summarizes a spoofdpi log.
type logStats struct {
	// warns and errs count the warnings and errors logged after the server
	// started, so that startup messages such as a missing config file do
	// not count.
	warns, errs int
	last        string
	// configKnown is set once the log says which config file spoofdpi
	// loaded; config is that file, or "" if spoofdpi found none.
	configKnown bool
	config      string
}

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// These match messages spoofdpi logs (cmd/spoofdpi/main.go and, for a
// missing config file, internal/config/load.go).
const (
	startedMsg        = "server started"
	loadedConfigMsg   = "loaded config file"
	configNotFoundMsg = "config file not found"
	configFieldPrefix = "dir="
)

// scanLog copies spoofdpi's output to w without color codes, closes started
// once spoofdpi reports that its server started, counts the warnings and
// errors after that, and notes which config file spoofdpi loaded.
func scanLog(r io.Reader, w io.Writer, started chan<- struct{}) logStats {
	var stats logStats
	isStarted := false

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := ansiRE.ReplaceAllString(sc.Text(), "")
		_, _ = fmt.Fprintln(w, line)
		if strings.TrimSpace(line) != "" {
			stats.last = line
		}

		switch {
		case !isStarted:
		case strings.HasPrefix(line, "WRN"):
			stats.warns++
		case strings.HasPrefix(line, "ERR"), strings.HasPrefix(line, "FTL"):
			stats.errs++
		}
		if !stats.configKnown {
			stats.config, stats.configKnown = configFromLine(line)
		}
		if !isStarted && strings.Contains(line, startedMsg) {
			isStarted = true
			close(started)
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		stats.last = err.Error()
	}
	return stats
}

// configFromLine returns the config file a log line says spoofdpi loaded,
// or "" if it says spoofdpi found none. ok is false if the line says
// neither.
func configFromLine(line string) (path string, ok bool) {
	if strings.Contains(line, configNotFoundMsg) {
		return "", true
	}
	if !strings.Contains(line, loadedConfigMsg) {
		return "", false
	}
	_, path, ok = strings.Cut(line, " "+configFieldPrefix)
	path = strings.TrimSpace(path)
	// The log quotes a value with spaces or non-ASCII characters.
	if unquoted, err := strconv.Unquote(path); err == nil {
		path = unquoted
	}
	return path, ok
}
