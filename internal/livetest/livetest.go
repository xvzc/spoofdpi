// Package livetest runs a spoofdpi binary against real sites and reports
// how many requests through it succeed, so that DPI bypass options can be
// checked on a live network.
//
// Each case starts spoofdpi with its own arguments, sends requests to every
// URL through it, and stops it. Run it as root (for example with sudo) so
// that spoofdpi can send fake packets; one sudo then covers every case.
package livetest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Options configures a live test.
type Options struct {
	// Bin is the spoofdpi binary to run.
	Bin string
	// URLs are requested through spoofdpi in every case.
	URLs []string
	// Adds are the cases to test, as given to --add ("label:NAME, ARGS" or
	// "ARGS"), in the order they run.
	Adds []string
	// NoBaseline skips the baseline case, which runs spoofdpi with the
	// user's config and no extra arguments.
	NoBaseline bool
	// Tries is the number of requests per URL and case.
	Tries int
	// Timeout is the timeout of each request.
	Timeout time.Duration
	// StartTimeout is the time to wait for spoofdpi to start.
	StartTimeout time.Duration
	// Mode is the proxy mode spoofdpi runs in: "http" or "socks5".
	Mode string
	// Listen is the address spoofdpi listens on.
	Listen string
	// Config is the spoofdpi config file. If empty, the baseline case uses
	// spoofdpi's default config search and the other cases run with --clean.
	Config string
	// CaseFlags are the server flags a case may set. Other flags are
	// dropped from the arguments of a case, with a warning.
	CaseFlags CaseFlags
	// UserAgent is the User-Agent header of each request.
	UserAgent string
	// OutDir, if set, is the directory each case's log is written to.
	OutDir string

	// stopGrace is how long spoofdpi has to exit after an interrupt before
	// it is killed; zero means defaultStopGrace.
	stopGrace time.Duration
}

const defaultStopGrace = 5 * time.Second

// InterruptedError reports that a live test was stopped before it
// finished.
type InterruptedError struct {
	// Signal is the signal that stopped the test, or nil if its context
	// was cancelled.
	Signal os.Signal
}

func (e *InterruptedError) Error() string {
	if e.Signal == nil {
		return "interrupted"
	}
	return "interrupted by " + signalName(e.Signal)
}

// signalName returns the conventional name of sig, such as "SIGINT", or
// its description for a signal without one.
func signalName(sig os.Signal) string {
	switch sig {
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGHUP:
		return "SIGHUP"
	}
	return sig.String()
}

// ExitStatus is the conventional exit status of a program stopped by
// e.Signal: 128 plus the signal number, or 130, as for SIGINT, if there
// is no signal.
func (e *InterruptedError) ExitStatus() int {
	if sig, ok := e.Signal.(syscall.Signal); ok {
		return 128 + int(sig)
	}
	return 128 + int(syscall.SIGINT)
}

// DefaultUserAgent is the User-Agent of a desktop Chrome. Some sites answer
// Go's default User-Agent with an error page.
const DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
	"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

// Run tests every case and writes the report to stdout. Progress, the
// arguments dropped from cases and the cases that fail to run go to stderr.
// It returns an error when the test cannot run, for example because opts is
// invalid; the results of the cases do not change it. SIGINT, SIGTERM and
// SIGHUP, or cancelling ctx, stop the running case; Run then reports the
// results so far and returns an *InterruptedError.
func Run(ctx context.Context, opts Options, stdout, stderr io.Writer) error {
	cases, err := opts.cases()
	if err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		_, _ = fmt.Fprintln(stderr,
			"livetest: warning: not running as root; spoofdpi may not send fake packets")
	}
	for _, c := range cases {
		for _, ignored := range c.ignored {
			_, _ = fmt.Fprintf(stderr, "livetest: case %q: ignored %s\n", c.label, ignored)
		}
	}
	if opts.OutDir != "" {
		if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
			return err
		}
	}

	ctx, stop := stopOnSignal(ctx)
	defer stop()

	var results []result
	var baseline *logStats
	for _, c := range cases {
		res, stats, err := runCase(ctx, opts, c, stderr)
		if c.baseline {
			baseline = &stats
		}
		results = append(results, res...)
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "livetest: case %q: %v\n", c.label, err)
		}
	}

	if err := writeReport(stdout, baseline, results, opts.OutDir); err != nil {
		return err
	}
	if ctx.Err() != nil {
		var interrupted *InterruptedError
		if errors.As(context.Cause(ctx), &interrupted) {
			return interrupted
		}
		return &InterruptedError{}
	}
	return nil
}

// stopOnSignal returns a context that is cancelled, with an
// *InterruptedError as its cause, when the process gets SIGINT, SIGTERM or
// SIGHUP.
func stopOnSignal(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		select {
		case sig := <-signals:
			cancel(&InterruptedError{Signal: sig})
		case <-ctx.Done():
		}
	}()
	return ctx, func() {
		signal.Stop(signals)
		cancel(nil)
	}
}

// cases validates opts and returns the cases to run, the baseline first.
func (opts Options) cases() ([]testCase, error) {
	switch {
	case len(opts.URLs) == 0:
		return nil, errors.New("at least one --url is required")
	case opts.Tries < 1:
		return nil, errors.New("--tries must be at least 1")
	case opts.Timeout <= 0:
		return nil, errors.New("--timeout must be positive")
	case opts.StartTimeout <= 0:
		return nil, errors.New("--start-timeout must be positive")
	case opts.Mode != "http" && opts.Mode != "socks5":
		return nil, fmt.Errorf("--mode must be http or socks5, not %q", opts.Mode)
	case opts.UserAgent == "":
		return nil, errors.New("--user-agent must not be empty")
	case len(opts.CaseFlags.Allowed) == 0:
		return nil, errors.New("no server flags are allowed in cases")
	case opts.NoBaseline && len(opts.Adds) == 0:
		return nil, errors.New("--no-baseline needs at least one --add")
	}
	if err := checkURLs(opts.URLs); err != nil {
		return nil, fmt.Errorf("--url: %w", err)
	}
	if err := checkListen(opts.Listen); err != nil {
		return nil, fmt.Errorf("--listen: %w", err)
	}
	if opts.Config != "" {
		if err := checkConfigFile(opts.Config); err != nil {
			return nil, fmt.Errorf("--config: %w", err)
		}
	}

	var cases []testCase
	if !opts.NoBaseline {
		cases = append(cases, testCase{label: baselineLabel, baseline: true})
	}
	added, err := parseAdds(opts.Adds, newArgFilter(opts.CaseFlags))
	if err != nil {
		return nil, err
	}
	return append(cases, added...), nil
}
