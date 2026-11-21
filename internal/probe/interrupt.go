package probe

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// InterruptedError reports that a probe was stopped before it finished.
type InterruptedError struct {
	// Signal is the signal that stopped the probe, or nil if its context
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

// notifySignals returns the signals that stop the run: SIGINT, SIGTERM
// and, unless the process ignores it, SIGHUP. Asking to be notified of an
// ignored signal would stop ignoring it.
func notifySignals() []os.Signal {
	signals := []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) {
		signals = append(signals, syscall.SIGHUP)
	}
	return signals
}

// stopOnSignal returns a context that is cancelled, with an
// *InterruptedError as its cause, when the process gets SIGINT, SIGTERM or
// SIGHUP. SIGHUP is left alone when the process ignores it, as under
// nohup.
func stopOnSignal(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(ctx)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, notifySignals()...)
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
