package probe

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterruptedError_ExitStatus(t *testing.T) {
	for sig, want := range map[os.Signal]int{
		syscall.SIGINT:  130,
		syscall.SIGTERM: 143,
		syscall.SIGHUP:  129,
		nil:             130,
	} {
		assert.Equal(t, want, (&InterruptedError{Signal: sig}).ExitStatus(), sig)
	}
}

func TestInterruptedError_Message(t *testing.T) {
	assert.Equal(
		t,
		"interrupted by SIGINT",
		(&InterruptedError{Signal: syscall.SIGINT}).Error(),
	)
	assert.Equal(
		t,
		"interrupted by SIGTERM",
		(&InterruptedError{Signal: syscall.SIGTERM}).Error(),
	)
	assert.Equal(
		t,
		"interrupted by SIGHUP",
		(&InterruptedError{Signal: syscall.SIGHUP}).Error(),
	)
	assert.Equal(t, "interrupted", (&InterruptedError{}).Error())
}

func TestStopOnSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			if signal.Ignored(sig) {
				t.Skip("the test process ignores the signal")
			}
			ctx, stop := stopOnSignal(context.Background())
			defer stop()

			require.NoError(t, syscall.Kill(os.Getpid(), sig))
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
				t.Fatal("the context was not cancelled")
			}
			var interrupted *InterruptedError
			require.True(t, errors.As(context.Cause(ctx), &interrupted))
			assert.Equal(t, sig, interrupted.Signal)
		})
	}
}

func TestStopOnSignal_IgnoredSIGHUP(t *testing.T) {
	if signal.Ignored(syscall.SIGHUP) {
		t.Skip("the test process already ignores SIGHUP")
	}
	signal.Ignore(syscall.SIGHUP)
	t.Cleanup(func() {
		// signal.Reset would leave SIGHUP reported as ignored. Notify
		// clears that, and Stop then restores the default action.
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		signal.Stop(c)
	})
	require.True(t, signal.Ignored(syscall.SIGHUP))

	ctx, stop := stopOnSignal(context.Background())
	defer stop()

	assert.True(t, signal.Ignored(syscall.SIGHUP), "SIGHUP is still ignored")
	// Were SIGHUP registered, it would no longer be ignored and would
	// cancel the context.
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGHUP))
	select {
	case <-ctx.Done():
		t.Fatal("an ignored SIGHUP cancelled the context")
	case <-time.After(200 * time.Millisecond):
	}
}
