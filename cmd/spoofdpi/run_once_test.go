package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRunOnceWhenDone_RunsWhenCtxIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var runs atomic.Int32
	ran := make(chan struct{})

	runNow := runOnceWhenDone(ctx, func() {
		runs.Add(1)
		close(ran)
	})

	cancel()
	select {
	case <-ran:
	case <-time.After(time.Second):
		t.Fatal("fn did not run when ctx was done")
	}

	runNow()
	assert.EqualValues(t, 1, runs.Load())
}

func TestRunOnceWhenDone_RunNowBeforeCtxIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var runs atomic.Int32

	runNow := runOnceWhenDone(ctx, func() { runs.Add(1) })

	runNow()
	assert.EqualValues(t, 1, runs.Load())

	cancel()
	time.Sleep(20 * time.Millisecond)
	assert.EqualValues(t, 1, runs.Load(), "fn must not run again when ctx is done")
}

func TestRunOnceWhenDone_RunNowWaitsForRunningFn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	release := make(chan struct{})
	var finished atomic.Bool

	runNow := runOnceWhenDone(ctx, func() {
		close(started)
		<-release
		finished.Store(true)
	})

	cancel()
	<-started

	returned := make(chan struct{})
	go func() {
		runNow()
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("runNow returned while fn was still running")
	case <-time.After(20 * time.Millisecond):
	}

	close(release)
	<-returned
	assert.True(t, finished.Load())
}
