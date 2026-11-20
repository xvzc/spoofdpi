package livetest

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeScript writes a shell script that stands in for spoofdpi.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "spoofdpi")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"+body), 0o755))
	return bin
}

// newProxy starts a local HTTP proxy with handler and returns its address
// and the number of connections it accepted.
func newProxy(t *testing.T, handler http.HandlerFunc) (string, *atomic.Int64) {
	t.Helper()
	conns := &atomic.Int64{}
	proxy := httptest.NewUnstartedServer(handler)
	proxy.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	proxy.Start()
	t.Cleanup(proxy.Close)
	return strings.TrimPrefix(proxy.URL, "http://"), conns
}

func TestRun_StartTimeout(t *testing.T) {
	bin := writeScript(t, "echo 'INF starting'\nexec sleep 30\n")
	opts := testOptions(bin, "127.0.0.1:1")
	opts.StartTimeout = 200 * time.Millisecond

	var stdout, stderr bytes.Buffer
	start := time.Now()
	require.NoError(t, Run(context.Background(), opts, &stdout, &stderr))
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.Contains(t, stderr.String(), "spoofdpi did not start within 200ms")
}

func TestRun_KillsAfterGracePeriod(t *testing.T) {
	// The script, and the sleep it becomes, ignore SIGINT.
	bin := writeScript(t, "trap '' INT\necho 'INF server started'\nexec sleep 30\n")
	opts := testOptions(bin, fakeProxy(t, DefaultUserAgent))
	opts.stopGrace = 200 * time.Millisecond

	var stdout, stderr bytes.Buffer
	start := time.Now()
	require.NoError(t, Run(context.Background(), opts, &stdout, &stderr), stderr.String())
	assert.Less(t, time.Since(start), 5*time.Second, "spoofdpi is killed")
	assert.Contains(t, stdout.String(), "2/2")
}

func TestRun_CancelMidCase(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var requests atomic.Int64
	listen, _ := newProxy(t, func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// Interrupt during the second request, and hold it until the
		// client gives up.
		cancel()
		<-r.Context().Done()
	})

	bin := fakeSpoofdpi(t, "WRN config file not found")
	opts := testOptions(bin, listen)
	opts.Tries = 3
	opts.URLs = []string{"http://ok.test/", "http://next.test/"}
	opts.NoBaseline = true
	opts.Adds = []string{"label:a, --tls-disorder", "label:b, --tls-disorder"}

	var stdout, stderr bytes.Buffer
	err := Run(ctx, opts, &stdout, &stderr)

	var interrupted *InterruptedError
	require.ErrorAs(t, err, &interrupted)
	assert.Equal(t, 130, interrupted.ExitStatus())

	report := stdout.String()
	assert.Regexp(t, `(?m)^a\s+http://ok\.test/\s+1/1\s+204\s+1\s+0$`, report,
		"the interrupted request is not counted")
	assert.NotContains(t, report, "next.test", "a URL without results has no row")
	assert.NotContains(t, stderr.String(), "livetest: case b:", "later cases do not run")
}

func TestRun_CancelBeforeStart(t *testing.T) {
	bin := writeScript(t, "exec sleep 30\n")
	opts := testOptions(bin, "127.0.0.1:1")
	opts.NoBaseline = true
	opts.Adds = []string{"label:a, --tls-disorder"}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(100*time.Millisecond, cancel)

	var stdout, stderr bytes.Buffer
	err := Run(ctx, opts, &stdout, &stderr)

	var interrupted *InterruptedError
	require.ErrorAs(t, err, &interrupted)
	assert.Equal(t, "CASE  URL  OK  OUTCOMES  WARN  ERR\n", stdout.String(),
		"the report has no rows")
}

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

func TestStopOnSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
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

func TestProxyURL(t *testing.T) {
	opts := Options{Mode: "http", Listen: "127.0.0.1:1"}
	assert.Equal(t, "http://127.0.0.1:1", proxyURL(opts).String())
	opts.Mode = "socks5"
	assert.Equal(t, "socks5://127.0.0.1:1", proxyURL(opts).String())
}

func TestRun_RedirectsAreNotFollowed(t *testing.T) {
	var followed atomic.Int64
	listen, _ := newProxy(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Host == "target.test" {
			followed.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "http://target.test/", http.StatusMovedPermanently)
	})

	opts := testOptions(fakeSpoofdpi(t, "WRN config file not found"), listen)
	opts.URLs = []string{"http://redirect.test/"}

	var stdout, stderr bytes.Buffer
	require.NoError(t, Run(context.Background(), opts, &stdout, &stderr), stderr.String())
	assert.Regexp(
		t,
		`(?m)^config\s+http://redirect\.test/\s+2/2\s+301x2\s`,
		stdout.String(),
	)
	assert.Zero(t, followed.Load(), "the Location is not requested")
}

func TestRun_NewConnectionPerRequest(t *testing.T) {
	listen, conns := newProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	opts := testOptions(fakeSpoofdpi(t, "WRN config file not found"), listen)
	opts.Tries = 3
	opts.URLs = []string{"http://a.test/", "http://b.test/"}

	var stdout, stderr bytes.Buffer
	require.NoError(t, Run(context.Background(), opts, &stdout, &stderr), stderr.String())
	assert.Equal(t, int64(6), conns.Load())
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
