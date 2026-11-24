//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xvzc/spoofdpi/internal/testutil"
)

// Both root tests check that spoofdpi's low-TTL fake packets leave through the
// physical interface (and never through the TUN), and the TUN test also checks
// that a run puts the routes, rules and interfaces back on SIGINT.

func TestFakeEgress_Proxy_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	runFakeEgress(t, false)
}

func TestFakeEgress_TUN_RequireRoot(t *testing.T) {
	testutil.RequireRoot(t)
	runFakeEgress(t, true)
}

// TestFakeEgress_NonRoot checks that fake packets without root fail at startup
// with an error that names the option.
func TestFakeEgress_NonRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("must run as a normal user")
	}
	bin := requireBin(t)
	logPath := filepath.Join(artifactDir(t, "nonroot"), "spoofdpi.log")

	ctx, cancel := context.WithTimeout(context.Background(), *startTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "run", "--clean", "--no-tui",
		"--app-mode", "http", "--listen-addr", listenAddr(),
		"--tls-fake-preflight", "1").CombinedOutput()
	if werr := os.WriteFile(logPath, out, 0o644); werr != nil {
		t.Fatalf("write log: %v", werr)
	}
	t.Logf("log %s", logPath)

	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		t.Errorf("still running after %s", *startTimeout)
	case !errors.As(err, &exitErr):
		t.Errorf("want a non-zero exit, got err=%v", err)
	default:
		t.Logf("exit=%d", exitErr.ExitCode())
	}
	for _, want := range []string{"fake packets need root", "tls.fake-preflight"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "fake packets need root") {
			t.Logf("error: %s", strings.TrimSpace(line))
		}
	}
}

func listenAddr() string { return fmt.Sprintf("127.0.0.1:%d", *portFlag) }

// runFakeEgress runs spoofdpi in proxy or TUN mode, fetches the URLs, and
// reports each check as a subtest.
func runFakeEgress(t *testing.T, tun bool) {
	mode := "proxy"
	if tun {
		mode = "tun"
	}
	dir := artifactDir(t, mode)
	requireBin(t)

	// The physical interface comes from the OS's own command, so that the check
	// stays independent of spoofdpi's route code.
	phys := physicalIface()
	if phys == "" {
		t.Fatal("no IPv4 default route found")
	}
	t.Logf("physical interface: %s", phys)

	// The state a TUN run must restore.
	before := snapshot()
	beforePath := filepath.Join(dir, "before.txt")
	writeFile(t, beforePath, before)
	t.Logf("snapshot: %s", beforePath)
	snapshotTime := time.Now()

	args := []string{"run", "--clean", "--no-tui"}
	if tun {
		args = append(args, "--app-mode", "tun", "--auto-configure-network")
	} else {
		args = append(args, "--app-mode", "http", "--listen-addr", listenAddr())
	}
	args = append(args, "--tls-fake-preflight", "1", "--log-level", "trace")
	logPath := filepath.Join(dir, "spoofdpi.log")
	spoofdpi := startSpoofdpi(t, logPath, args...)

	tunName := waitReady(t, spoofdpi, tun, before)
	// The TUN exists before the routes and rules are installed.
	time.Sleep(2 * time.Second)

	var stateFile string
	if tun {
		t.Logf("tun interface: %s", tunName)
		stateFile = findStateFile(snapshotTime)
		t.Run("state-file-created", func(t *testing.T) {
			if stateFile == "" {
				t.Fatal("no /tmp/spoofdpi.*.state written since the snapshot")
			}
			t.Log(stateFile)
		})
	}

	captures := []*capture{startCapture(t, phys)}
	if tun {
		captures = append(captures, startCapture(t, tunName))
	}

	proxyURL := ""
	if !tun {
		proxyURL = "http://" + listenAddr()
	}
	type fetched struct {
		host   string
		status int
		err    error
	}
	var fetches []fetched
	for _, u := range urlsFlag {
		status, err := fetchStatus(u, proxyURL)
		host := u
		if parsed, perr := url.Parse(u); perr == nil && parsed.Host != "" {
			host = parsed.Host
		}
		fetches = append(fetches, fetched{host, status, err})
	}

	// Let the last packets drain, then stop everything.
	time.Sleep(2 * time.Second)
	for _, c := range captures {
		c.stop()
	}
	graceful := spoofdpi.stop(15 * time.Second)

	for _, f := range fetches {
		t.Run("fetch/"+f.host, func(t *testing.T) {
			// A 2xx or 3xx status passes: the sites may redirect and only
			// reaching them matters.
			if f.err != nil || f.status < 200 || f.status >= 400 {
				t.Fatalf("status=%d err=%v", f.status, f.err)
			}
			t.Logf("status=%d", f.status)
		})
	}

	physFakes, _ := captures[0].counts()
	t.Run("fakes-on-physical", func(t *testing.T) {
		t.Logf("%s count=%d ttls=%v", phys, physFakes, captures[0].ttls())
		if physFakes == 0 {
			t.Error("no fake packets on the physical interface")
		}
	})

	// A fake with TTL 1 expires at the first hop, which is what a wrongly
	// learned hop count of 1 sends. The log lines `ttl(tcp) update` in the
	// artifacts show how that count was learned.
	t.Run("fakes-ttl-above-1", func(t *testing.T) {
		for _, c := range captures {
			ttls := c.ttls()
			t.Logf("%s ttls=%v", c.iface, ttls)
			if low := lowTTLs(ttls); len(low) != 0 {
				t.Errorf("%s: fake packets with TTL %v expire at the first hop", c.iface, low)
			}
		}
	})

	t.Run("fake-log", func(t *testing.T) {
		n := strings.Count(readFile(t, logPath), "sent fake packets")
		t.Logf("count=%d", n)
		if n == 0 {
			t.Errorf("no 'sent fake packets' in %s", logPath)
		}
	})

	t.Run("bad-checksums", func(t *testing.T) {
		bad := 0
		for _, c := range captures {
			_, b := c.counts()
			bad += b
		}
		t.Logf("count=%d", bad)
		if bad != 0 {
			t.Errorf("%d fake packets have a wrong TCP checksum", bad)
		}
	})

	if !tun {
		return
	}

	t.Run("fakes-on-tun", func(t *testing.T) {
		fakes, _ := captures[1].counts()
		t.Logf("%s count=%d ttls=%v", tunName, fakes, captures[1].ttls())
		if fakes != 0 {
			t.Errorf("%d fake packets leaked into the TUN", fakes)
		}
	})

	t.Run("graceful-exit", func(t *testing.T) {
		if !graceful {
			t.Fatal("no exit within 15s after SIGINT; killed")
		}
		code := spoofdpi.exitCode()
		if code != 0 {
			t.Fatalf("exit=%d", code)
		}
		t.Logf("exit=%d after SIGINT", code)
	})

	// The state must be back as before.
	time.Sleep(time.Second)
	after := snapshot()
	afterPath := filepath.Join(dir, "after.txt")
	writeFile(t, afterPath, after)
	t.Logf("snapshot: %s", afterPath)

	t.Run("reset-diff", func(t *testing.T) {
		out, err := exec.Command("diff", beforePath, afterPath).CombinedOutput()
		var exitErr *exec.ExitError
		if err != nil && (!errors.As(err, &exitErr) || exitErr.ExitCode() != 1) {
			t.Fatalf("diff: %v: %s", err, out)
		}
		if len(out) == 0 {
			t.Logf("%s and %s match", beforePath, afterPath)
			return
		}
		diffPath := filepath.Join(dir, "reset.diff")
		writeFile(t, diffPath, string(out))
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		t.Errorf("state differs after exit, full diff in %s:\n%s", diffPath,
			strings.Join(lines[:min(len(lines), 20)], "\n"))
	})

	t.Run("state-file-removed", func(t *testing.T) {
		if stateFile == "" {
			t.Fatal("no state file was found while the TUN was up")
		}
		if _, err := os.Stat(stateFile); err == nil {
			t.Fatalf("%s still exists", stateFile)
		}
		t.Logf("%s removed", stateFile)
	})

	t.Run("tun-removed", func(t *testing.T) {
		if ifaceExists(tunName) {
			t.Fatalf("%s still exists", tunName)
		}
		t.Logf("%s removed", tunName)
	})

	// The test never changes routes itself.
	if t.Failed() && stateFile != "" {
		if _, err := os.Stat(stateFile); err == nil {
			t.Logf("TUN state file still present: %s; the routes may need manual "+
				"cleanup (compare %s with the current state)", stateFile, beforePath)
		}
	}
}

// waitReady waits until the proxy port accepts a connection, or the TUN
// exists, and returns the TUN name.
func waitReady(t *testing.T, p *spoofdpiProc, tun bool, before string) string {
	t.Helper()
	deadline := time.Now().Add(*startTimeout)
	for time.Now().Before(deadline) && !p.exited() {
		if tun {
			if name := tunIface(before); name != "" {
				return name
			}
		} else if conn, err := net.DialTimeout("tcp", listenAddr(), time.Second); err == nil {
			_ = conn.Close()
			return ""
		}
		time.Sleep(500 * time.Millisecond)
	}
	if p.exited() {
		t.Fatal("spoofdpi exited early; see its log in the artifacts dir")
	}
	t.Fatalf("not ready after %s; see its log in the artifacts dir", *startTimeout)
	return ""
}

// findStateFile returns the /tmp/spoofdpi.*.state file written after since. It
// matches by modification time instead of hardcoding the per-OS name, so that a
// renamed file fails the check rather than passing unnoticed.
func findStateFile(since time.Time) string {
	// /tmp is a symlink on darwin.
	tmp, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return ""
	}
	matches, _ := filepath.Glob(filepath.Join(tmp, "spoofdpi.*.state"))
	for _, m := range matches {
		if st, err := os.Stat(m); err == nil && st.ModTime().After(since) {
			return m
		}
	}
	return ""
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
