//go:build e2e

// Package e2e runs the real spoofdpi binary and checks where its fake packets
// leave, and that TUN mode resets the network on exit.
package e2e

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const buildHint = "build it first: go build -o out/e2e/spoofdpi ./cmd/spoofdpi"

// urlList is a repeatable flag that also accepts comma-separated values.
type urlList []string

func (l *urlList) String() string { return strings.Join(*l, ",") }

func (l *urlList) Set(v string) error {
	for _, u := range strings.Split(v, ",") {
		if u = strings.TrimSpace(u); u != "" {
			*l = append(*l, u)
		}
	}
	return nil
}

var (
	binFlag      = flag.String("bin", "", "spoofdpi binary (default out/e2e/spoofdpi)")
	portFlag     = flag.Int("port", 18089, "proxy listen port")
	startTimeout = flag.Duration("start-timeout", 20*time.Second, "startup timeout")
	outFlag      = flag.String(
		"out",
		"",
		"artifacts dir (default out/e2e/fake-egress-<time>)",
	)
	urlsFlag urlList

	repoRoot string
	binPath  string // empty when no binary was found
	outDir   string
)

func TestMain(m *testing.M) {
	flag.Var(&urlsFlag, "url", "URL to fetch; repeatable or comma-separated")
	flag.Parse()

	pkgDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	repoRoot = filepath.Join(pkgDir, "..", "..")
	if len(urlsFlag) == 0 {
		urlsFlag = urlList{"https://www.youtube.com/", "https://example.com/"}
	}

	// The tests never build spoofdpi: under sudo, root has no Go toolchain.
	bin := *binFlag
	if bin == "" {
		bin = filepath.Join(repoRoot, "out", "e2e", "spoofdpi")
	}
	if abs, err := filepath.Abs(bin); err == nil {
		if st, err := os.Stat(abs); err == nil && !st.IsDir() {
			binPath = abs
		}
	}

	outDir = *outFlag
	if outDir == "" {
		outDir = filepath.Join(repoRoot, "out", "e2e",
			"fake-egress-"+time.Now().Format("20060102-150405"))
	}
	outDir, _ = filepath.Abs(outDir)

	code := m.Run()
	chownToSudoUser()
	os.Exit(code)
}

// chownToSudoUser gives the artifacts dir, and the parents root created, back
// to the user who ran sudo.
func chownToSudoUser() {
	uid, errU := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, errG := strconv.Atoi(os.Getenv("SUDO_GID"))
	if errU != nil || errG != nil || os.Geteuid() != 0 {
		return
	}
	if _, err := os.Stat(outDir); err != nil {
		return
	}
	_ = filepath.WalkDir(outDir, func(p string, _ os.DirEntry, err error) error {
		if err == nil {
			_ = os.Lchown(p, uid, gid)
		}
		return nil
	})
	for d := filepath.Dir(outDir); d != filepath.Dir(d); d = filepath.Dir(d) {
		st, err := os.Stat(d)
		if err != nil || st.Sys().(*syscall.Stat_t).Uid != 0 {
			return
		}
		_ = os.Lchown(d, uid, gid)
	}
}

// requireBin fails t when no spoofdpi binary was found.
func requireBin(t *testing.T) string {
	t.Helper()
	if binPath == "" {
		t.Fatalf("spoofdpi binary not found; %s (or pass -bin)", buildHint)
	}
	return binPath
}

// artifactDir returns the directory for one test's logs and snapshots.
func artifactDir(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(outDir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create artifacts dir: %v", err)
	}
	return dir
}

// output runs a command and returns its combined output. The OS commands that
// build snapshots may fail on a bare system; the snapshot then holds the error
// text, the same before and after.
func output(name string, args ...string) string {
	out, _ := exec.Command(name, args...).CombinedOutput()
	return string(out)
}

// spoofdpiProc is a running spoofdpi child.
type spoofdpiProc struct {
	cmd  *exec.Cmd
	done chan struct{} // closed once the process has exited and been reaped
}

// startSpoofdpi starts the binary with its output in logPath, and kills it when
// the test ends so that it never keeps running.
func startSpoofdpi(t *testing.T, logPath string, args ...string) *spoofdpiProc {
	t.Helper()
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	defer func() { _ = logFile.Close() }()

	cmd := exec.Command(requireBin(t), args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start spoofdpi: %v", err)
	}
	p := &spoofdpiProc{cmd: cmd, done: make(chan struct{})}
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(p.kill)
	t.Logf("started spoofdpi pid=%d, log %s", cmd.Process.Pid, logPath)
	return p
}

func (p *spoofdpiProc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *spoofdpiProc) kill() {
	if !p.exited() {
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

// stop sends SIGINT, which makes spoofdpi reset the network, and waits up to
// timeout. It reports false when spoofdpi had to be killed.
func (p *spoofdpiProc) stop(timeout time.Duration) bool {
	if p.exited() {
		return true
	}
	_ = p.cmd.Process.Signal(os.Interrupt)
	select {
	case <-p.done:
		return true
	case <-time.After(timeout):
		p.kill()
		return false
	}
}

func (p *spoofdpiProc) exitCode() int { return p.cmd.ProcessState.ExitCode() }

// capture counts the low-TTL IPv4 packets (the fakes) seen on one interface.
type capture struct {
	iface  string
	cancel context.CancelFunc
	done   chan struct{}

	mu       sync.Mutex
	fakes    int
	badSums  int
	ttlsSeen map[uint8]bool
}

// startCapture opens iface with pcap directly rather than through spoofdpi's
// own capture code, so that the check does not depend on the code it checks.
func startCapture(t *testing.T, iface string) *capture {
	t.Helper()
	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		t.Fatalf("capture %s: %v", iface, err)
	}
	defer inactive.CleanUp()
	for _, err := range []error{
		inactive.SetSnapLen(65535),
		inactive.SetPromisc(false),
		inactive.SetTimeout(50 * time.Millisecond),
		inactive.SetImmediateMode(true),
	} {
		if err != nil {
			t.Fatalf("capture %s: %v", iface, err)
		}
	}
	handle, err := inactive.Activate()
	if err != nil {
		t.Fatalf("capture %s: %v", iface, err)
	}
	if err := handle.SetBPFFilter("tcp port 443 and ip[8] < 16"); err != nil {
		handle.Close()
		t.Fatalf("capture %s: %v", iface, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &capture{
		iface:    iface,
		cancel:   cancel,
		done:     make(chan struct{}),
		ttlsSeen: map[uint8]bool{},
	}
	go c.run(ctx, handle)
	t.Cleanup(c.stop)
	return c
}

func (c *capture) run(ctx context.Context, handle *pcap.Handle) {
	defer close(c.done)
	defer handle.Close()
	linkType := handle.LinkType() // DLT_NULL/LOOP on utun, Ethernet elsewhere
	for ctx.Err() == nil {
		data, _, err := handle.ReadPacketData()
		if errors.Is(err, pcap.NextErrorTimeoutExpired) {
			continue
		}
		if err != nil {
			return
		}
		c.record(gopacket.NewPacket(data, linkType, gopacket.Default))
	}
}

func (c *capture) record(packet gopacket.Packet) {
	ip, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fakes++
	c.ttlsSeen[ip.TTL] = true
	// With checksum offload the host leaves the TCP checksum zero (or only the
	// pseudo-header sum) in packets captured before the NIC. A zero checksum is
	// therefore skipped, and the check only catches a wrong, non-zero value.
	tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if ok && tcp.Checksum != 0 && !tcpChecksumValid(ip) {
		c.badSums++
	}
}

// stop ends the capture and waits for the reader to finish. It can be called
// more than once.
func (c *capture) stop() {
	c.cancel()
	<-c.done
}

func (c *capture) ttls() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ttls []int
	for ttl := range c.ttlsSeen {
		ttls = append(ttls, int(ttl))
	}
	return ttls
}

func (c *capture) counts() (fakes, badSums int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fakes, c.badSums
}

// tcpChecksumValid recomputes the TCP checksum over the pseudo header and the
// segment; a valid segment sums to 0xffff.
func tcpChecksumValid(ip *layers.IPv4) bool {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(ip.SrcIP.To4())
	add(ip.DstIP.To4())
	sum += uint32(layers.IPProtocolTCP) + uint32(len(ip.Payload))
	add(ip.Payload)
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return sum == 0xffff
}

// fetchStatus fetches rawURL without following redirects, through proxyURL
// when it is not empty, and returns the status code.
func fetchStatus(rawURL, proxyURL string) (int, error) {
	transport := &http.Transport{DisableKeepAlives: true}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return 0, err
		}
		transport.Proxy = http.ProxyURL(u)
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, nil
}
