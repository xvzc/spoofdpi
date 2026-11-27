//go:build darwin

package server

import (
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSysProxyJobs_ServiceNameIsOneArgument(t *testing.T) {
	const pacURL = "http://127.0.0.1:8081/spoofdpi.pac"
	for _, service := range []string{"USB 10/100/1000 LAN", "Bob's Wi-Fi"} {
		t.Run(service, func(t *testing.T) {
			jobs := sysProxyJobs(service, pacURL)

			// No WPAD (-setproxyautodiscovery) job.
			assert.Equal(t, []NetworkJob{{
				Description: "set auto proxy URL",
				Apply: CommandAction{
					"networksetup", "-setautoproxyurl", service, pacURL,
				},
				Reset: CommandAction{
					"networksetup", "-setautoproxystate", service, "off",
				},
			}}, jobs)
		})
	}
}

func TestParseNetworkServices(t *testing.T) {
	out := "An asterisk (*) denotes that a network service is disabled.\n" +
		"Wi-Fi\n*Thunderbolt Bridge\nUSB 10/100/1000 LAN\n\n"
	assert.Equal(t,
		[]string{"Wi-Fi", "Thunderbolt Bridge", "USB 10/100/1000 LAN"},
		parseNetworkServices(out))
}

func TestParseAutoProxy(t *testing.T) {
	tests := map[string]autoProxyConfig{
		"URL: http://127.0.0.1:64136/proxy.pac\nEnabled: No\n": {
			URL: "http://127.0.0.1:64136/proxy.pac",
		},
		"URL: http://127.0.0.1:64136/spoofdpi.pac\nEnabled: Yes\n": {
			URL: "http://127.0.0.1:64136/spoofdpi.pac", Enabled: true,
		},
		"URL: (null)\nEnabled: No\n": {URL: "(null)"},
	}
	for out, want := range tests {
		assert.Equal(t, want, parseAutoProxy(out), out)
	}
}

func TestSpoofdpiPACURL(t *testing.T) {
	match := []string{
		"http://127.0.0.1:8080/spoofdpi.pac",
		"http://127.0.0.1:64136/proxy.pac",
	}
	noMatch := []string{
		"(null)",
		"http://127.0.0.1/spoofdpi.pac",
		"http://127.0.0.1:8080/other.pac",
		"http://127.0.0.1:8080/spoofdpi.pac?x",
		"http://127.0.0.1:8080/x/proxy.pac",
		"https://127.0.0.1:8080/proxy.pac",
		"http://localhost:8080/proxy.pac",
		"http://10.0.0.1:8080/proxy.pac",
		"http://127.0.0.1.evil.com:8080/proxy.pac",
	}
	for _, u := range match {
		assert.True(t, spoofdpiPACURL.MatchString(u), u)
	}
	for _, u := range noMatch {
		assert.False(t, spoofdpiPACURL.MatchString(u), u)
	}
}

func TestProbePAC(t *testing.T) {
	t.Run("live spoofdpi by header", func(t *testing.T) {
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(pacMarkerHeader, pacMarkerValue)
			}),
		)
		defer srv.Close()
		assert.Equal(t, pacLive, probePAC(srv.URL+"/spoofdpi.pac").kind)
	})

	t.Run("live spoofdpi by comment", func(t *testing.T) {
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(pacMarkerComment + "\nfunction FindProxyForURL(){}"))
			}),
		)
		defer srv.Close()
		assert.Equal(t, pacLive, probePAC(srv.URL+"/proxy.pac").kind)
	})

	t.Run("another server", func(t *testing.T) {
		srv := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("hello"))
			}),
		)
		defer srv.Close()
		assert.Equal(t, pacUnknown, probePAC(srv.URL+"/proxy.pac").kind)
	})

	t.Run("redirect is not followed", func(t *testing.T) {
		live := httptest.NewServer(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(pacMarkerHeader, pacMarkerValue)
			}),
		)
		defer live.Close()
		srv := httptest.NewServer(http.RedirectHandler(live.URL, http.StatusFound))
		defer srv.Close()
		assert.Equal(t, pacUnknown, probePAC(srv.URL+"/proxy.pac").kind)
	})

	t.Run("connection refused", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		url := "http://" + l.Addr().String() + "/spoofdpi.pac"
		require.NoError(t, l.Close())
		assert.Equal(t, pacDead, probePAC(url).kind)
	})

	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		srv := httptest.NewServer(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				<-release
			}),
		)
		defer srv.Close()
		defer close(release)
		start := time.Now()
		assert.Equal(t, pacUnknown, probePAC(srv.URL+"/spoofdpi.pac").kind)
		assert.Less(t, time.Since(start), 3*time.Second)
	})
}

func TestPACServer_OnlyServesPACPaths(t *testing.T) {
	url, pac, err := runPACServer("body")
	require.NoError(t, err)
	defer func() { _ = pac.Close() }()
	base := strings.TrimSuffix(url, "/spoofdpi.pac")

	for path, want := range map[string]int{
		"/spoofdpi.pac": http.StatusOK,
		"/proxy.pac":    http.StatusOK,
		"/":             http.StatusNotFound,
		"/other.pac":    http.StatusNotFound,
	} {
		resp, err := http.Get(base + path)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, want, resp.StatusCode, path)
	}
}

func TestPACServer_ServesMarkedPACAtSpoofdpiPath(t *testing.T) {
	url, pac, err := runPACServer(pacMarkerComment + "\nbody")
	require.NoError(t, err)
	defer func() { _ = pac.Close() }()

	assert.True(t, strings.HasSuffix(url, "/spoofdpi.pac"))
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, "application/x-ns-proxy-autoconfig", resp.Header.Get("Content-Type"))
	assert.Equal(t, pacMarkerValue, resp.Header.Get(pacMarkerHeader))
	assert.Equal(t, pacLive, probePAC(url).kind)
}

// fakeNetworksetup replaces runNetworksetup with a fake over the given
// services (name to getautoproxyurl output) and records the commands that
// change state. A service whose output is "error" fails to be read, one whose
// output starts with "** Error" fails with exit status 0, and turning a
// service off rewrites its output to Enabled: No.
func fakeNetworksetup(t *testing.T, services map[string]string) *[][]string {
	t.Helper()
	var changes [][]string
	orig := runNetworksetup
	t.Cleanup(func() { runNetworksetup = orig })
	runNetworksetup = func(args ...string) (string, error) {
		switch args[0] {
		case "-listallnetworkservices":
			out := "An asterisk (*) denotes that a network service is disabled.\n"
			for name := range services {
				out += name + "\n"
			}
			return out, nil
		case "-getautoproxyurl":
			out, ok := services[args[1]]
			if !ok || out == "error" {
				return "", errors.New("cannot read")
			}
			return out, nil
		}
		changes = append(changes, args)
		if args[0] == "-setautoproxystate" {
			services[args[1]] = strings.Replace(
				services[args[1]], "Enabled: Yes", "Enabled: No", 1)
		}
		return "", nil
	}
	return &changes
}

func TestCleanSystemProxyLeftovers_DecisionTable(t *testing.T) {
	live := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(pacMarkerHeader, pacMarkerValue)
		}),
	)
	defer live.Close()
	other := httptest.NewServer(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
	)
	defer other.Close()
	release := make(chan struct{})
	slow := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer slow.Close()
	defer close(release)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	deadAddr := l.Addr().String()
	require.NoError(t, l.Close())

	enabled := func(url string) string { return "URL: " + url + "\nEnabled: Yes\n" }
	changes := fakeNetworksetup(t, map[string]string{
		"Dead Wi-Fi":   enabled("http://" + deadAddr + "/spoofdpi.pac"),
		"Old Bob's":    enabled("http://" + deadAddr + "/proxy.pac"),
		"Disabled":     "URL: http://" + deadAddr + "/spoofdpi.pac\nEnabled: No\n",
		"Live":         enabled(live.URL + "/spoofdpi.pac"),
		"Reused port":  enabled(other.URL + "/spoofdpi.pac"),
		"Foreign tool": enabled("http://" + deadAddr + "/foreign.pac"),
		"Unreadable":   "error",
		"Slow":         enabled(slow.URL + "/spoofdpi.pac"),
		"None":         "URL: (null)\nEnabled: No\n",
	})

	var logs bytes.Buffer
	CleanSystemProxyLeftovers(zerolog.New(&logs))

	// The slow, reused-port and unreadable rows are warned about.
	assert.Contains(t, logs.String(), "did not answer within 1s")
	assert.Contains(t, logs.String(), "cannot read the auto proxy configuration")
	assert.ElementsMatch(t, [][]string{
		{"-setautoproxystate", "Dead Wi-Fi", "off"},
		{"-setautoproxystate", "Old Bob's", "off"},
	}, *changes)
}

func TestAutoProxyLeftover_ManualCommandQuotesServiceName(t *testing.T) {
	l := autoProxyLeftover("Bob's Wi-Fi", "http://127.0.0.1:1/proxy.pac", "kept")
	assert.Nil(t, l.Remove)
	assert.Contains(t, l.Description, "kept")
	assert.Equal(
		t,
		`networksetup -setautoproxystate 'Bob'\''s Wi-Fi' off`,
		l.ManualCommand,
	)
}

func TestCheckSystemProxyLeftoversAfterReset(t *testing.T) {
	const pacURL = "http://127.0.0.1:9/spoofdpi.pac"
	tests := map[string]struct {
		output   string
		wantWarn bool
	}{
		"still enabled with this run's URL": {
			"URL: " + pacURL + "\nEnabled: Yes\n", true,
		},
		"disabled": {"URL: " + pacURL + "\nEnabled: No\n", false},
		"another URL enabled": {
			"URL: http://127.0.0.1:10/spoofdpi.pac\nEnabled: Yes\n", false,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			setThisRunProxy("Wi-Fi", pacURL)
			t.Cleanup(func() { setThisRunProxy("", "") })
			changes := fakeNetworksetup(t, map[string]string{"Wi-Fi": tt.output})

			var logs bytes.Buffer
			CheckSystemProxyLeftoversAfterReset(zerolog.New(&logs))

			assert.Empty(t, *changes)
			if tt.wantWarn {
				assert.Contains(t, logs.String(), `"level":"warn"`)
			} else {
				assert.Empty(t, logs.String())
			}
		})
	}
}

func TestAutoProxyLeftover_RemoveFailures(t *testing.T) {
	const url = "http://127.0.0.1:9/spoofdpi.pac"
	t.Run("error output with exit status 0", func(t *testing.T) {
		orig := runNetworksetup
		t.Cleanup(func() { runNetworksetup = orig })
		runNetworksetup = func(...string) (string, error) {
			return "** Error: Admin authorization required.\n", nil
		}
		assert.Error(t, autoProxyLeftover("Wi-Fi", url, "").Remove())
	})
	t.Run("still enabled after off", func(t *testing.T) {
		orig := runNetworksetup
		t.Cleanup(func() { runNetworksetup = orig })
		runNetworksetup = func(args ...string) (string, error) {
			return "URL: " + url + "\nEnabled: Yes\n", nil
		}
		assert.Error(t, autoProxyLeftover("Wi-Fi", url, "").Remove())
	})
}
