package proto

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readTestRequest(t *testing.T, head string) *HTTPRequest {
	t.Helper()
	req, err := ReadHttpRequest(strings.NewReader(
		"GET http://origin.test/ HTTP/1.1\r\nHost: origin.test\r\n" + head + "\r\n",
	))
	require.NoError(t, err)
	return req
}

func TestHTTPRequest_IsUpgrade(t *testing.T) {
	tcs := []struct {
		name string
		head string
		want bool
	}{
		{"no connection header", "", false},
		{"keep-alive", "Connection: keep-alive\r\n", false},
		{"upgrade", "Connection: Upgrade\r\nUpgrade: websocket\r\n", true},
		{"upgrade among options", "Connection: keep-alive, Upgrade\r\n", true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, readTestRequest(t, tc.head).IsUpgrade())
		})
	}
}

func TestHTTPRequest_SetConnectionClose(t *testing.T) {
	req := readTestRequest(t,
		"Connection: keep-alive, X-Hop\r\n"+
			"Keep-Alive: timeout=5\r\n"+
			"Proxy-Connection: keep-alive\r\n"+
			"X-Hop: 1\r\n"+
			"X-End: 1\r\n",
	)

	req.SetConnectionClose()

	var buf bytes.Buffer
	require.NoError(t, req.WriteProxy(&buf))
	written, err := http.ReadRequest(bufio.NewReader(&buf))
	require.NoError(t, err)

	assert.True(t, written.Close)
	assert.Equal(t, []string{"close"}, written.Header.Values("Connection"))
	assert.Empty(t, written.Header.Values("Keep-Alive"))
	assert.Empty(t, written.Header.Values("Proxy-Connection"))
	assert.Empty(
		t,
		written.Header.Values("X-Hop"),
		"a header Connection names is dropped",
	)
	assert.Equal(t, "1", written.Header.Get("X-End"))
}

func TestHTTPRequest_ExtractHost(t *testing.T) {
	tcs := []struct {
		host string
		want string
	}{
		{"origin.test", "origin.test"},
		{"origin.test:8080", "origin.test"},
		{"192.0.2.1", "192.0.2.1"},
		{"192.0.2.1:8080", "192.0.2.1"},
		{"[::1]", "::1"},
		{"[::1]:8080", "::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[fe80::1%en0]", "fe80::1%en0"},
		{"[]", "[]"},
	}
	for _, tc := range tcs {
		t.Run(tc.host, func(t *testing.T) {
			req := &HTTPRequest{Request: &http.Request{Host: tc.host}}
			assert.Equal(t, tc.want, req.ExtractHost())
		})
	}
}
