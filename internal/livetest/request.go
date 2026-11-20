package livetest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
)

// outcome is the result of one request.
type outcome struct {
	status int   // HTTP status, if a response arrived
	err    error // otherwise, why not
}

// request sends one GET request for target through spoofdpi. Every request
// uses a new connection, so each one goes through a new TLS handshake.
// Redirects are not followed: any response means the handshake passed.
func request(ctx context.Context, opts Options, target string) outcome {
	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL(opts)),
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return outcome{err: err}
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return outcome{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return outcome{status: resp.StatusCode}
}

// proxyURL is the address of spoofdpi's proxy for opts.Mode.
func proxyURL(opts Options) *url.URL {
	proxy := &url.URL{Scheme: "http", Host: opts.Listen}
	if opts.Mode == "socks5" {
		proxy.Scheme = "socks5"
	}
	return proxy
}

// result is the outcome of every request for one case and URL.
type result struct {
	caseLabel string
	url       string
	// tries counts the requests and ok the ones that got a response.
	tries int
	ok    int
	// outcomes counts outcomes by label: an HTTP status, "timeout",
	// "reset" or "error".
	outcomes map[string]int
	order    []string
	// warns and errs count the warnings and errors spoofdpi logged during
	// the case.
	warns, errs int
}

func (r *result) add(o outcome) {
	r.tries++
	label := o.label()
	if o.err == nil {
		r.ok++
	}
	if r.outcomes == nil {
		r.outcomes = map[string]int{}
	}
	if r.outcomes[label] == 0 {
		r.order = append(r.order, label)
	}
	r.outcomes[label]++
}

func (o outcome) label() string {
	if o.err == nil {
		return strconv.Itoa(o.status)
	}
	var ue *url.Error
	if errors.As(o.err, &ue) && ue.Timeout() {
		return "timeout"
	}
	if errors.Is(o.err, context.DeadlineExceeded) {
		return "timeout"
	}
	if isReset(o.err) {
		return "reset"
	}
	return "error"
}

func isReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		strings.Contains(err.Error(), "connection reset") ||
		strings.Contains(err.Error(), "EOF")
}

// summary formats the outcomes, for example "200x9 timeout".
func (r result) summary() string {
	var b strings.Builder
	for i, label := range r.order {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(label)
		if n := r.outcomes[label]; n > 1 {
			fmt.Fprintf(&b, "x%d", n)
		}
	}
	return b.String()
}
