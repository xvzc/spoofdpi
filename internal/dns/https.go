package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
	"golang.org/x/net/http2"
)

type httpsResolver struct {
	logger zerolog.Logger
	client *http.Client
}

func newHTTPSResolver(logger zerolog.Logger, cfg *config.RuntimeConfig) *httpsResolver {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			NextProtos: []string{"h2", "http/1.1"},
		},
		DialContext: (&net.Dialer{
			Timeout:   cfg.Conn.DNSTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 9 * time.Second,
		MaxIdleConnsPerHost: 100,
		MaxIdleConns:        100,
		ForceAttemptHTTP2:   true,
	}

	if err := http2.ConfigureTransport(tr); err != nil {
		logger.Warn().
			Err(err).
			Msg("failed to configure http2 expressly, falling back to default / http/1.1")
	}

	return &httpsResolver{
		logger: logger,
		client: &http.Client{
			Transport: tr,
			Timeout:   cfg.Conn.DNSTimeout,
		},
	}
}

func (hr *httpsResolver) resolve(
	ctx context.Context,
	server string,
	domain string,
	qTypes []uint16,
) ([]netip.Addr, uint32, error) {
	resCh := lookupAllTypes(ctx, domain, server, qTypes, hr.exchange)
	return processMessages(ctx, resCh)
}

func (hr *httpsResolver) exchange(
	ctx context.Context,
	msg *dns.Msg,
	upstream string,
) (*dns.Msg, error) {
	logger := logging.WithLocalScope(ctx, hr.logger, "doh_exchange")

	pack, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	const maxRetries = 2
	var resp *http.Response
	var reqErr error

	for i := 0; i < maxRetries; i++ {
		req, err := http.NewRequestWithContext(
			ctx,
			http.MethodPost,
			upstream,
			bytes.NewReader(pack),
		)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")

		resp, reqErr = hr.client.Do(req)
		if reqErr == nil {
			break
		}

		if i < maxRetries-1 && isRetryableError(reqErr) {
			continue
		}
	}

	if reqErr != nil {
		return nil, reqErr
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		logger.Trace().
			Int("len", len(body)).
			Int("status", resp.StatusCode).
			Str("body", string(body)).
			Msg("doh status not ok")
		return nil, fmt.Errorf("status code(%d)", resp.StatusCode)
	}

	resultMsg := new(dns.Msg)
	if err := resultMsg.Unpack(body); err != nil {
		return nil, err
	}

	if resultMsg.Rcode != dns.RcodeSuccess && resultMsg.Rcode != dns.RcodeNameError {
		logger.Trace().
			Int("rcode", resultMsg.Rcode).
			Str("msg", resultMsg.String()).
			Msg("doh rcode not ok")
		return nil, fmt.Errorf("Rcode(%d)", resultMsg.Rcode)
	}

	return resultMsg, nil
}

func isRetryableError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "unexpected EOF") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe")
}
