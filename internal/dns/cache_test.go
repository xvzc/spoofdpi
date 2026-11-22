package dns

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
)

// countingResolver is a backend that counts its lookups and answers each
// with a new address, so that answers of different lookups differ.
type countingResolver struct {
	ttl     uint32
	lookups atomic.Int32
}

func (r *countingResolver) resolve(
	_ context.Context,
	_, _ string,
	_ []uint16,
) ([]netip.Addr, uint32, error) {
	n := r.lookups.Add(1)
	addr := netip.AddrFrom4([4]byte{192, 0, 2, byte(n)})
	return []netip.Addr{addr}, r.ttl, nil
}

// newCountingClient returns a Client whose three backends are fakes.
// The udp and https fakes report ttl.
func newCountingClient(
	ttl uint32,
) (c *Client, udp, https, system *countingResolver) {
	c = NewClient(zerolog.Nop(), &config.DNSOptions{})
	udp = &countingResolver{ttl: ttl}
	https = &countingResolver{ttl: ttl}
	system = &countingResolver{}
	c.udp, c.https, c.system = udp, https, system
	return c, udp, https, system
}

func TestClient_CacheKeyedByOptions(t *testing.T) {
	c, udp, https, system := newCountingClient(60)

	base := config.DNSOptions{
		Mode:     config.DNSModeUDP,
		Addr:     config.MustParseTCPAddr("192.0.2.53:53"),
		HTTPSURL: "https://dns.test/dns-query",
		QType:    config.DNSQueryIPv4,
	}
	otherServer := base
	otherServer.Addr = config.MustParseTCPAddr("192.0.2.54:53")
	otherQType := base
	otherQType.QType = config.DNSQueryAll
	doh := base
	doh.Mode = config.DNSModeHTTPS
	sys := base
	sys.Mode = config.DNSModeSystem

	// Each set of options is looked up: none is served another's answer.
	all := []*config.DNSOptions{&base, &otherServer, &otherQType, &doh, &sys}
	first := map[*config.DNSOptions]netip.Addr{}
	for _, opts := range all {
		addrs, err := c.Resolve(context.Background(), opts, "example.test")
		require.NoError(t, err)
		first[opts] = addrs[0]
	}
	assert.Equal(t, int32(3), udp.lookups.Load())
	assert.Equal(t, int32(1), https.lookups.Load())
	assert.Equal(t, int32(1), system.lookups.Load())

	// Asked again, each is answered from the cache with its own answer.
	for _, opts := range all {
		addrs, err := c.Resolve(context.Background(), opts, "example.test")
		require.NoError(t, err)
		assert.Equal(t, first[opts], addrs[0])
	}
	assert.Equal(t, int32(3), udp.lookups.Load())
	assert.Equal(t, int32(1), https.lookups.Load())
	assert.Equal(t, int32(1), system.lookups.Load())
}

func TestClient_CacheHonoursTTL(t *testing.T) {
	opts := &config.DNSOptions{
		Mode: config.DNSModeUDP,
		Addr: config.MustParseTCPAddr("192.0.2.53:53"),
	}

	t.Run("cached for the record TTL", func(t *testing.T) {
		c, udp, _, _ := newCountingClient(1)
		for range 2 {
			_, err := c.Resolve(context.Background(), opts, "example.test")
			require.NoError(t, err)
		}
		assert.Equal(t, int32(1), udp.lookups.Load())

		time.Sleep(1100 * time.Millisecond)
		_, err := c.Resolve(context.Background(), opts, "example.test")
		require.NoError(t, err)
		assert.Equal(t, int32(2), udp.lookups.Load())
	})

	t.Run("a TTL above 2^31-1 is not cached", func(t *testing.T) {
		c, udp, _, _ := newCountingClient(math.MaxUint32)
		for range 2 {
			_, err := c.Resolve(context.Background(), opts, "example.test")
			require.NoError(t, err)
		}
		assert.Equal(t, int32(2), udp.lookups.Load())
	})

	t.Run("a zero TTL is not cached", func(t *testing.T) {
		c, udp, _, _ := newCountingClient(0)
		for range 2 {
			_, err := c.Resolve(context.Background(), opts, "example.test")
			require.NoError(t, err)
		}
		assert.Equal(t, int32(2), udp.lookups.Load())
	})
}

func TestClient_SystemCachedForFixedTTL(t *testing.T) {
	assert.Equal(t, 30*time.Second, systemCacheTTL)

	c, _, _, system := newCountingClient(60)
	c.systemTTL = time.Second
	opts := &config.DNSOptions{Mode: config.DNSModeSystem}

	for range 2 {
		_, err := c.Resolve(context.Background(), opts, "example.test")
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), system.lookups.Load())

	time.Sleep(c.systemTTL + 100*time.Millisecond)
	_, err := c.Resolve(context.Background(), opts, "example.test")
	require.NoError(t, err)
	assert.Equal(t, int32(2), system.lookups.Load())
}

func TestSystemNetwork(t *testing.T) {
	tcs := []struct {
		qtype config.DNSQueryType
		want  string
	}{
		{config.DNSQueryIPv4, "ip4"},
		{config.DNSQueryIPv6, "ip6"},
		{config.DNSQueryAll, "ip"},
	}
	for _, tc := range tcs {
		t.Run(tc.qtype.String(), func(t *testing.T) {
			assert.Equal(t, tc.want, systemNetwork(parseQueryTypes(tc.qtype)))
		})
	}
	assert.Equal(t, "ip", systemNetwork([]uint16{dns.TypeA, dns.TypeAAAA}))
}

// The system resolver returns IPv4 addresses unmapped, like the others.
func TestSystemResolver_Localhost(t *testing.T) {
	sr := newSystemResolver(zerolog.Nop())
	addrs, ttl, err := sr.resolve(
		context.Background(),
		"",
		"localhost",
		parseQueryTypes(config.DNSQueryIPv4),
	)
	if err != nil {
		t.Skipf("localhost does not resolve here: %v", err)
	}
	assert.Zero(t, ttl)
	require.NotEmpty(t, addrs)
	for _, a := range addrs {
		assert.True(t, a.Is4(), a.String())
	}
}

func TestRecordCacheTTL(t *testing.T) {
	tcs := []struct {
		ttl  uint32
		want time.Duration
	}{
		{0, 0},
		{60, time.Minute},
		{86400, 24 * time.Hour},
		{2 * 86400, 24 * time.Hour}, // capped at a day
		{math.MaxInt32, 24 * time.Hour},
		{math.MaxInt32 + 1, 0}, // RFC 2181, section 8
		{math.MaxUint32, 0},
	}
	for _, tc := range tcs {
		assert.Equal(t, tc.want, recordCacheTTL(tc.ttl), tc.ttl)
	}
}

// answerMsg returns a reply to a query for qType with rcode, holding one
// record with ttl when a is valid.
func answerMsg(qType uint16, rcode int, a netip.Addr, ttl uint32) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion("example.test.", qType)
	msg.Response = true
	msg.Rcode = rcode
	if a.IsValid() {
		hdr := dns.RR_Header{
			Name:   "example.test.",
			Rrtype: qType,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		}
		if a.Is4() {
			msg.Answer = append(msg.Answer, &dns.A{Hdr: hdr, A: a.AsSlice()})
		} else {
			msg.Answer = append(msg.Answer, &dns.AAAA{Hdr: hdr, AAAA: a.AsSlice()})
		}
	}
	return msg
}

func TestProcessMessages_PartialAnswer(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.1")
	okA := &msgChan{msg: answerMsg(dns.TypeA, dns.RcodeSuccess, v4, 300)}

	tcs := []struct {
		name    string
		results []*msgChan
		wantTTL uint32
		wantErr bool
	}{
		{
			name: "both answered",
			results: []*msgChan{
				okA,
				{msg: answerMsg(dns.TypeAAAA, dns.RcodeSuccess, netip.Addr{}, 0)},
			},
			wantTTL: 300,
		},
		{
			name: "AAAA SERVFAIL",
			results: []*msgChan{
				okA,
				{msg: answerMsg(dns.TypeAAAA, dns.RcodeServerFailure, netip.Addr{}, 0)},
			},
			wantTTL: 30,
		},
		{
			name:    "AAAA error",
			results: []*msgChan{okA, {err: errors.New("timeout")}},
			wantTTL: 30,
		},
		{
			name: "a shorter TTL is kept",
			results: []*msgChan{
				{msg: answerMsg(dns.TypeA, dns.RcodeSuccess, v4, 10)},
				{err: errors.New("timeout")},
			},
			wantTTL: 10,
		},
		{
			name: "both SERVFAIL",
			results: []*msgChan{
				{msg: answerMsg(dns.TypeA, dns.RcodeServerFailure, netip.Addr{}, 0)},
				{msg: answerMsg(dns.TypeAAAA, dns.RcodeServerFailure, netip.Addr{}, 0)},
			},
			wantErr: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			resCh := make(chan *msgChan, len(tc.results))
			for _, r := range tc.results {
				resCh <- r
			}
			close(resCh)

			addrs, ttl, err := processMessages(context.Background(), resCh)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []netip.Addr{v4}, addrs)
			assert.Equal(t, tc.wantTTL, ttl)
		})
	}
}
