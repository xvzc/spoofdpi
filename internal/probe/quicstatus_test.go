package probe

import (
	"context"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/proto"
)

func quicOut(o quicOutcome) quicAttemptResult { return quicAttemptResult{outcome: o} }

func TestJudgeQUIC(t *testing.T) {
	emfile := quicAttemptResult{outcome: quicLocalError, localErr: syscall.EMFILE}
	built := quicAttemptResult{
		outcome: quicLocalError,
		detail:  "build QUIC ClientHello: boom",
	}
	unknown := func(reason string) QUICResult {
		return QUICResult{Status: QUICUnknown, Reason: reason}
	}
	all := []quicOutcome{
		quicNoReply, quicUnreachable, quicPortUnreachable,
		quicLocalError, quicVersionNegotiation, quicReply,
	}
	for _, benign := range all {
		assert.Equal(t, QUICResult{Status: QUICClear},
			judgeQUIC(quicOut(benign), quicOut(quicReply)), "real reply, benign %d", benign)
		assert.Equal(t, unknown("no QUIC v1"),
			judgeQUIC(quicOut(benign), quicOut(quicVersionNegotiation)), "real VN")
		assert.Equal(t, unknown("local error: "+syscall.EMFILE.Error()),
			judgeQUIC(quicOut(benign), emfile), "real local error")
	}

	for _, site := range []quicOutcome{quicNoReply, quicUnreachable, quicPortUnreachable} {
		for _, tc := range []struct {
			benign quicAttemptResult
			want   QUICResult
		}{
			{quicOut(quicReply), QUICResult{Status: QUICCensored}},
			{quicOut(quicVersionNegotiation), QUICResult{Status: QUICCensored}},
			{built, unknown("local error: build QUIC ClientHello: boom")},
			{quicOut(quicPortUnreachable), unknown("no QUIC")},
			{quicOut(quicNoReply), unknown("no reply")},
		} {
			assert.Equal(t, tc.want, judgeQUIC(tc.benign, quicOut(site)),
				"benign %d, real %d", tc.benign.outcome, site)
		}
	}

	assert.Equal(t, QUICResult{Status: QUICUnreachable},
		judgeQUIC(quicOut(quicUnreachable), quicOut(quicUnreachable)))
	assert.Equal(t, unknown("no reply"),
		judgeQUIC(quicOut(quicUnreachable), quicOut(quicNoReply)))
	assert.Equal(t, unknown("no reply"),
		judgeQUIC(quicOut(quicNoReply), quicOut(quicUnreachable)))
}

// scriptedQUIC answers the Initials of the QUIC check from scripts of
// outcomes per server name, the last one repeating, and records them.
type scriptedQUIC struct {
	mu      sync.Mutex
	scripts map[string][]quicOutcome
	sent    []string
	servers []netip.AddrPort
}

func (s *scriptedQUIC) attempts(server netip.AddrPort) quicAttemptFunc {
	s.mu.Lock()
	s.servers = append(s.servers, server)
	s.mu.Unlock()
	return func(_ context.Context, sni string) quicAttemptResult {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.sent = append(s.sent, sni)
		script := s.scripts[sni]
		o := script[0]
		if len(script) > 1 {
			s.scripts[sni] = script[1:]
		}
		return quicOut(o)
	}
}

func (s *scriptedQUIC) count(sni string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, sent := range s.sent {
		if sent == sni {
			n++
		}
	}
	return n
}

func TestQUICTry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		script []quicOutcome
		want   quicOutcome
		tries  int
	}{
		{"first reply", []quicOutcome{quicReply}, quicReply, 1},
		{"reply on the third", []quicOutcome{quicNoReply, quicNoReply, quicReply}, quicReply, 3},
		{"VN stops", []quicOutcome{quicNoReply, quicVersionNegotiation}, quicVersionNegotiation, 2},
		{"local error stops", []quicOutcome{quicNoReply, quicLocalError}, quicLocalError, 2},
		{"never answered", []quicOutcome{quicNoReply}, quicNoReply, quicTries},
		{
			"ICMP tells more than silence",
			[]quicOutcome{quicUnreachable, quicNoReply, quicNoReply},
			quicUnreachable,
			quicTries,
		},
		{
			"port unreachable tells more than unreachable",
			[]quicOutcome{quicUnreachable, quicPortUnreachable, quicNoReply},
			quicPortUnreachable,
			quicTries,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &scriptedQUIC{scripts: map[string][]quicOutcome{"a.test": tc.script}}
			got := quicTry(context.Background(), s.attempts(netip.AddrPort{}), "a.test")
			assert.Equal(t, tc.want, got.outcome)
			assert.Equal(t, tc.tries, s.count("a.test"))
		})
	}
}

func quicProber(s *scriptedQUIC) *Prober {
	p := testProber(nil, nil)
	p.quicAttempts = s.attempts
	p.residual = residualWait{
		recheck: 20 * time.Millisecond,
		limit:   100 * time.Millisecond,
	}
	return p
}

func TestMeasureQUIC(t *testing.T) {
	addr := netip.MustParseAddr("203.0.113.1")
	s := &scriptedQUIC{scripts: map[string][]quicOutcome{
		benignSNI: {quicReply},
		"a.test":  {quicNoReply},
	}}
	got := quicProber(s).measureQUIC(
		context.Background(), target(t, "a.test"), addr, "", targetProgress{})
	assert.Equal(t, QUICResult{Status: QUICCensored}, got)
	assert.Equal(t,
		[]string{benignSNI, "a.test", "a.test", "a.test"}, s.sent, "benign first")
	assert.Equal(t, []netip.AddrPort{netip.AddrPortFrom(addr, 443)}, s.servers)
}

func TestMeasureQUIC_Residual(t *testing.T) {
	addr := netip.MustParseAddr("203.0.113.1")
	t.Run("cleared at once", func(t *testing.T) {
		s := &scriptedQUIC{scripts: map[string][]quicOutcome{
			benignSNI: {quicReply},
			"a.test":  {quicReply},
		}}
		got := quicProber(s).measureQUIC(
			context.Background(), target(t, "a.test"), addr, "b.test", targetProgress{})
		assert.Equal(t, QUICResult{Status: QUICClear}, got, "no note")
	})

	t.Run("cleared after waiting", func(t *testing.T) {
		s := &scriptedQUIC{scripts: map[string][]quicOutcome{
			benignSNI: {quicNoReply, quicNoReply, quicReply},
			"a.test":  {quicReply},
		}}
		var mu sync.Mutex
		var phases []string
		progress := targetProgress{report: func(e progressEvent) {
			mu.Lock()
			defer mu.Unlock()
			phases = append(phases, e.phase)
		}}
		got := quicProber(s).measureQUIC(
			context.Background(), target(t, "a.test"), addr, "b.test", progress)
		assert.Equal(t, QUICClear, got.Status)
		require.Len(t, got.Notes, 1)
		assert.Regexp(t, `^waited \d+s for residual block from b.test$`, got.Notes[0])
		assert.Equal(t, 3, s.count(benignSNI), "one benign Initial per round")
		assert.Contains(t, phases, "waiting for residual block")
		assert.Equal(t, "quic", phases[len(phases)-1], "back to the check after the wait")
	})

	t.Run("not cleared", func(t *testing.T) {
		s := &scriptedQUIC{scripts: map[string][]quicOutcome{
			benignSNI: {quicNoReply},
			"a.test":  {quicReply},
		}}
		got := quicProber(s).measureQUIC(
			context.Background(), target(t, "a.test"), addr, "b.test", targetProgress{})
		assert.Equal(t, QUICResult{
			Status: QUICSkipped,
			Notes:  []string{"residual block from b.test (not cleared after 0s)"},
		}, got)
		assert.Zero(t, s.count("a.test"), "the real Initial is not sent")
	})

	t.Run("local error ends the wait", func(t *testing.T) {
		s := &scriptedQUIC{scripts: map[string][]quicOutcome{
			benignSNI: {quicLocalError},
			"a.test":  {quicNoReply},
		}}
		got := quicProber(s).measureQUIC(
			context.Background(), target(t, "a.test"), addr, "b.test", targetProgress{})
		assert.Equal(t, QUICUnknown, got.Status)
		assert.Equal(t, 1, s.count(benignSNI))
	})
}

func TestMeasureQUIC_Interrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := testProber(nil, nil)
	p.quicAttempts = func(netip.AddrPort) quicAttemptFunc {
		return func(context.Context, string) quicAttemptResult {
			cancel()
			return quicOut(quicNoReply)
		}
	}
	got := p.measureQUIC(ctx, target(t, "a.test"),
		netip.MustParseAddr("203.0.113.1"), "", targetProgress{})
	assert.Equal(t, QUICResult{}, got)
}

// answerQUIC answers a client Initial with a QUIC v1 packet of type
// typ to its source connection ID, after a datagram that does not answer
// it.
func answerQUIC(typ proto.QUICPacketType) func(req []byte) [][]byte {
	return func(req []byte) [][]byte {
		h, err := proto.ParseQUICLongHeader(req)
		if err != nil {
			return nil
		}
		reply := []byte{0xc0 | byte(typ)<<4, 0, 0, 0, 1, byte(len(h.SCID))}
		reply = append(reply, h.SCID...)
		reply = append(reply, 4, 1, 2, 3, 4, 0, 0x40, 0x20)
		reply = append(reply, make([]byte, 32)...)
		other := []byte{0xc0, 0, 0, 0, 1, 1, 0xee, 0, 0, 0x40, 0x20}
		return [][]byte{other, reply}
	}
}

func TestQUICAttempt(t *testing.T) {
	p := testProber(nil, dialer("udp4"))
	p.cfg.Timeout = 300 * time.Millisecond

	for _, tc := range []struct {
		name   string
		server func(t *testing.T) netip.AddrPort
		want   quicOutcome
	}{
		{
			name:   "Initial",
			server: func(t *testing.T) netip.AddrPort { return quicServer(t, answerQUIC(proto.QUICInitial)) },
			want:   quicReply,
		},
		{
			name:   "Retry",
			server: func(t *testing.T) netip.AddrPort { return quicServer(t, answerQUIC(proto.QUICRetry)) },
			want:   quicReply,
		},
		{
			name: "Version Negotiation",
			server: func(t *testing.T) netip.AddrPort {
				return quicServer(t, func(req []byte) [][]byte {
					h, err := proto.ParseQUICLongHeader(req)
					if err != nil {
						return nil
					}
					return [][]byte{
						versionNegotiation(h.SCID, []byte{9}, 0x6b3343cf),
						versionNegotiation(h.SCID, h.DCID, 0x6b3343cf),
					}
				})
			},
			want: quicVersionNegotiation,
		},
		{
			name: "silence",
			server: func(t *testing.T) netip.AddrPort {
				return quicServer(t, func([]byte) [][]byte { return nil })
			},
			want: quicNoReply,
		},
		{name: "closed port", server: closedUDPPort, want: quicPortUnreachable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := p.quicAttempt(tc.server(t))(context.Background(), "a.test")
			assert.Equal(t, tc.want, got.outcome)
		})
	}
}

func TestQUICAnswer(t *testing.T) {
	dcid, scid := []byte{1, 2, 3, 4}, []byte{5, 6, 7, 8}
	o, ok := quicAnswer(versionNegotiation(scid, dcid, 0x6b3343cf), dcid, scid)
	assert.True(t, ok)
	assert.Equal(t, quicVersionNegotiation, o)

	_, ok = quicAnswer(
		versionNegotiation(scid, dcid, 0x6b3343cf, proto.QUICVersion1), dcid, scid)
	assert.False(t, ok, "a Version Negotiation that lists version 1 is ignored")
	_, ok = quicAnswer(versionNegotiation(dcid, scid, 0x6b3343cf), dcid, scid)
	assert.False(t, ok, "IDs not echoed")
}

func TestQUICAttempt_IgnoresVersionNegotiationListingV1(t *testing.T) {
	addr := quicServer(t, func(req []byte) [][]byte {
		h, err := proto.ParseQUICLongHeader(req)
		if err != nil {
			return nil
		}
		return [][]byte{versionNegotiation(h.SCID, h.DCID, proto.QUICVersion1)}
	})
	p := testProber(nil, dialer("udp4"))
	p.cfg.Timeout = 100 * time.Millisecond
	got := p.quicAttempt(addr)(context.Background(), "a.test")
	assert.Equal(t, quicNoReply, got.outcome)
}

func TestQUICAttempt_SendsInitial(t *testing.T) {
	got := make(chan []byte, 1)
	addr := quicServer(t, func(req []byte) [][]byte {
		select {
		case got <- append([]byte(nil), req...):
		default:
		}
		return nil
	})
	p := testProber(nil, dialer("udp4"))
	p.cfg.Timeout = 100 * time.Millisecond
	p.quicAttempt(addr)(context.Background(), "a.test")

	req := <-got
	assert.Len(t, req, proto.QUICMinInitialSize)
	h, err := proto.ParseQUICLongHeader(req)
	require.NoError(t, err)
	assert.Equal(t, proto.QUICInitial, h.Type)
	assert.Equal(t, proto.QUICVersion1, h.Version)
}
