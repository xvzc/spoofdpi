package probe

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStatusLine(n int, width *int) *statusLine {
	urls := make([]string, n)
	return newStatusLine(&bytes.Buffer{}, urls, func() int { return *width })
}

func TestStatusLine_Text(t *testing.T) {
	width := 200
	s := newTestStatusLine(5, &width)
	s.done = 2
	s.fractions = []float64{1, 1, 0.5, 0.2, 0.2} // 2.9/5 = 58%

	assert.Equal(t, "⠋ [███████████░░░░░░░░░]  58%  2/5", s.text())
	assert.Equal(t, "⠙ [███████████░░░░░░░░░]  58%  2/5", func() string {
		s.frame++
		return s.text()
	}(), "the spinner advances on each frame")

	s.frame = len(spinnerFrames)
	assert.Contains(t, s.text(), "⠋", "the spinner wraps around")
}

func TestStatusLine_TextBounds(t *testing.T) {
	width := 200
	s := newTestStatusLine(2, &width)
	assert.Equal(t, "⠋ [░░░░░░░░░░░░░░░░░░░░]   0%  0/2", s.text())

	s.report(progressEvent{target: 0, done: true})
	s.report(progressEvent{target: 1, done: true})
	assert.Equal(t, "⠋ [████████████████████] 100%  2/2", s.text())
}

func TestStatusLine_TextNarrow(t *testing.T) {
	width := 200
	s := newTestStatusLine(5, &width)
	s.done = 2
	s.fractions = []float64{1, 1, 0.5, 0.2, 0.2}

	width = 20
	assert.Equal(t, "⠋  58%  2/5", s.text(), "the bar is dropped first")
	width = 8
	assert.Equal(t, "⠋  58% ", s.text(), "one less than the width, then cut")
	width = 0
	assert.Equal(t, "⠋", s.text())
}

func TestStatusLine_Report(t *testing.T) {
	width := 200
	s := newTestStatusLine(2, &width)

	s.report(progressEvent{target: 0, phase: "dpi chunks 20 bytes"})
	assert.InDelta(t, 0.22, s.fractions[0], 1e-9)
	s.report(progressEvent{target: 0, phase: "hops"})
	assert.InDelta(t, 0.22, s.fractions[0], 1e-9, "never goes back")

	s.report(progressEvent{target: 0, phase: "dpi chunks 40 bytes"})
	s.report(progressEvent{
		target: 0, phase: "waiting for residual block",
		waitStart: time.Now(), waitLimit: time.Minute,
	})
	assert.InDelta(t, 0.22, s.fractions[0], 1e-9, "waiting keeps the fraction")
	s.report(progressEvent{target: 0, phase: "dpi residual check"})
	assert.InDelta(t, 0.22, s.fractions[0], 1e-9, "unlisted phases keep the fraction")

	s.report(progressEvent{target: 0, phase: "server tls13"})
	assert.InDelta(t, 0.80, s.fractions[0], 1e-9, "skipped phases jump ahead")

	s.report(progressEvent{target: 1, done: true})
	assert.Equal(t, 1, s.done)
	assert.Equal(t, 1.0, s.fractions[1], "a finished target is at 100%")
	assert.Equal(t, 90, s.percent())

	s.report(progressEvent{target: 7, phase: "hops"})
	s.report(progressEvent{target: -1, done: true})
	assert.Equal(t, 1, s.done, "unknown targets are ignored")
}

func TestStatusLine_WriteAndClose(t *testing.T) {
	var out bytes.Buffer
	s := newStatusLine(&out, []string{"a.test"}, func() int { return 100 })
	go s.refresh(5 * time.Millisecond)

	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.drawn != ""
	}, 5*time.Second, 5*time.Millisecond)

	_, err := s.Write([]byte("probe: warning: something\n"))
	require.NoError(t, err)
	s.Close()
	s.Close()

	got := out.String()
	assert.Contains(t, got, "\r⠋ [░░░░░░░░░░░░░░░░░░░░]   0%  0/1\x1b[K")
	assert.Contains(t, got, clearLine+"probe: warning: something\n\r",
		"the line is cleared before a warning, and drawn again after it")
	assert.True(t, strings.HasSuffix(got, clearLine), "Close clears the line")
}

func TestTerminalStatus_NotATerminal(t *testing.T) {
	var buf bytes.Buffer
	report, lines, stop := terminalStatus(&buf, []string{"a.test"})
	assert.Nil(t, report)
	assert.Same(t, &buf, lines)
	stop()

	f, err := os.CreateTemp(t.TempDir(), "stderr")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	report, lines, stop = terminalStatus(f, []string{"a.test"})
	assert.Nil(t, report, "a file is not a terminal")
	assert.Same(t, f, lines)
	stop()
}

func TestPhaseActivity(t *testing.T) {
	for _, tc := range []struct {
		phase string
		want  activity
	}{
		{"resolving", activityResolving},
		{"hops", activityHops},
		{"quic", activityQUIC},
		{"queued for checks", activityQUIC},
		{"dpi connect", activityDPI},
		{"dpi baseline", activityDPI},
		{"dpi block", activityDPI},
		{"dpi chunks 20 bytes", activityDPI},
		{"dpi disorder 1 bytes", activityDPI},
		{"dpi position TTL 3", activityDPI},
		{"dpi residual check", activityDPI},
		{"preparing fake packets", activityFake},
		{"dpi fake seq", activityFake},
		{"server preparing fake packets", activityServer},
		{"server tls13", activityServer},
		{"waiting for residual block", activityResidualWait},
	} {
		got, ok := phaseActivity(tc.phase)
		assert.True(t, ok, tc.phase)
		assert.Equal(t, tc.want, got, tc.phase)
	}
	_, ok := phaseActivity("something else")
	assert.False(t, ok)
}

func TestStatusLine_Words(t *testing.T) {
	width := 200
	s := newTestStatusLine(5, &width)
	assert.Equal(
		t,
		"⠋ [░░░░░░░░░░░░░░░░░░░░]   0%  0/5",
		s.text(),
		"no words when nothing is active",
	)

	s.report(progressEvent{target: 0, phase: "dpi block"})
	s.report(progressEvent{target: 1, phase: "hops"})
	s.report(progressEvent{target: 2, phase: "dpi chunks 20 bytes"})
	assert.Equal(t, []string{"measuring hops", "checking DPI"}, s.words(),
		"deduplicated, in the fixed order")

	s.report(progressEvent{target: 3, phase: "preparing fake packets"})
	s.report(progressEvent{target: 4, phase: "resolving"})
	assert.Equal(t,
		[]string{"resolving", "measuring hops", "checking DPI", "testing fake packets"},
		s.words())

	s.report(progressEvent{target: 2, phase: "quic"})
	assert.Equal(t,
		[]string{
			"resolving", "measuring hops", "checking QUIC", "checking DPI",
			"testing fake packets",
		},
		s.words(), "checking QUIC goes between measuring hops and checking DPI")
	s.report(progressEvent{target: 2, phase: "dpi chunks 20 bytes"})
	assert.Contains(
		t,
		s.text(),
		"0/5  resolving · measuring hops · checking DPI · testing fake packets",
	)

	s.report(progressEvent{target: 3, phase: "preparing fake packets"})
	s.report(progressEvent{target: 3, phase: "waiting for residual block"})
	assert.Contains(t, s.words(), "waiting for residual block")
}

func TestStatusLine_WordsServerDisambiguation(t *testing.T) {
	width := 200
	s := newTestStatusLine(1, &width)
	s.report(progressEvent{target: 0, phase: "preparing fake packets"})
	s.report(progressEvent{target: 0, phase: "dpi fake seq"})
	assert.Equal(t, []string{"testing fake packets"}, s.words())
	s.report(progressEvent{target: 0, phase: "server preparing fake packets"})
	assert.Equal(t, []string{"checking server"}, s.words())
}

func TestStatusLine_WordsActiveOnly(t *testing.T) {
	width := 200
	s := newTestStatusLine(2, &width)
	s.report(progressEvent{target: 0, phase: "hops"})
	s.report(progressEvent{target: 1, phase: "server tls13"})
	s.report(progressEvent{target: 1, done: true})
	assert.Equal(t, []string{"measuring hops"}, s.words())
	s.report(progressEvent{target: 0, done: true})
	assert.Empty(t, s.words())
}

func TestStatusLine_WordsNarrow(t *testing.T) {
	width := 200
	s := newTestStatusLine(5, &width)
	s.done = 2
	s.report(progressEvent{target: 2, phase: "hops"})
	s.report(progressEvent{target: 3, phase: "dpi block"})
	s.report(progressEvent{target: 4, phase: "server tls13"})
	s.fractions = []float64{1, 1, 0.5, 0.2, 0.2}

	full := "⠋ [███████████░░░░░░░░░]  58%  2/5  measuring hops · checking DPI · checking server"
	assert.Equal(t, full, s.text())

	bar := "⠋ [███████████░░░░░░░░░]  58%  2/5"
	width = len([]rune(full)) // one less than this fits
	assert.Equal(
		t,
		bar+"  measuring hops · checking DPI",
		s.text(),
		"the last word goes first",
	)
	width = len([]rune(bar + "  measuring hops · checking DPI"))
	assert.Equal(t, bar+"  measuring hops", s.text(), "then the next to last")
	width = len([]rune(bar + "  measuring hops"))
	assert.Equal(t, bar, s.text(), "no partial words, words go before the bar")
	width = len([]rune(bar))
	assert.Equal(t, "⠋  58%  2/5", s.text(), "then the bar")
	width = 8
	assert.Equal(t, "⠋  58% ", s.text(), "then cut")
}
