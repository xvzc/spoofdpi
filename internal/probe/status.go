package probe

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// spinnerFrames are the frames of the spinner, one per redraw.
var spinnerFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

const (
	// statusRefresh is how often the status line is redrawn, which
	// advances the spinner.
	statusRefresh = 100 * time.Millisecond
	// barCells is the number of cells of the progress bar.
	barCells = 20
	// defaultStatusWidth is the width of the status line when the width
	// of the terminal is not known.
	defaultStatusWidth = 100
	// clearLine moves to the start of the line and clears it.
	clearLine = "\r\x1b[K"
)

// statusFunc starts showing the progress of the targets with the given
// URLs on stderr. It returns the function that receives the progress
// events, the writer for the lines stderr gets meanwhile, and the
// function that stops showing it and clears it.
type statusFunc func(stderr io.Writer, urls []string) (
	report progressFunc,
	lines io.Writer,
	stop func(),
)

// noStatus shows nothing.
func noStatus(stderr io.Writer, _ []string) (progressFunc, io.Writer, func()) {
	return nil, stderr, func() {}
}

// terminalStatus shows the status line when stderr is a terminal, and
// nothing otherwise.
func terminalStatus(stderr io.Writer, urls []string) (progressFunc, io.Writer, func()) {
	f, ok := stderr.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return noStatus(stderr, urls)
	}
	fd := int(f.Fd())
	width := func() int {
		if w, _, err := term.GetSize(fd); err == nil && w > 0 {
			return w
		}
		return defaultStatusWidth
	}
	s := newStatusLine(stderr, urls, width)
	go s.refresh(statusRefresh)
	return s.report, s, s.Close
}

// statusLine shows the progress of the probe on one line of a terminal,
// rewritten in place: a spinner, a progress bar with the percent done,
// how many targets are done, and what the targets that are not done are
// doing, in short words.
type statusLine struct {
	w io.Writer
	// width returns the width of the terminal; it is read on every
	// redraw, as the terminal may be resized.
	width func() int

	mu sync.Mutex
	// fractions is the fraction of the work done, per target.
	fractions []float64
	// activities is what each target is doing, activityNone when it is
	// done or has not reported yet.
	activities []activity
	done       int
	frame      int
	// drawn is the text on the line, "" when it is clear.
	drawn   string
	closed  bool
	stop    chan struct{}
	stopped chan struct{}
}

func newStatusLine(w io.Writer, urls []string, width func() int) *statusLine {
	return &statusLine{
		w:         w,
		width:     width,
		fractions: make([]float64, len(urls)),
		activities: func() []activity {
			a := make([]activity, len(urls))
			for i := range a {
				a[i] = activityNone
			}
			return a
		}(),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
}

// report records e; the line shows it on the next refresh. The fraction
// of a target never goes back. Each target reports done once.
func (s *statusLine) report(e progressEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.target < 0 || e.target >= len(s.fractions) {
		return
	}
	if e.done {
		s.fractions[e.target] = 1
		s.activities[e.target] = activityNone
		s.done++
		return
	}
	if a, ok := phaseActivity(e.phase); ok {
		s.activities[e.target] = a
	}
	if f, ok := phaseFraction(e.phase); ok {
		s.fractions[e.target] = max(s.fractions[e.target], f)
	}
}

// refresh redraws the line every interval until Close.
func (s *statusLine) refresh(interval time.Duration) {
	defer close(s.stopped)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			s.draw()
			s.mu.Unlock()
		case <-s.stop:
			return
		}
	}
}

// Write writes p, a line for stderr, above the status line.
func (s *statusLine) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clear()
	n, err := s.w.Write(p)
	if !s.closed {
		s.draw()
	}
	return n, err
}

// Close stops redrawing the line and clears it.
func (s *statusLine) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	close(s.stop)
	<-s.stopped

	s.mu.Lock()
	defer s.mu.Unlock()
	s.clear()
}

// clear clears the line. s.mu must be held.
func (s *statusLine) clear() {
	if s.drawn != "" {
		_, _ = io.WriteString(s.w, clearLine)
		s.drawn = ""
	}
}

// draw writes the next frame of the line. s.mu must be held.
func (s *statusLine) draw() {
	text := s.text()
	s.frame++
	_, _ = io.WriteString(s.w, "\r"+text+"\x1b[K")
	s.drawn = text
}

// percent returns the average fraction done over the targets, in percent
// and rounded down, so that 100 means all targets are done.
func (s *statusLine) percent() int {
	if len(s.fractions) == 0 {
		return 100
	}
	sum := 0.0
	for _, f := range s.fractions {
		sum += f
	}
	return int(sum / float64(len(s.fractions)) * 100)
}

// words returns the words for what the targets that are not done are
// doing, each once, in the order of the activities.
func (s *statusLine) words() []string {
	var active [activityCount]bool
	for _, a := range s.activities {
		if a != activityNone {
			active[a] = true
		}
	}
	var words []string
	for a, on := range active {
		if on {
			words = append(words, activityWords[a])
		}
	}
	return words
}

// text returns the line for the current frame, at most one less than
// the width long so that the terminal does not wrap it. When the
// terminal is too narrow the words are dropped from the end, a whole
// word at a time, then the bar, then the line is cut. s.mu must be held.
func (s *statusLine) text() string {
	spinner := string(spinnerFrames[s.frame%len(spinnerFrames)])
	percent := s.percent()
	counts := fmt.Sprintf("%d/%d", s.done, len(s.fractions))
	filled := barCells * percent / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barCells-filled)
	limit := max(s.width()-1, 1)

	withBar := fmt.Sprintf("%s [%s] %3d%%  %s", spinner, bar, percent, counts)
	words := s.words()
	for n := len(words); n >= 0; n-- {
		text := withBar
		if n > 0 {
			text += "  " + strings.Join(words[:n], " · ")
		}
		if len([]rune(text)) <= limit {
			return text
		}
	}
	text := fmt.Sprintf("%s %3d%%  %s", spinner, percent, counts)
	if runes := []rune(text); len(runes) > limit {
		text = string(runes[:limit])
	}
	return text
}
