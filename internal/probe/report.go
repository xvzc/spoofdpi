package probe

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"syscall"
)

// localErrnoNames are the names of the errors in localErrnos.
var localErrnoNames = map[syscall.Errno]string{
	syscall.EMFILE:        "EMFILE",
	syscall.ENFILE:        "ENFILE",
	syscall.ENOBUFS:       "ENOBUFS",
	syscall.ENOMEM:        "ENOMEM",
	syscall.EADDRNOTAVAIL: "EADDRNOTAVAIL",
	syscall.EADDRINUSE:    "EADDRINUSE",
}

// WriteReport prints one block per result, separated by blank lines: a
// header with the URL and the probed address, then a section per protocol,
// https and quic, each when there is something to show. The https section
// has the verdict of the DPI checks, the TCP hop counts, a dpi subsection
// with what the DPI checks found and a server subsection with how the
// server handles fake packets. The quic section has the verdict of the
// QUIC check and the UDP hop counts.
func WriteReport(w io.Writer, results []Result) error {
	var b strings.Builder
	for i, r := range results {
		if i > 0 {
			b.WriteString("\n")
		}
		writeBlock(&b, r)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// line is a named line of a section. A line with sub lines is a
// subsection: its name heads them, and it has no value.
type line struct {
	name, value string
	sub         []line
	// subWidth is the width of the names of the sub lines.
	subWidth int
}

// nameWidth is the width of the names of the dpi lines, the longest one.
const nameWidth = len("position")

// protocolWidth is the width of the names of the lines of a protocol
// section. They are indented 2 less than the dpi lines, so their values
// start at the same column.
const protocolWidth = nameWidth + 2

// variantWidth is the width of the names of the fake lines and of the
// server lines, one past the longest, so that their values stand off as
// far as those of the other lines.
const variantWidth = len("seq_offset") + 1

// protocolSections build the sections of a block, in order.
var protocolSections = []struct {
	name  string
	lines func(Result) []line
}{
	{"https", httpsSection},
	{"quic", quicSection},
}

// writeBlock writes the block of r.
func writeBlock(b *strings.Builder, r Result) {
	if r.AddrNote != "" {
		fmt.Fprintf(b, "%s (%s)\n", r.Target.Input, addrNote(r.AddrNote))
		return
	}
	fmt.Fprintf(b, "%s (%s)\n", r.Target.Input, r.Addr)
	var sections []line
	for _, s := range protocolSections {
		if lines := s.lines(r); len(lines) > 0 {
			sections = append(
				sections,
				line{name: s.name, sub: lines, subWidth: protocolWidth},
			)
		}
	}
	writeLines(b, 2, 0, sections)
}

// writeLines writes lines indented by indent, with names width wide, and
// the sub lines of each subsection indented 2 more.
func writeLines(b *strings.Builder, indent, width int, lines []line) {
	for _, l := range lines {
		if len(l.sub) == 0 {
			fmt.Fprintf(b, "%*s%-*s  %s\n", indent, "", width, l.name, l.value)
			continue
		}
		fmt.Fprintf(b, "%*s%s\n", indent, "", l.name)
		writeLines(b, indent+2, l.subWidth, l.sub)
	}
}

// httpsSection returns the lines of the https section: the status line
// with the verdict of the DPI checks, a note line when there is no dpi
// subsection to hold it, the TCP hop counts, the dpi subsection and the
// server line or subsection.
func httpsSection(r Result) []line {
	var lines, dpi []line
	if r.DPI.Measured {
		lines, dpi = dpiLines(r.DPI)
	}
	if cell, ok := tcpCell(r); ok {
		lines = append(lines, line{name: "hops(tcp)", value: cell})
	}
	if len(dpi) > 0 {
		lines = append(lines, line{name: "dpi", sub: dpi, subWidth: nameWidth})
	}
	if r.Server.Measured {
		if value, whole := serverValue(r.Server); whole {
			lines = append(lines, line{name: "server", value: value})
		} else {
			lines = append(
				lines,
				line{name: "server", sub: serverLines(r.Server), subWidth: variantWidth},
			)
		}
	}
	return lines
}

// quicSection returns the lines of the quic section: the status line with
// the verdict of the QUIC check, its notes and the UDP hop counts.
func quicSection(r Result) []line {
	var lines []line
	if status := quicStatusValue(r.QUIC); status != "" {
		lines = append(lines, line{name: "status", value: status})
	}
	if len(r.QUIC.Notes) > 0 {
		lines = append(lines, line{name: "note", value: strings.Join(r.QUIC.Notes, "; ")})
	}
	if cell, ok := udpCell(r); ok {
		lines = append(lines, line{name: "hops(udp)", value: cell})
	}
	return lines
}

// quicStatusValue returns the value of the status line of the quic
// section, or "" when the check did not run.
func quicStatusValue(q QUICResult) string {
	switch q.Status {
	case QUICClear:
		return "clear"
	case QUICCensored:
		return "censored"
	case QUICUnreachable:
		return "unreachable"
	case QUICUnknown:
		return "unknown (" + failureNote(q.Reason) + ")"
	case QUICSkipped:
		return "?"
	}
	return ""
}

// tcpCell returns the value of the hops(tcp) line. There is none when
// TCP is not measured, or when no connection completed and the status line
// says so.
func tcpCell(r Result) (string, bool) {
	switch r.TCP.Status {
	case TCPNotMeasured:
		return "", false
	case TCPNoHandshake:
		if r.DPI.Block.State == StepDone && r.DPI.Block.Kind == BlockUnreachable {
			return "", false
		}
		if r.TCP.Reason == "unreachable" {
			return "unreachable", true
		}
		return "no handshake (" + failureNote(r.TCP.Reason) + ")", true
	}
	actual := strconv.Itoa(r.TCP.Hops) + " actual"
	if r.TCP.Status == TCPAboveMax {
		actual = "over " + actual
	}
	delta, mismatch := r.TCPMismatch()
	return hopCell(
		actual,
		r.TCP.Unstable,
		r.TCP.LocalError,
		r.TCPLearned,
		delta,
		mismatch,
	), true
}

// udpCell returns the value of the hops(udp) line, if UDP is measured.
func udpCell(r Result) (string, bool) {
	switch r.UDP.Status {
	case UDPNotMeasured:
		return "", false
	case UDPNoReply:
		switch r.UDP.Reason {
		case "no reply", "unreachable":
			return r.UDP.Reason, true
		}
		return "no reply (" + failureNote(r.UDP.Reason) + ")", true
	}
	actual := strconv.Itoa(r.UDP.Hops) + " actual"
	if r.UDP.Status == UDPAboveMax {
		actual = "over " + actual
	}
	delta, mismatch := r.UDPMismatch()
	return hopCell(
		actual,
		r.UDP.Unstable,
		r.UDP.LocalError,
		r.UDPLearned,
		delta,
		mismatch,
	), true
}

// hopCell returns "ACTUAL / LEARNED", with the reasons to note in one
// parenthesis.
func hopCell(
	actual string,
	unstable bool,
	localErr string,
	learned LearnedResult,
	delta int,
	mismatch bool,
) string {
	learnedPart := "-"
	if learned.Status == Learned {
		learnedPart = strconv.Itoa(int(learned.Hops)) + " learned"
	}

	var reasons []string
	if mismatch {
		reasons = append(reasons, fmt.Sprintf("gap %+d", delta))
	}
	if unstable {
		reasons = append(reasons, "path varies")
	}
	if localErr != "" {
		reasons = append(reasons, "local error "+localErrorName(localErr))
	}
	switch learned.Status {
	case LearnedNotCaptured, LearnedNoUDPReply:
		reasons = append(reasons, "not learned")
	case Learned:
		if len(learned.Seen) > 1 {
			seen := make([]string, len(learned.Seen))
			for i, h := range learned.Seen {
				seen[i] = strconv.Itoa(int(h))
			}
			reasons = append(reasons, "learned varies "+strings.Join(seen, ","))
		}
	}

	cell := actual + " / " + learnedPart
	if len(reasons) > 0 {
		cell += " (" + strings.Join(reasons, ", ") + ")"
	}
	return cell
}

// dpiLines returns the status line and the lines of the dpi subsection,
// in the order the checks run, without those of checks that did not run.
// The dpi subsection is only there for a censored site. When it is left
// out, its notes go under the status line.
func dpiLines(d DPIResult) (top, dpi []line) {
	status, detailed := statusValue(d.Block)
	if status != "" {
		top = append(top, line{name: "status", value: status})
	}
	var note []line
	if len(d.Notes) > 0 {
		note = []line{{name: "note", value: strings.Join(d.Notes, "; ")}}
	}
	if !detailed {
		return append(top, note...), nil
	}

	add := func(name string, state StepState, done func() string) {
		switch state {
		case StepDone:
			dpi = append(dpi, line{name: name, value: done()})
		case StepSkipped:
			dpi = append(dpi, line{name: name, value: "?"})
		}
	}
	add("type", d.Block.State, func() string { return typeValue(d.Block) })
	add("chunks", d.Chunks.State, func() string { return chunksValue(d.Chunks) })
	add("disorder", d.Disorder.State, func() string {
		return disorderValue(d.Disorder, d.Chunks)
	})
	add("position", d.Position.State, func() string { return positionValue(d.Position) })
	if l, ok := fakeLine(d.Fake); ok {
		dpi = append(dpi, l)
	}
	return top, append(dpi, note...)
}

// fakeLine returns the fake line of the dpi subsection, a subsection with
// a line per fake tried, if the check ran.
func fakeLine(f FakeResult) (line, bool) {
	switch {
	case f.State == StepSkipped:
		return line{name: "fake", value: "?"}, true
	case f.State != StepDone:
		return line{}, false
	case f.Reason != "":
		return line{name: "fake", value: "unknown (" + f.Reason + ")"}, true
	}
	l := line{name: "fake", subWidth: variantWidth}
	l.sub = appendRun(l.sub, "ttl", f.TTL.State, fakeVariantValue(f.TTL))
	l.sub = appendRun(
		l.sub,
		"seq_offset",
		f.SeqOffset.State,
		fakeOffsetValue(f.SeqOffset),
	)
	l.sub = appendRun(
		l.sub,
		"ack_offset",
		f.AckOffset.State,
		fakeOffsetValue(f.AckOffset),
	)
	l.sub = appendRun(l.sub, "bad_md5", f.BadMD5.State, fakeVariantValue(f.BadMD5))
	return l, true
}

// appendRun appends the line name with value to lines, if its check ran.
func appendRun(lines []line, name string, state StepState, value string) []line {
	if state == StepNotRun {
		return lines
	}
	return append(lines, line{name: name, value: value})
}

func fakeVariantValue(v FakeVariantResult) string {
	switch {
	case v.Reason != "":
		return "unknown (" + v.Reason + ")"
	case v.Pass:
		return "ok"
	}
	return "x"
}

func fakeOffsetValue(o FakeOffsetResult) string {
	switch {
	case o.State == StepUnstable:
		return "UNSTABLE"
	case o.Reason != "":
		return "unknown (" + o.Reason + ")"
	case o.MaxPass == 0:
		return "x"
	case o.MinFail == 0:
		return "ok at every offset"
	}
	return fmt.Sprintf("ok up to %d (x at %d)", -o.MaxPass, -o.MinFail)
}

// serverValue returns the value of the server line when the check has
// one for the whole subsection, and whole is set.
func serverValue(s ServerResult) (value string, whole bool) {
	switch {
	case s.State == StepSkipped:
		return "?", true
	case s.Reason != "":
		return "unknown (" + s.Reason + ")", true
	}
	return "", false
}

// serverLines returns the lines of the server subsection: the baseline,
// then a line per fake tried.
func serverLines(s ServerResult) []line {
	lines := []line{{name: "bad_sni", value: s.BadSNI}}
	lines = appendRun(
		lines,
		"seq_offset",
		s.SeqOffset.State,
		serverOffsetValue(s.SeqOffset),
	)
	lines = appendRun(
		lines,
		"ack_offset",
		s.AckOffset.State,
		serverOffsetValue(s.AckOffset),
	)
	return appendRun(lines, "bad_md5", s.BadMD5.State, serverVariantValue(s.BadMD5))
}

func serverVariantValue(v ServerVariantResult) string {
	switch {
	case v.Reason != "":
		return "unknown (" + v.Reason + ")"
	case v.Drops:
		return "drops"
	}
	return "breaks (" + v.Break + ")"
}

func serverOffsetValue(o ServerOffsetResult) string {
	switch {
	case o.State == StepUnstable:
		return "UNSTABLE"
	case o.Reason != "":
		return "unknown (" + o.Reason + ")"
	case o.DropsFrom == 1:
		return "drops at every offset"
	case o.DropsFrom == 0:
		return "breaks at every offset (" + o.Break + ")"
	}
	// Past -2^31 there is no offset to try, so -2^31 is the only one
	// dropped.
	below := " or below"
	if o.DropsFrom >= maxOffset {
		below = ""
	}
	return fmt.Sprintf(
		"drops at %d%s; breaks (%s) at %d", -o.DropsFrom, below, o.Break, -o.LastBreak)
}

// statusValue returns the value of the status line of the https section,
// and whether the dpi subsection is shown. The value is empty when the block check did not run.
func statusValue(b BlockResult) (status string, detailed bool) {
	switch b.State {
	case StepSkipped:
		return "?", false
	case StepDone:
		switch b.Kind {
		case BlockClear:
			return "clear", false
		case BlockUnreachable:
			return "unreachable", false
		case BlockUnknown:
			return "unknown (" + b.Reason + ")", false
		}
		return "censored", true
	}
	return "", false
}

// typeValue returns the value of the type line of a censored site.
func typeValue(b BlockResult) string {
	switch b.Kind {
	case BlockRST:
		return "RST"
	case BlockSilent:
		return "silent"
	}
	return "other (" + b.Reason + ")"
}

func chunksValue(c ChunksResult) string {
	switch {
	case c.Reason != "":
		return "unknown (" + c.Reason + ")"
	case !c.Reassembled:
		return "not reassembled"
	case c.PassAt > 0:
		return fmt.Sprintf("reassembled, passes at %d bytes or less", c.PassAt)
	}
	return "reassembled"
}

// disorderValue says why disorder failed by what the chunks check found:
// a DPI that reassembles in-order chunks and still blocks disordered ones
// reorders them; one that does not reassemble blocks on the disorder
// itself.
func disorderValue(d DisorderResult, c ChunksResult) string {
	switch {
	case d.Reason != "":
		return "unknown (" + d.Reason + ")"
	case d.Pass:
		return "ok"
	case c.State != StepDone, c.Reason != "":
		return "x"
	case c.Reassembled:
		return "x (DPI reorders segments)"
	}
	return "x (blocked on out-of-order segments)"
}

func positionValue(p PositionResult) string {
	switch {
	case p.Hop > 0:
		return strconv.Itoa(p.Hop)
	case p.Reason != "":
		return "unknown (" + p.Reason + ")"
	}
	return "unknown"
}

// failureNote returns the short note of a failed actual measurement for
// the reason it was given, such as "timeout".
func failureNote(reason string) string {
	if msg, ok := strings.CutPrefix(reason, "local error: "); ok {
		return "local error " + localErrorName(msg)
	}
	return reason
}

// localErrorName returns the name of the local error whose message is msg,
// such as "EMFILE" for "too many open files", or msg itself when it is not
// a known one.
func localErrorName(msg string) string {
	for errno, name := range localErrnoNames {
		if errno.Error() == msg {
			return name
		}
	}
	return msg
}

// addrNote returns the short note of an address problem.
func addrNote(note string) string {
	if err, ok := strings.CutPrefix(note, "resolve: "); ok {
		return "resolve failed: " + err
	}
	return note
}
