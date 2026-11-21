package probe

import "net/netip"

// Result is the outcome of probing one target. Hop counts count the
// routers between this host and the server, the unit spoofdpi learns hop
// counts in: the smallest TTL that reaches the server, minus 1.
type Result struct {
	Target Target
	// Addr is the IPv4 address that was probed. It is invalid when the
	// host has none.
	Addr netip.Addr
	// AddrNote, if set, says why Addr was not probed, such as
	// "resolve: <error>" or "no IPv4 address".
	AddrNote string

	// TCP is the actual TCP hop count, and TCPLearned the one spoofdpi
	// learns from the server's SYN/ACK.
	TCP        TCPResult
	TCPLearned LearnedResult
	// UDP is the actual UDP hop count, and UDPLearned the one spoofdpi
	// learns from the server's UDP reply.
	UDP        UDPResult
	UDPLearned LearnedResult

	// DPI is what the DPI checks found.
	DPI DPIResult
	// Server is how the server handles fake packets that reach it.
	Server ServerResult

	// QUIC is what the QUIC check found.
	QUIC QUICResult
}

// QUICStatus is the verdict of the QUIC check.
type QUICStatus int

const (
	// QUICNotRun: the check did not run, because the probe was
	// interrupted.
	QUICNotRun QUICStatus = iota
	// QUICClear: the server answered the Initial for the target's host.
	QUICClear
	// QUICCensored: the server answered the Initial for the benign name,
	// but not the one for the target's host.
	QUICCensored
	// QUICUnreachable: both Initials got an ICMP host or network
	// unreachable.
	QUICUnreachable
	// QUICUnknown: the check has no verdict; Reason says why, such as
	// "no reply", "no QUIC", "no QUIC v1" or "local error: <error>".
	QUICUnknown
	// QUICSkipped: the residual block of a target checked before at the
	// same address did not clear.
	QUICSkipped
)

// QUICResult is the result of the QUIC check: whether the server answers
// a QUIC v1 Initial for the target's host, compared with one for the
// benign name.
type QUICResult struct {
	Status QUICStatus
	Reason string
	// Notes are about the check as a whole, such as a residual block.
	Notes []string
}

// TCPStatus is the outcome of the TCP measurement.
type TCPStatus int

const (
	// TCPNotMeasured: the target was not probed.
	TCPNotMeasured TCPStatus = iota
	// TCPMeasured: Hops is the hop count.
	TCPMeasured
	// TCPAboveMax: no TTL up to the maximum reached the server; the hop
	// count is more than Hops.
	TCPAboveMax
	// TCPNoHandshake: a connection at the default TTL did not complete;
	// Reason says why, such as "timeout", "reset", "unreachable" or
	// "local error: <error>".
	TCPNoHandshake
)

// TCPResult is the outcome of the TCP measurement.
type TCPResult struct {
	Status TCPStatus
	Hops   int
	// Unstable is set when some TTL above the smallest reaching one never
	// reached the server, which happens when the path differs between
	// connections.
	Unstable bool
	Reason   string
	// LocalError, if set, is a local socket error that some attempts of
	// the TTL scan failed with, such as "too many open files". Those
	// attempts say nothing about the path, so Hops may be too high.
	LocalError string
}

// LearnedStatus is the outcome of a learned hop count measurement.
type LearnedStatus int

const (
	// LearnedNotMeasured: the protocol was not measured, or the server
	// was not reached at the default TTL.
	LearnedNotMeasured LearnedStatus = iota
	// Learned: Hops is the hop count spoofdpi learns.
	Learned
	// LearnedSkipped: packet capture is unavailable.
	LearnedSkipped
	// LearnedNotCaptured: the reply was not captured; Reason may say why.
	LearnedNotCaptured
	// LearnedNoUDPReply: the server answered UDP only with an ICMP port
	// unreachable, which spoofdpi does not learn from.
	LearnedNoUDPReply
)

// LearnedResult is the hop count spoofdpi would learn from the server's
// SYN/ACK or UDP reply, before its hop-count-offset, -min and -max apply.
type LearnedResult struct {
	Status LearnedStatus
	// Hops is the learned hop count, and TTLLeft the TTL the reply
	// arrived with.
	Hops, TTLLeft uint8
	// Seen are the distinct hop counts of every reply from the server's
	// address and port captured during the measurement, in ascending
	// order. spoofdpi keeps the latest one, so more than one value means
	// its learned hop count varies.
	Seen   []uint8
	Reason string
}

// UDPStatus is the outcome of the UDP measurement.
type UDPStatus int

const (
	// UDPNotMeasured: the target was not probed.
	UDPNotMeasured UDPStatus = iota
	// UDPMeasured: Hops is the hop count.
	UDPMeasured
	// UDPAboveMax: no TTL up to the maximum reached the server; the hop
	// count is more than Hops.
	UDPAboveMax
	// UDPNoReply: the server was not reached at the default TTL; Reason
	// says how, such as "no reply", "unreachable" or
	// "local error: <error>".
	UDPNoReply
)

// UDPResult is the outcome of the UDP measurement.
type UDPResult struct {
	Status   UDPStatus
	Hops     int
	Unstable bool
	Reason   string
	// LocalError is as in TCPResult.
	LocalError string
}

// TCPMismatch returns TCPLearned minus TCP when both were measured and
// differ.
func (r Result) TCPMismatch() (delta int, ok bool) {
	if r.TCP.Status != TCPMeasured {
		return 0, false
	}
	return r.TCPLearned.mismatch(r.TCP.Hops)
}

// UDPMismatch returns UDPLearned minus UDP when both were measured and
// differ.
func (r Result) UDPMismatch() (delta int, ok bool) {
	if r.UDP.Status != UDPMeasured {
		return 0, false
	}
	return r.UDPLearned.mismatch(r.UDP.Hops)
}

// mismatch returns the learned hop count minus actual when it was learned
// and differs.
func (l LearnedResult) mismatch(actual int) (delta int, ok bool) {
	if l.Status != Learned {
		return 0, false
	}
	delta = int(l.Hops) - actual
	return delta, delta != 0
}

// DPIResult is what the DPI checks found about the blocking of the
// target's TLS connections.
type DPIResult struct {
	// Measured is set when the checks ran.
	Measured bool
	Block    BlockResult
	Chunks   ChunksResult
	Disorder DisorderResult
	Position PositionResult
	Fake     FakeResult
	// Notes are about the checks as a whole, such as a residual block.
	Notes []string
}

// StepState is how far a DPI check got.
type StepState int

const (
	// StepNotRun: the check did not apply, such as every check after a
	// clear block check.
	StepNotRun StepState = iota
	// StepDone: the check has a result.
	StepDone
	// StepUnstable: the outcome of an offset search flipped back.
	StepUnstable
	// StepSkipped: the check could not run, or its result was spoiled,
	// because of a residual block.
	StepSkipped
)

// BlockKind is how the DPI blocks a ClientHello sent in one piece.
type BlockKind int

const (
	// BlockClear: the ClientHello got through.
	BlockClear BlockKind = iota
	// BlockRST: the connection was reset.
	BlockRST
	// BlockSilent: nothing came back.
	BlockSilent
	// BlockUnreachable: no TCP connection completed.
	BlockUnreachable
	// BlockOther: another answer, such as a TLS alert or a close; Reason
	// says which.
	BlockOther
	// BlockUnknown: the attempt failed on this host, or the connect
	// failed after the hop measurement connected; Reason says why.
	BlockUnknown
)

// BlockResult is the result of the block check.
type BlockResult struct {
	State  StepState
	Kind   BlockKind
	Reason string
}

// ChunksResult is the result of sending the ClientHello in chunks of 35
// down to 2 bytes.
type ChunksResult struct {
	State StepState
	// Reassembled is set when the chunks of the largest size are blocked:
	// the DPI reassembles TCP segments.
	Reassembled bool
	// PassAt is the largest chunk size that got through, or 0 if none did.
	PassAt int
	// SmallestBlocked is the smallest chunk size that was blocked, or the
	// largest size if none was.
	SmallestBlocked int
	// Reason, if set, says why the check has no result: the attempt of a
	// size failed on this host.
	Reason string
}

// DisorderResult is the result of sending the chunks with spoofdpi's
// disorder.
type DisorderResult struct {
	State StepState
	// Pass is set when the disordered chunks got through.
	Pass bool
	// Size is the chunk size sent.
	Size int
	// Reason, if set, says why the check has no result: the attempt failed
	// on this host.
	Reason string
}

// PositionResult is the hop the DPI acts at.
type PositionResult struct {
	State StepState
	// Hop is the hop count to the DPI, or 0 if it is unknown; Reason may
	// then say why.
	Hop    int
	Reason string
}

// FakeResult is the result of sending a fake ClientHello, with a TTL that
// dies before the server, before the real one: whether the DPI takes the
// fake for the connection's ClientHello and lets the real one through.
type FakeResult struct {
	State StepState
	// Reason, if set, says why no fake was sent, such as "needs root".
	Reason string
	// TTL is the result of the fake with the connection's own sequence
	// numbers. The others are tried only when it gets through.
	TTL FakeVariantResult
	// SeqOffset and AckOffset are the results of the searches for the
	// fake-seq-offset and fake-ack-offset values that fool the DPI.
	SeqOffset, AckOffset FakeOffsetResult
	// BadMD5 is the result of the fake with fake-bad-md5sig.
	BadMD5 FakeVariantResult
}

// FakeVariantResult is the result of one fake of the fake check.
type FakeVariantResult struct {
	State StepState
	// Pass is set when the real ClientHello got through after the fake.
	Pass bool
	// Reason, if set, says why the fake has no result: its attempt failed
	// on this host.
	Reason string
}

// FakeOffsetResult is the result of the search, over the negative powers
// of two from -1 to -2^31, for the offsets whose fakes fool the DPI.
type FakeOffsetResult struct {
	// State is StepUnstable when the DPI let the real ClientHello through
	// again at the offset past the first one it did not.
	State StepState
	// MaxPass is the largest magnitude M such that the fakes of every
	// offset tried from -1 to -M fooled the DPI, 0 when -1 did not, and
	// MinFail the smallest magnitude whose fake did not, 2*MaxPass, or 0
	// when every offset tried fooled it.
	MaxPass, MinFail int64
	// Reason, if set, says why the search has no result: the attempt at
	// an offset failed on this host.
	Reason string
}

// ServerResult is how the server handles a fake ClientHello that reaches
// it: sent with TTL 64 before a ClientHello the DPI lets through, the site's
// own for a clear site and one for the benign name otherwise, the fake must
// be dropped by the server for the connection to go on as without it.
type ServerResult struct {
	// Measured is set when the check applies to the target.
	Measured bool
	State    StepState
	// Reason, if set, says why no fake was sent, such as "needs root" or
	// "server rejects unknown SNI".
	Reason string
	// BadSNI is how the server answers the benign ClientHello alone, such
	// as "answers" or "alert 112 (unrecognized_name)". The benign
	// ClientHello is sent after the fakes only when it is "answers".
	BadSNI string
	// SeqOffset and AckOffset are the results of the searches for the
	// fake-seq-offset and fake-ack-offset values whose fakes the server
	// drops.
	SeqOffset, AckOffset ServerOffsetResult
	// BadMD5 is the result of the fake with fake-bad-md5sig.
	BadMD5 ServerVariantResult
}

// ServerVariantResult is the result of one fake of the server check.
type ServerVariantResult struct {
	State StepState
	// Drops is set when the server answered the real ClientHello with a
	// ServerHello, as it does without the fake.
	Drops bool
	// Break says how the connection went otherwise, such as "reset" or
	// "bad sni".
	Break string
	// Reason, if set, says why the fake has no result: its attempt failed
	// on this host.
	Reason string
}

// ServerOffsetResult is the result of the search, over the negative
// powers of two from -1 to -2^31, for the offsets whose fakes the server
// drops.
type ServerOffsetResult struct {
	// State is StepUnstable when the server broke again at the offset
	// past the first one it dropped.
	State StepState
	// DropsFrom is the smallest magnitude N whose fake the server
	// dropped, from which on it dropped every one tried: 1 when it dropped
	// the fake at -1 already, 0 when it dropped none up to -2^31.
	DropsFrom int64
	// LastBreak is the largest magnitude tried whose fake broke the
	// connection, DropsFrom/2, or 2^31 when DropsFrom is 0, and Break says
	// how it broke.
	LastBreak int64
	Break     string
	// Reason, if set, says why the search has no result: the attempt at
	// an offset failed on this host.
	Reason string
}
