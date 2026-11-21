package probe

import (
	"bytes"
	"net/netip"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func target(t *testing.T, in string) Target {
	t.Helper()
	tg, err := ParseTarget(in)
	require.NoError(t, err)
	return tg
}

func report(t *testing.T, results ...Result) string {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, WriteReport(&buf, results))
	return buf.String()
}

func TestWriteReport_Measured(t *testing.T) {
	got := report(t,
		Result{
			Target: target(t, "a.test"),
			Addr:   netip.MustParseAddr("203.0.113.10"),
			TCP:    TCPResult{Status: TCPMeasured, Hops: 11},
			TCPLearned: LearnedResult{
				Status: Learned, Hops: 11, TTLLeft: 53, Seen: []uint8{11},
			},
			UDP: UDPResult{Status: UDPMeasured, Hops: 11},
			UDPLearned: LearnedResult{
				Status: Learned, Hops: 11, TTLLeft: 117, Seen: []uint8{11},
			},
			DPI: DPIResult{
				Measured: true,
				Block:    BlockResult{State: StepDone, Kind: BlockClear},
			},
			QUIC: QUICResult{Status: QUICClear},
		},
		Result{
			Target:     target(t, "b.test"),
			Addr:       netip.MustParseAddr("203.0.113.20"),
			UDP:        UDPResult{Status: UDPMeasured, Hops: 9},
			UDPLearned: LearnedResult{Status: Learned, Hops: 9, TTLLeft: 55},
		},
		Result{
			Target:     target(t, "c.test"),
			Addr:       netip.MustParseAddr("203.0.113.30"),
			TCP:        TCPResult{Status: TCPMeasured, Hops: 7},
			TCPLearned: LearnedResult{Status: Learned, Hops: 7, TTLLeft: 57},
		},
		Result{
			Target: target(t, "d.test"),
			Addr:   netip.MustParseAddr("203.0.113.40"),
		},
	)
	assert.Equal(t, ""+
		"a.test (203.0.113.10)\n"+
		"  https\n"+
		"    status      clear\n"+
		"    hops(tcp)   11 actual / 11 learned\n"+
		"  quic\n"+
		"    status      clear\n"+
		"    hops(udp)   11 actual / 11 learned\n"+
		"\n"+
		"b.test (203.0.113.20)\n"+
		"  quic\n"+
		"    hops(udp)   9 actual / 9 learned\n"+
		"\n"+
		"c.test (203.0.113.30)\n"+
		"  https\n"+
		"    hops(tcp)   7 actual / 7 learned\n"+
		"\n"+
		"d.test (203.0.113.40)\n",
		got, "sections with nothing to show are left out")
}

func TestWriteReport_Reasons(t *testing.T) {
	got := report(t,
		Result{
			Target: target(t, "a.test"),
			Addr:   netip.MustParseAddr("203.0.113.10"),
			TCP:    TCPResult{Status: TCPMeasured, Hops: 9},
			TCPLearned: LearnedResult{
				Status:  Learned,
				Hops:    40,
				TTLLeft: 88,
				Seen:    []uint8{9, 40},
			},
			UDP: UDPResult{Status: UDPMeasured, Hops: 9, Unstable: true},
			UDPLearned: LearnedResult{
				Status:  Learned,
				Hops:    11,
				TTLLeft: 53,
				Seen:    []uint8{11, 12},
			},
		},
		Result{
			Target:     target(t, "b.test"),
			Addr:       netip.MustParseAddr("203.0.113.20"),
			TCP:        TCPResult{Status: TCPMeasured, Hops: 12, Unstable: true},
			TCPLearned: LearnedResult{Status: Learned, Hops: 10, TTLLeft: 54},
			UDP:        UDPResult{Status: UDPAboveMax, Hops: 31},
			UDPLearned: LearnedResult{Status: Learned, Hops: 3, TTLLeft: 61},
		},
	)
	assert.Equal(t, ""+
		"a.test (203.0.113.10)\n"+
		"  https\n"+
		"    hops(tcp)   9 actual / 40 learned (gap +31, learned varies 9,40)\n"+
		"  quic\n"+
		"    hops(udp)   9 actual / 11 learned (gap +2, path varies, learned varies 11,12)\n"+
		"\n"+
		"b.test (203.0.113.20)\n"+
		"  https\n"+
		"    hops(tcp)   12 actual / 10 learned (gap -2, path varies)\n"+
		"  quic\n"+
		"    hops(udp)   over 31 actual / 3 learned\n",
		got)
}

func TestWriteReport_Failures(t *testing.T) {
	got := report(t,
		Result{
			Target:   target(t, "a.test"),
			AddrNote: "resolve: context deadline exceeded",
		},
		Result{
			Target:   target(t, "v6only.test"),
			AddrNote: "no IPv4 address",
		},
		Result{
			Target: target(t, "b.test"),
			Addr:   netip.MustParseAddr("203.0.113.30"),
			TCP:    TCPResult{Status: TCPNoHandshake, Reason: "timeout"},
			UDP:    UDPResult{Status: UDPNoReply, Reason: "no reply"},
		},
		Result{
			Target: target(t, "b2.test"),
			Addr:   netip.MustParseAddr("203.0.113.31"),
			TCP:    TCPResult{Status: TCPNoHandshake, Reason: "reset"},
			UDP:    UDPResult{Status: UDPNoReply, Reason: "unreachable"},
		},
		Result{
			Target: target(t, "b3.test"),
			Addr:   netip.MustParseAddr("203.0.113.32"),
			TCP:    TCPResult{Status: TCPNoHandshake, Reason: "unreachable"},
		},
		Result{
			Target:     target(t, "c.test"),
			Addr:       netip.MustParseAddr("203.0.113.40"),
			TCP:        TCPResult{Status: TCPAboveMax, Hops: 31},
			TCPLearned: LearnedResult{Status: Learned, Hops: 3, TTLLeft: 61},
			UDP:        UDPResult{Status: UDPMeasured, Hops: 5},
			UDPLearned: LearnedResult{Status: LearnedNoUDPReply},
		},
		Result{
			Target:     target(t, "d.test"),
			Addr:       netip.MustParseAddr("203.0.113.50"),
			TCP:        TCPResult{Status: TCPMeasured, Hops: 5},
			TCPLearned: LearnedResult{Status: LearnedSkipped},
		},
		Result{
			Target: target(t, "f.test"),
			Addr:   netip.MustParseAddr("203.0.113.70"),
			TCP:    TCPResult{Status: TCPMeasured, Hops: 5},
			TCPLearned: LearnedResult{
				Status: LearnedNotCaptured,
				Reason: "capture stopped: boom",
			},
		},
		Result{
			Target: target(t, "h.test"),
			Addr:   netip.MustParseAddr("203.0.113.90"),
			TCP: TCPResult{
				Status: TCPNoHandshake,
				Reason: "local error: " + syscall.EMFILE.Error(),
			},
			UDP: UDPResult{
				Status:     UDPMeasured,
				Hops:       6,
				LocalError: syscall.EMFILE.Error(),
			},
			UDPLearned: LearnedResult{Status: LearnedSkipped},
		},
		Result{
			Target: target(t, "i.test"),
			Addr:   netip.MustParseAddr("203.0.113.100"),
			UDP: UDPResult{
				Status: UDPNoReply,
				Reason: "local error: " + syscall.ENOBUFS.Error(),
			},
		},
	)
	assert.Equal(t, ""+
		"a.test (resolve failed: context deadline exceeded)\n"+
		"\n"+
		"v6only.test (no IPv4 address)\n"+
		"\n"+
		"b.test (203.0.113.30)\n"+
		"  https\n"+
		"    hops(tcp)   no handshake (timeout)\n"+
		"  quic\n"+
		"    hops(udp)   no reply\n"+
		"\n"+
		"b2.test (203.0.113.31)\n"+
		"  https\n"+
		"    hops(tcp)   no handshake (reset)\n"+
		"  quic\n"+
		"    hops(udp)   unreachable\n"+
		"\n"+
		"b3.test (203.0.113.32)\n"+
		"  https\n"+
		"    hops(tcp)   unreachable\n"+
		"\n"+
		"c.test (203.0.113.40)\n"+
		"  https\n"+
		"    hops(tcp)   over 31 actual / 3 learned\n"+
		"  quic\n"+
		"    hops(udp)   5 actual / - (not learned)\n"+
		"\n"+
		"d.test (203.0.113.50)\n"+
		"  https\n"+
		"    hops(tcp)   5 actual / -\n"+
		"\n"+
		"f.test (203.0.113.70)\n"+
		"  https\n"+
		"    hops(tcp)   5 actual / - (not learned)\n"+
		"\n"+
		"h.test (203.0.113.90)\n"+
		"  https\n"+
		"    hops(tcp)   no handshake (local error EMFILE)\n"+
		"  quic\n"+
		"    hops(udp)   6 actual / - (local error EMFILE)\n"+
		"\n"+
		"i.test (203.0.113.100)\n"+
		"  quic\n"+
		"    hops(udp)   no reply (local error ENOBUFS)\n",
		got)
}

func TestWriteReport_DPI(t *testing.T) {
	addr := netip.MustParseAddr("203.0.113.10")
	hops := TCPResult{Status: TCPMeasured, Hops: 12}
	block := func(dpi DPIResult) string {
		t.Helper()
		return report(
			t,
			Result{Target: target(t, "a.test"), Addr: addr, TCP: hops, DPI: dpi},
		)
	}
	header := func(status string, under ...string) string {
		return "" +
			"a.test (203.0.113.10)\n" +
			"  https\n" +
			"    status      " + status + "\n" +
			strings.Join(under, "") +
			"    hops(tcp)   12 actual / -\n"
	}

	assert.Equal(t, header("censored")+""+
		"    dpi\n"+
		"      type      RST\n"+
		"      chunks    reassembled, passes at 8 bytes or less\n"+
		"      disorder  ok\n"+
		"      position  7\n",
		block(DPIResult{
			Measured: true,
			Block:    BlockResult{State: StepDone, Kind: BlockRST},
			Chunks: ChunksResult{
				State: StepDone, Reassembled: true, PassAt: 8, SmallestBlocked: 11,
			},
			Disorder: DisorderResult{State: StepDone, Pass: true, Size: 11},
			Position: PositionResult{State: StepDone, Hop: 7},
		}), "RST site")

	assert.Equal(t, header("censored")+""+
		"    dpi\n"+
		"      type      silent\n"+
		"      chunks    reassembled\n"+
		"      disorder  x (DPI reorders segments)\n"+
		"      position  unknown (needs root)\n",
		block(DPIResult{
			Measured: true,
			Block:    BlockResult{State: StepDone, Kind: BlockSilent},
			Chunks:   ChunksResult{State: StepDone, Reassembled: true, SmallestBlocked: 2},
			Disorder: DisorderResult{State: StepDone, Size: 2},
			Position: PositionResult{State: StepDone, Reason: "needs root"},
		}), "silent site without root")

	assert.Equal(t, header("censored")+""+
		"    dpi\n"+
		"      type      other (TLS alert 40)\n"+
		"      chunks    not reassembled\n"+
		"      disorder  x (blocked on out-of-order segments)\n"+
		"      position  unknown (block is neither RST nor silent)\n",
		block(DPIResult{
			Measured: true,
			Block:    BlockResult{State: StepDone, Kind: BlockOther, Reason: "TLS alert 40"},
			Chunks:   ChunksResult{State: StepDone, PassAt: 35, SmallestBlocked: 35},
			Disorder: DisorderResult{State: StepDone, Size: 35},
			Position: PositionResult{
				State: StepDone, Reason: "block is neither RST nor silent",
			},
		}), "other block")

	assert.Equal(t, header("unknown (connect failed)"),
		block(DPIResult{
			Measured: true,
			Block: BlockResult{
				State: StepDone, Kind: BlockUnknown, Reason: "connect failed",
			},
		}), "a failed connect after the hop measurement")

	assert.Equal(
		t,
		header("?", "    note        residual block from b.test (not cleared after 60s)\n"),
		block(DPIResult{
			Measured: true,
			Block:    BlockResult{State: StepSkipped},
			Chunks:   ChunksResult{State: StepSkipped},
			Disorder: DisorderResult{State: StepSkipped},
			Position: PositionResult{State: StepSkipped},
			Notes:    []string{"residual block from b.test (not cleared after 60s)"},
		}),
		"residual block not cleared",
	)

	assert.Equal(
		t,
		header("clear", "    note        waited 5s for residual block from b.test\n"),
		block(DPIResult{
			Measured: true,
			Block:    BlockResult{State: StepDone, Kind: BlockClear},
			Notes:    []string{"waited 5s for residual block from b.test"},
		}),
		"clear with a note",
	)

	assert.Equal(t, header("unknown (local error EMFILE)"),
		block(DPIResult{
			Measured: true,
			Block: BlockResult{
				State: StepDone, Kind: BlockUnknown, Reason: "local error EMFILE",
			},
		}), "unknown")

	assert.Equal(t, header("censored")+""+
		"    dpi\n"+
		"      type      RST\n"+
		"      chunks    reassembled\n"+
		"      note      residual block after the chunks check\n",
		block(DPIResult{
			Measured: true,
			Block:    BlockResult{State: StepDone, Kind: BlockRST},
			Chunks:   ChunksResult{State: StepDone, Reassembled: true, SmallestBlocked: 2},
			Notes:    []string{"residual block after the chunks check"},
		}), "note stays in the dpi subsection")
}

func TestWriteReport_FakeAndServer(t *testing.T) {
	addr := netip.MustParseAddr("66.254.114.41")
	censored := DPIResult{
		Measured: true,
		Block:    BlockResult{State: StepDone, Kind: BlockRST},
		Chunks:   ChunksResult{State: StepDone, Reassembled: true, SmallestBlocked: 2},
		Disorder: DisorderResult{State: StepDone, Pass: true, Size: 2},
		Position: PositionResult{State: StepDone, Hop: 7},
	}
	block := func(dpi DPIResult, server ServerResult) string {
		t.Helper()
		return report(t, Result{
			Target:     target(t, "www.pornhub.com"),
			Addr:       addr,
			TCP:        TCPResult{Status: TCPMeasured, Hops: 12},
			TCPLearned: LearnedResult{Status: Learned, Hops: 11},
			DPI:        dpi,
			Server:     server,
		})
	}
	const head = "" +
		"www.pornhub.com (66.254.114.41)\n" +
		"  https\n" +
		"    status      censored\n" +
		"    hops(tcp)   12 actual / 11 learned (gap -1)\n" +
		"    dpi\n" +
		"      type      RST\n" +
		"      chunks    reassembled\n" +
		"      disorder  ok\n" +
		"      position  7\n"

	withFake := censored
	withFake.Fake = FakeResult{
		State:     StepDone,
		TTL:       FakeVariantResult{State: StepDone, Pass: true},
		SeqOffset: FakeOffsetResult{State: StepDone, MaxPass: 8192, MinFail: 16384},
		AckOffset: FakeOffsetResult{State: StepDone, MaxPass: maxOffset},
		BadMD5:    FakeVariantResult{State: StepDone},
	}
	assert.Equal(t, head+""+
		"      fake\n"+
		"        ttl          ok\n"+
		"        seq_offset   ok up to -8192 (x at -16384)\n"+
		"        ack_offset   ok at every offset\n"+
		"        bad_md5      x\n"+
		"    server\n"+
		"      bad_sni      answers\n"+
		"      seq_offset   drops at -1024 or below; breaks (closed) at -512\n"+
		"      ack_offset   drops at every offset\n"+
		"      bad_md5      breaks (bad sni)\n",
		block(withFake, ServerResult{
			Measured: true,
			State:    StepDone,
			BadSNI:   "answers",
			SeqOffset: ServerOffsetResult{
				State: StepDone, DropsFrom: 1024, LastBreak: 512, Break: "closed",
			},
			AckOffset: ServerOffsetResult{State: StepDone, DropsFrom: 1},
			BadMD5:    ServerVariantResult{State: StepDone, Break: "bad sni"},
		}), "the full example")

	noOffset := censored
	noOffset.Fake = FakeResult{
		State:     StepDone,
		TTL:       FakeVariantResult{State: StepDone, Pass: true},
		SeqOffset: FakeOffsetResult{State: StepDone, MinFail: 1},
		AckOffset: FakeOffsetResult{State: StepUnstable},
		BadMD5:    FakeVariantResult{State: StepDone, Reason: "seq not learned"},
	}
	assert.Equal(t, head+""+
		"      fake\n"+
		"        ttl          ok\n"+
		"        seq_offset   x\n"+
		"        ack_offset   UNSTABLE\n"+
		"        bad_md5      unknown (seq not learned)\n"+
		"    server\n"+
		"      bad_sni      answers\n"+
		"      seq_offset   breaks at every offset (reset)\n"+
		"      ack_offset   unknown (seq not verified)\n"+
		"      bad_md5      unknown (seq not learned)\n",
		block(noOffset, ServerResult{
			Measured: true,
			State:    StepDone,
			BadSNI:   "answers",
			SeqOffset: ServerOffsetResult{
				State: StepDone, LastBreak: maxOffset, Break: "reset",
			},
			AckOffset: ServerOffsetResult{State: StepDone, Reason: "seq not verified"},
			BadMD5:    ServerVariantResult{State: StepDone, Reason: "seq not learned"},
		}), "x, UNSTABLE, unknown and breaking at every offset")

	needsRoot := censored
	needsRoot.Fake = FakeResult{State: StepDone, Reason: "needs root"}
	assert.Equal(t, head+""+
		"      fake      unknown (needs root)\n"+
		"    server      unknown (needs root)\n",
		block(needsRoot, ServerResult{
			Measured: true, State: StepDone, Reason: "needs root",
		}), "without root")

	assert.Equal(t, head+""+
		"      fake      unknown (needs root)\n"+
		"    server      unknown (server rejects unknown SNI)\n",
		block(needsRoot, ServerResult{
			Measured: true, State: StepDone,
			BadSNI: "alert 112 (unrecognized_name)", Reason: "server rejects unknown SNI",
		}), "a blocked site whose server rejects unknown names: one line")

	ttlFails := censored
	ttlFails.Fake = FakeResult{State: StepDone, TTL: FakeVariantResult{State: StepDone}}
	ttlFails.Notes = []string{"residual block after the server check"}
	assert.Equal(t, head+""+
		"      fake\n"+
		"        ttl          x\n"+
		"      note      residual block after the server check\n"+
		"    server      ?\n",
		block(ttlFails, ServerResult{Measured: true, State: StepSkipped}),
		"ttl x leaves out the other fakes; a residual block after the server check")

	partial := censored
	partial.Fake = FakeResult{
		State:     StepDone,
		TTL:       FakeVariantResult{State: StepDone, Pass: true},
		SeqOffset: FakeOffsetResult{State: StepDone, MaxPass: maxOffset},
	}
	assert.Equal(t, head+""+
		"      fake\n"+
		"        ttl          ok\n"+
		"        seq_offset   ok at every offset\n"+
		"    server\n"+
		"      bad_sni      answers\n"+
		"      seq_offset   UNSTABLE\n",
		block(partial, ServerResult{
			Measured:  true,
			State:     StepDone,
			BadSNI:    "answers",
			SeqOffset: ServerOffsetResult{State: StepUnstable},
		}), "lines of fakes that were not tried left out")

	skipped := censored
	skipped.Position = PositionResult{State: StepSkipped}
	skipped.Fake = FakeResult{State: StepSkipped}
	assert.Equal(t, ""+
		"www.pornhub.com (66.254.114.41)\n"+
		"  https\n"+
		"    status      censored\n"+
		"    hops(tcp)   12 actual / 11 learned (gap -1)\n"+
		"    dpi\n"+
		"      type      RST\n"+
		"      chunks    reassembled\n"+
		"      disorder  ok\n"+
		"      position  ?\n"+
		"      fake      ?\n"+
		"    server      ?\n",
		block(skipped, ServerResult{Measured: true, State: StepSkipped}),
		"residual block before the fake check")

	assert.Equal(t, ""+
		"www.pornhub.com (66.254.114.41)\n"+
		"  https\n"+
		"    status      clear\n"+
		"    hops(tcp)   12 actual / 11 learned (gap -1)\n"+
		"    server\n"+
		"      bad_sni      silent\n"+
		"      seq_offset   drops at -2147483648; breaks (timeout) at -1073741824\n",
		block(DPIResult{
			Measured: true,
			Block:    BlockResult{State: StepDone, Kind: BlockClear},
		}, ServerResult{
			Measured: true,
			State:    StepDone,
			BadSNI:   "silent",
			SeqOffset: ServerOffsetResult{
				State: StepDone, DropsFrom: maxOffset, LastBreak: maxOffset / 2,
				Break: "timeout",
			},
		}), "clear site")
}

func TestWriteReport_UnreachableHidesTCPLine(t *testing.T) {
	got := report(t,
		Result{
			Target: target(t, "d.test"),
			Addr:   netip.MustParseAddr("203.0.113.40"),
			TCP:    TCPResult{Status: TCPNoHandshake, Reason: "timeout"},
			UDP:    UDPResult{Status: UDPNoReply, Reason: "no reply"},
			DPI: DPIResult{
				Measured: true,
				Block:    BlockResult{State: StepDone, Kind: BlockUnreachable},
			},
			QUIC: QUICResult{Status: QUICUnknown, Reason: "no reply"},
		},
	)
	assert.Equal(t, ""+
		"d.test (203.0.113.40)\n"+
		"  https\n"+
		"    status      unreachable\n"+
		"  quic\n"+
		"    status      unknown (no reply)\n"+
		"    hops(udp)   no reply\n",
		got)
}

func TestWriteReport_QUIC(t *testing.T) {
	block := func(q QUICResult) string {
		t.Helper()
		return report(t, Result{
			Target: target(t, "a.test"),
			Addr:   netip.MustParseAddr("203.0.113.10"),
			UDP:    UDPResult{Status: UDPMeasured, Hops: 8},
			QUIC:   q,
		})
	}
	section := func(lines ...string) string {
		return "" +
			"a.test (203.0.113.10)\n" +
			"  quic\n" +
			strings.Join(lines, "") +
			"    hops(udp)   8 actual / -\n"
	}
	for _, tc := range []struct {
		name string
		q    QUICResult
		want string
	}{
		{
			name: "clear",
			q:    QUICResult{Status: QUICClear},
			want: section("    status      clear\n"),
		},
		{
			name: "censored",
			q:    QUICResult{Status: QUICCensored},
			want: section("    status      censored\n"),
		},
		{
			name: "unreachable",
			q:    QUICResult{Status: QUICUnreachable},
			want: section("    status      unreachable\n"),
		},
		{
			name: "no QUIC v1",
			q:    QUICResult{Status: QUICUnknown, Reason: "no QUIC v1"},
			want: section("    status      unknown (no QUIC v1)\n"),
		},
		{
			name: "local error",
			q: QUICResult{
				Status: QUICUnknown,
				Reason: "local error: " + syscall.EMFILE.Error(),
			},
			want: section("    status      unknown (local error EMFILE)\n"),
		},
		{
			name: "skipped",
			q: QUICResult{
				Status: QUICSkipped,
				Notes:  []string{"residual block from b.test (not cleared after 60s)"},
			},
			want: section(
				"    status      ?\n",
				"    note        residual block from b.test (not cleared after 60s)\n",
			),
		},
		{
			name: "notes",
			q: QUICResult{
				Status: QUICCensored,
				Notes:  []string{"waited 10s for residual block from b.test", "x"},
			},
			want: section(
				"    status      censored\n",
				"    note        waited 10s for residual block from b.test; x\n",
			),
		},
		{
			name: "not run",
			want: section(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, block(tc.q))
		})
	}
}

func TestWriteReport_BothSections(t *testing.T) {
	got := report(t, Result{
		Target:     target(t, "www.xvideos.com"),
		Addr:       netip.MustParseAddr("185.88.181.2"),
		TCP:        TCPResult{Status: TCPMeasured, Hops: 11},
		TCPLearned: LearnedResult{Status: Learned, Hops: 11},
		UDP:        UDPResult{Status: UDPMeasured, Hops: 11},
		UDPLearned: LearnedResult{Status: Learned, Hops: 11},
		DPI: DPIResult{
			Measured: true,
			Block:    BlockResult{State: StepDone, Kind: BlockRST},
			Chunks:   ChunksResult{State: StepDone, Reassembled: true, SmallestBlocked: 2},
			Disorder: DisorderResult{State: StepDone, Pass: true, Size: 2},
			Position: PositionResult{State: StepDone, Hop: 7},
			Fake: FakeResult{
				State: StepDone,
				TTL:   FakeVariantResult{State: StepDone, Pass: true},
			},
		},
		Server: ServerResult{Measured: true, State: StepDone, BadSNI: "answers"},
		QUIC:   QUICResult{Status: QUICCensored},
	})
	assert.Equal(t, ""+
		"www.xvideos.com (185.88.181.2)\n"+
		"  https\n"+
		"    status      censored\n"+
		"    hops(tcp)   11 actual / 11 learned\n"+
		"    dpi\n"+
		"      type      RST\n"+
		"      chunks    reassembled\n"+
		"      disorder  ok\n"+
		"      position  7\n"+
		"      fake\n"+
		"        ttl          ok\n"+
		"    server\n"+
		"      bad_sni      answers\n"+
		"  quic\n"+
		"    status      censored\n"+
		"    hops(udp)   11 actual / 11 learned\n",
		got)
}

func TestWriteReport_NoResults(t *testing.T) {
	assert.Empty(t, report(t))
}

func TestResult_Mismatch(t *testing.T) {
	tcp := func(status TCPStatus, hops int, learned LearnedStatus, learnedHops uint8) Result {
		return Result{
			TCP:        TCPResult{Status: status, Hops: hops},
			TCPLearned: LearnedResult{Status: learned, Hops: learnedHops},
		}
	}
	delta, ok := tcp(TCPMeasured, 9, Learned, 12).TCPMismatch()
	assert.True(t, ok)
	assert.Equal(t, 3, delta)

	delta, ok = tcp(TCPMeasured, 9, Learned, 7).TCPMismatch()
	assert.True(t, ok)
	assert.Equal(t, -2, delta)

	_, ok = tcp(TCPMeasured, 9, Learned, 9).TCPMismatch()
	assert.False(t, ok, "equal")
	_, ok = tcp(TCPAboveMax, 31, Learned, 9).TCPMismatch()
	assert.False(t, ok, "TCP above the maximum")
	_, ok = tcp(TCPMeasured, 9, LearnedSkipped, 0).TCPMismatch()
	assert.False(t, ok, "learned skipped")

	udp := func(status UDPStatus, hops int, learned LearnedStatus, learnedHops uint8) Result {
		return Result{
			UDP:        UDPResult{Status: status, Hops: hops},
			UDPLearned: LearnedResult{Status: learned, Hops: learnedHops},
			// The TCP pair does not affect the UDP one.
			TCP:        TCPResult{Status: TCPMeasured, Hops: 1},
			TCPLearned: LearnedResult{Status: Learned, Hops: 1},
		}
	}
	delta, ok = udp(UDPMeasured, 9, Learned, 10).UDPMismatch()
	assert.True(t, ok)
	assert.Equal(t, 1, delta)
	_, ok = udp(UDPMeasured, 9, Learned, 9).UDPMismatch()
	assert.False(t, ok, "equal")
	_, ok = udp(UDPAboveMax, 31, Learned, 9).UDPMismatch()
	assert.False(t, ok, "UDP above the maximum")
	_, ok = udp(UDPMeasured, 9, LearnedNoUDPReply, 0).UDPMismatch()
	assert.False(t, ok, "no UDP reply")
}
