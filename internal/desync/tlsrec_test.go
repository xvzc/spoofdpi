package desync

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// clientHello returns the default fake Client Hello as a parsed TLS record.
func clientHello(t *testing.T) (*proto.TLSMessage, []byte) {
	t.Helper()

	msg, err := proto.ReadTLSMessage(strings.NewReader(config.FakeClientHello))
	require.NoError(t, err)
	require.True(t, msg.IsClientHello())

	return msg, msg.Raw()
}

// parseRecords splits out into records and returns their bodies,
// failing the test on malformed or empty records.
func parseRecords(t *testing.T, header, out []byte) [][]byte {
	t.Helper()

	var bodies [][]byte
	for len(out) > 0 {
		require.GreaterOrEqual(t, len(out), proto.TLSHeaderLen)
		assert.Equal(t, header[:3], out[:3], "type and version are copied")

		n := int(binary.BigEndian.Uint16(out[3:5]))
		require.Positive(t, n, "no empty records")
		require.GreaterOrEqual(t, len(out), proto.TLSHeaderLen+n)

		bodies = append(bodies, out[proto.TLSHeaderLen:proto.TLSHeaderLen+n])
		out = out[proto.TLSHeaderLen+n:]
	}

	return bodies
}

func TestSplitRecords(t *testing.T) {
	_, raw := clientHello(t)
	bodyLen := len(raw) - proto.TLSHeaderLen

	tcs := []struct {
		name    string
		raw     []byte
		cuts    []int
		records int
		wantErr bool
	}{
		{name: "no cuts", raw: raw, cuts: nil, records: 1},
		{name: "single cut", raw: raw, cuts: []int{16}, records: 2},
		{
			name:    "many cuts",
			raw:     raw,
			cuts:    recordCuts(bodyLen, 16, 150, 16),
			records: (bodyLen + 15) / 16,
		},
		{name: "unsorted with duplicates", raw: raw, cuts: []int{40, 8, 40, 8}, records: 3},
		{
			name:    "out of range cuts dropped",
			raw:     raw,
			cuts:    []int{-1, 0, bodyLen, bodyLen + 10, 3},
			records: 2,
		},
		{name: "too short", raw: raw[:4], wantErr: true},
		{name: "length mismatch", raw: raw[:len(raw)-1], wantErr: true},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			out, remap, err := splitRecords(tc.raw, tc.cuts)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			bodies := parseRecords(t, tc.raw, out)
			assert.Len(t, bodies, tc.records)
			assert.Equal(t, tc.raw[proto.TLSHeaderLen:], bytes.Join(bodies, nil))

			for o := proto.TLSHeaderLen; o < len(tc.raw); o++ {
				require.Equal(t, tc.raw[o], out[remap(o)], "remap(%d)", o)
			}
			assert.Equal(t, len(out), remap(len(tc.raw)), "end offset maps to end")
		})
	}
}

func TestRecordCuts(t *testing.T) {
	tcs := []struct {
		name                      string
		bodyLen, at, repeat, step int
		want                      []int
	}{
		{
			name:    "repeat with step",
			bodyLen: 100,
			at:      16,
			repeat:  3,
			step:    16,
			want:    []int{16, 32, 48},
		},
		{
			name:    "stops at body end",
			bodyLen: 40,
			at:      16,
			repeat:  150,
			step:    16,
			want:    []int{16, 32},
		},
		{name: "step zero", bodyLen: 100, at: 16, repeat: 5, step: 0, want: []int{16}},
		{name: "repeat zero", bodyLen: 100, at: 16, repeat: 0, step: 16, want: nil},
		{name: "at beyond body", bodyLen: 10, at: 16, repeat: 1, step: 0, want: []int{}},
		{name: "empty body", bodyLen: 0, at: 1, repeat: 1, step: 0, want: nil},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, recordCuts(tc.bodyLen, tc.at, tc.repeat, tc.step))
		})
	}
}

func TestSplitClientHelloRecords(t *testing.T) {
	msg, orig := clientHello(t)
	origStart, origEnd, err := msg.ExtractSNIOffset()
	require.NoError(t, err)
	host := orig[origStart:origEnd]

	tcs := []struct {
		name string
		opts config.TLSRecordSplit
	}{
		{name: "disabled", opts: config.TLSRecordSplit{}},
		{
			name: "cut inside sni",
			opts: config.TLSRecordSplit{At: uint16(origStart - 3), Repeat: 1},
		},
		{
			name: "16 byte records",
			opts: config.TLSRecordSplit{At: 16, Repeat: 150, Step: 16},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			raw, sniOffset := splitClientHelloRecords(zerolog.Nop(), msg, tc.opts)

			start, end, err := sniOffset()
			require.NoError(t, err)

			// Bytes between remapped offsets are the hostname, possibly
			// interleaved with inserted record headers.
			got := raw[start:end]
			if !tc.opts.Enabled() {
				assert.Equal(t, orig, raw)
				assert.Equal(t, host, got)
				return
			}
			bodies := parseRecords(t, raw[:proto.TLSHeaderLen], raw)
			assert.Equal(
				t, orig[proto.TLSHeaderLen:], bytes.Join(bodies, nil),
			)
			assert.Equal(t, host[0], got[0])
			assert.Equal(t, host[len(host)-1], got[len(got)-1])
			assert.Greater(t, len(raw), len(orig), "record headers inserted")

			plans := []config.SegmentPlan{{From: config.SegmentFromSNI, At: 0}}
			segs, err := applySegmentPlans(raw, sniOffset, plans)
			require.NoError(t, err)
			require.Len(t, segs, 2)
			assert.Equal(t, raw[:start], segs[0].Packet)
		})
	}
}

func TestSplitClientHelloRecords_nonClientHello(t *testing.T) {
	// Application data record: must be passed through untouched.
	rec := append([]byte{0x17, 0x03, 0x03, 0x00, 0x40}, make([]byte, 0x40)...)
	msg, err := proto.ReadTLSMessage(bytes.NewReader(rec))
	require.NoError(t, err)
	require.False(t, msg.IsClientHello())

	opts := config.TLSRecordSplit{At: 16, Repeat: 150, Step: 16}
	raw, _ := splitClientHelloRecords(zerolog.Nop(), msg, opts)
	assert.Equal(t, rec, raw)
}
