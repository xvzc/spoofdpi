package desync

import (
	"encoding/binary"
	"fmt"
	"slices"
	"sort"

	"github.com/xvzc/spoofdpi/internal/proto"
)

// recordCuts returns sorted, unique cut points within (0, bodyLen) built as
// at, at+step, ... with at most repeat entries, mirroring ciadpi's
// `-r pos:repeats:skip`. step == 0 yields a single cut.
func recordCuts(bodyLen, at, repeat, step int) []int {
	if repeat <= 0 || bodyLen <= 0 {
		return nil
	}
	if step <= 0 {
		repeat = 1
	}

	cuts := make([]int, 0, repeat)
	for i := range repeat {
		c := at + i*step
		if c >= bodyLen {
			break
		}
		if c > 0 {
			cuts = append(cuts, c)
		}
	}

	return cuts
}

// splitRecords splits a single TLS record raw (5-byte header + body) into
// several records at the given body offsets. Each new record copies the
// content type and version from the original header. Cuts outside
// (0, bodyLen) and duplicates are dropped, so no empty record is produced.
//
// remap converts an offset in raw into the offset of the same byte in out.
func splitRecords(
	raw []byte,
	cuts []int,
) (out []byte, remap func(int) int, err error) {
	if len(raw) < proto.TLSHeaderLen {
		return nil, nil, fmt.Errorf("record too short: %d", len(raw))
	}

	body := raw[proto.TLSHeaderLen:]
	bodyLen := len(body)
	if declared := int(binary.BigEndian.Uint16(raw[3:5])); declared != bodyLen {
		return nil, nil, fmt.Errorf(
			"record length mismatch: header %d, actual %d", declared, bodyLen,
		)
	}

	norm := make([]int, 0, len(cuts))
	for _, c := range cuts {
		if c > 0 && c < bodyLen {
			norm = append(norm, c)
		}
	}
	slices.Sort(norm)
	norm = slices.Compact(norm)

	out = make([]byte, 0, len(raw)+len(norm)*proto.TLSHeaderLen)
	prev := 0
	for _, end := range append(norm, bodyLen) {
		out = append(out, raw[:3]...)
		out = binary.BigEndian.AppendUint16(out, uint16(end-prev))
		out = append(out, body[prev:end]...)
		prev = end
	}

	remap = func(o int) int {
		// Number of cuts c with header+c <= o, i.e. inserted headers before o.
		n := sort.SearchInts(norm, o-proto.TLSHeaderLen+1)
		return o + n*proto.TLSHeaderLen
	}

	return out, remap, nil
}
