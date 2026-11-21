package probe

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

// scriptedSearch is a searchProbe whose points side says, recording the
// magnitudes it is asked for.
type scriptedSearch struct {
	side  func(m int64) searchPoint
	tried []int64
}

func (s *scriptedSearch) probe(m int64) (searchPoint, bool) {
	s.tried = append(s.tried, m)
	return s.side(m), true
}

// beforeUpTo is a script whose points are before up to last, with the
// magnitude as their detail, and after past it.
func beforeUpTo(last int64) func(m int64) searchPoint {
	return func(m int64) searchPoint {
		if m <= last {
			return searchPoint{side: sideBefore, detail: strconv.FormatInt(m, 10)}
		}
		return searchPoint{side: sideAfter}
	}
}

func TestSearchOffset_Boundary(t *testing.T) {
	s := &scriptedSearch{side: beforeUpTo(5000)}
	got, ok := searchOffset(s.probe)
	assert.True(t, ok)
	assert.Equal(t, offsetSearch{
		lastBefore: 4096, firstAfter: 8192, beforeDetail: "4096",
	}, got)
	assert.Equal(t, []int64{
		1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
	}, s.tried, "powers of two to the flip, then the next one")
}

func TestSearchOffset_Ends(t *testing.T) {
	tcs := []struct {
		name      string
		last      int64
		want      offsetSearch
		wantTries int
	}{
		{
			name:      "before at every magnitude",
			last:      maxOffset,
			want:      offsetSearch{lastBefore: maxOffset, beforeDetail: "2147483648"},
			wantTries: 32,
		},
		{
			name:      "after at 1",
			last:      0,
			want:      offsetSearch{firstAfter: 1},
			wantTries: 2,
		},
		{
			name: "after at 2",
			last: 1,
			want: offsetSearch{lastBefore: 1, firstAfter: 2, beforeDetail: "1"},
			// 1, 2 and 4.
			wantTries: 3,
		},
		{
			name: "after at 2^31 only",
			last: maxOffset - 1,
			want: offsetSearch{
				lastBefore: maxOffset / 2, firstAfter: maxOffset,
				beforeDetail: "1073741824",
			},
			// No magnitude past 2^31.
			wantTries: 32,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			s := &scriptedSearch{side: beforeUpTo(tc.last)}
			got, ok := searchOffset(s.probe)
			assert.True(t, ok)
			assert.Equal(t, tc.want, got)
			assert.Len(t, s.tried, tc.wantTries)
			for _, m := range s.tried {
				assert.LessOrEqual(t, m, maxOffset)
			}
		})
	}
}

func TestSearchOffset_FlipsBack(t *testing.T) {
	// After from 5 to 15, before again from 16.
	s := &scriptedSearch{side: func(m int64) searchPoint {
		if m > 4 && m < 16 {
			return searchPoint{side: sideAfter}
		}
		return searchPoint{side: sideBefore}
	}}
	got, ok := searchOffset(s.probe)
	assert.True(t, ok)
	assert.Equal(t, offsetSearch{unstable: true}, got)
	assert.Equal(t, []int64{1, 2, 4, 8, 16}, s.tried)
}

func TestSearchOffset_Unknown(t *testing.T) {
	unknown := searchPoint{side: sideUnknown, detail: "seq not learned"}
	for _, at := range []int64{64, 256} {
		s := &scriptedSearch{side: func(m int64) searchPoint {
			if m == at {
				return unknown
			}
			return beforeUpTo(100)(m)
		}}
		got, ok := searchOffset(s.probe)
		assert.True(t, ok)
		assert.Equal(t, offsetSearch{reason: "seq not learned"}, got)
		assert.Equal(t, at, s.tried[len(s.tried)-1], "ends the search")
	}
}

func TestSearchOffset_Interrupted(t *testing.T) {
	for _, stop := range []int{3, 9} {
		calls := 0
		_, ok := searchOffset(func(m int64) (searchPoint, bool) {
			calls++
			return beforeUpTo(64)(m), calls < stop
		})
		assert.False(t, ok)
		assert.Equal(t, stop, calls, "in the powers of two and at the point past the flip")
	}
}
