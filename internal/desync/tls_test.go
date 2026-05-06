package desync

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/proto"
)

func TestApplySegmentPlans(t *testing.T) {
	// Using the FakeClientHello from config/types.go

	fakeRaw := []byte(config.FakeClientHello)

	msg := proto.NewFakeTLSMessage(fakeRaw)

	// We know where SNI is in FakeClientHello.
	// Let's verify SNI offset first to write correct assertions.
	sniStart, _, _ := msg.ExtractSNIOffset()
	t.Run("cut head", func(t *testing.T) {
		plans := []config.SegmentPlan{
			{
				From: config.SegmentFromHead,
				At:   5,
			},
		}

		chunks, err := applySegmentPlans(msg, plans)
		assert.NoError(t, err)
		assert.Len(t, chunks, 2)
		assert.Equal(t, fakeRaw[:5], chunks[0].Packet)
		assert.Equal(t, fakeRaw[5:], chunks[1].Packet)
		assert.False(t, chunks[0].Lazy)
		assert.False(t, chunks[1].Lazy)
	})

	t.Run("cut head lazy", func(t *testing.T) {
		plans := []config.SegmentPlan{
			{
				From: config.SegmentFromHead,
				At:   5,
				Lazy: true,
			},
		}

		chunks, err := applySegmentPlans(msg, plans)
		assert.NoError(t, err)
		assert.Len(t, chunks, 2)
		assert.Equal(t, fakeRaw[:5], chunks[0].Packet)
		assert.True(t, chunks[0].Lazy)
		assert.Equal(t, fakeRaw[5:], chunks[1].Packet)
		assert.False(t, chunks[1].Lazy) // Remainder is not lazy by default
	})

	t.Run("cut head multiple", func(t *testing.T) {
		plans := []config.SegmentPlan{
			{
				From: config.SegmentFromHead,
				At:   5,
			},
			{
				From: config.SegmentFromHead,
				At:   10,
			},
		}

		chunks, err := applySegmentPlans(msg, plans)
		assert.NoError(t, err)
		assert.Len(t, chunks, 3)
		assert.Equal(t, fakeRaw[:5], chunks[0].Packet)
		assert.Equal(t, fakeRaw[5:10], chunks[1].Packet)
		assert.Equal(t, fakeRaw[10:], chunks[2].Packet)
	})

	t.Run("cut sni", func(t *testing.T) {
		if sniStart == 0 {
			t.Skip("SNI not found in fake packet")
		}

		// Split at SNI start
		plans := []config.SegmentPlan{
			{
				From: config.SegmentFromSNI,
				At:   0,
			},
		}

		chunks, err := applySegmentPlans(msg, plans)
		assert.NoError(t, err)

		// Should be [0...sniStart], [sniStart...]
		assert.Len(t, chunks, 2)
		assert.Equal(t, fakeRaw[:sniStart], chunks[0].Packet)
		assert.Equal(t, fakeRaw[sniStart:], chunks[1].Packet)
	})

	t.Run("cut sni offset", func(t *testing.T) {
		if sniStart == 0 {
			t.Skip("SNI not found in fake packet")
		}

		offset := 5
		target := sniStart + offset
		plans := []config.SegmentPlan{
			{
				From: config.SegmentFromSNI,
				At:   offset,
			},
		}

		chunks, err := applySegmentPlans(msg, plans)
		assert.NoError(t, err)
		assert.Len(t, chunks, 2)
		assert.Equal(t, fakeRaw[:target], chunks[0].Packet)
		assert.Equal(t, fakeRaw[target:], chunks[1].Packet)
	})

	t.Run("cut mixed head and sni", func(t *testing.T) {
		if sniStart == 0 {
			t.Skip("SNI not found in fake packet")
		}

		// Split at 5 (head) and then at SNI start
		plans := []config.SegmentPlan{
			{
				From: config.SegmentFromHead,
				At:   5,
			},
			{
				From: config.SegmentFromSNI,
				At:   0,
			},
		}

		chunks, err := applySegmentPlans(msg, plans)
		assert.NoError(t, err)
		assert.Len(t, chunks, 3)
		assert.Equal(t, fakeRaw[:5], chunks[0].Packet)
		assert.Equal(t, fakeRaw[5:sniStart], chunks[1].Packet)
		assert.Equal(t, fakeRaw[sniStart:], chunks[2].Packet)
	})

	t.Run("out of order plans sorted", func(t *testing.T) {
		// Plans are out of order: split at 10 first, then 5.
		// After sorting, split points become [5, 10], producing correct segments.
		plans := []config.SegmentPlan{
			{
				From: config.SegmentFromHead,
				At:   10,
			},
			{
				From: config.SegmentFromHead,
				At:   5,
			},
		}

		chunks, err := applySegmentPlans(msg, plans)
		assert.NoError(t, err)
		assert.Len(t, chunks, 3)
		assert.Equal(t, fakeRaw[:5], chunks[0].Packet)
		assert.Equal(t, fakeRaw[5:10], chunks[1].Packet)
		assert.Equal(t, fakeRaw[10:], chunks[2].Packet)
	})

	t.Run("noise", func(t *testing.T) {
		// We can't strictly test random values, but we can check if it runs without panic

		plans := []config.SegmentPlan{
			{
				From:  config.SegmentFromHead,
				At:    10,
				Noise: 5,
			},
		}

		for i := 0; i < 50; i++ {
			chunks, err := applySegmentPlans(msg, plans)
			assert.NoError(t, err)
			assert.Len(t, chunks, 2)
			// Split point should be between 10-5=5 and 10+5=15
			splitLen := len(chunks[0].Packet)
			assert.GreaterOrEqual(t, splitLen, 5)
			assert.LessOrEqual(t, splitLen, 15)
		}
	})
}
