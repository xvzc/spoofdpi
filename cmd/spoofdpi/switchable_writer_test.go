package main

import (
	"bytes"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lockedBuffer is a bytes.Buffer that is safe for concurrent writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func TestSwitchableWriter_SetWriterWhileWriting(t *testing.T) {
	first, second := &lockedBuffer{}, &lockedBuffer{}
	sw := &SwitchableWriter{}
	sw.SetWriter(first)

	const writes = 100
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range writes {
			_, err := sw.Write([]byte("x"))
			assert.NoError(t, err)
		}
	}()
	sw.SetWriter(second)
	wg.Wait()

	assert.Equal(t, writes, first.Len()+second.Len())
	_, err := sw.Write([]byte("y"))
	require.NoError(t, err)
	assert.Positive(t, second.Len(), "writes after SetWriter go to the new target")
}
