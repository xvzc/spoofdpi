package desync

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSDesync_LogsCarrySNI(t *testing.T) {
	msg := fakeMsg()
	start, end, err := msg.ExtractSNIOffset()
	require.NoError(t, err)
	want := string(msg.Raw()[start:end])

	var log bytes.Buffer
	const server = "203.0.113.7"
	d := NewTLSDesyncer(
		zerolog.New(&log).Level(zerolog.DebugLevel),
		&recordingWriter{},
		hopStoreWith(ProtoTCP, 12, server),
		nil,
		nil,
	)
	require.Positive(t, desyncTLS(t, d, server))

	snis := map[string]string{}
	lines := bufio.NewScanner(bytes.NewReader(log.Bytes()))
	for lines.Scan() {
		var entry struct {
			Message string `json:"message"`
			SNI     string `json:"sni"`
		}
		require.NoError(t, json.Unmarshal(lines.Bytes(), &entry))
		snis[entry.Message] = entry.SNI
	}
	require.NoError(t, lines.Err())

	assert.Equal(t, want, snis["sent fake packets"])
	assert.Equal(t, want, snis["segments ready"])
}
