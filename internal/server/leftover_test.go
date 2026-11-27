package server

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoveLeftovers(t *testing.T) {
	var removed []string
	remove := func(name string, err error) func() error {
		return func() error {
			removed = append(removed, name)
			return err
		}
	}

	var logs bytes.Buffer
	RemoveLeftovers(zerolog.New(&logs), []Leftover{
		{
			Description:   "rule a",
			Remove:        remove("a", nil),
			ManualCommand: "ip rule del a",
		},
		{
			Description:   "rule b",
			ManualCommand: "ip rule del b",
		},
		{
			Description:   "rule c",
			Remove:        remove("c", errors.New("denied")),
			ManualCommand: "ip rule del c",
		},
	})

	assert.Equal(t, []string{"a", "c"}, removed,
		"a leftover without Remove is not removed")
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	require.Len(t, lines, 3, "one line per leftover")
	assert.Equal(t,
		`{"level":"info","leftover":"rule a",`+
			`"message":"removed leftover network configuration"}`,
		lines[0])
	assert.Equal(t,
		`{"level":"warn","leftover":"rule b","manual_command":"ip rule del b",`+
			`"message":"leftover network configuration not removed automatically"}`,
		lines[1])
	assert.Equal(t,
		`{"level":"warn","error":"denied","leftover":"rule c",`+
			`"manual_command":"ip rule del c",`+
			`"message":"failed to remove leftover network configuration"}`,
		lines[2])
}

func TestWarnLeftoversAfterReset(t *testing.T) {
	removed := false
	var logs bytes.Buffer
	WarnLeftoversAfterReset(zerolog.New(&logs), []Leftover{{
		Description:   "rule a",
		Remove:        func() error { removed = true; return nil },
		ManualCommand: "ip rule del a",
	}})

	assert.False(t, removed, "nothing is removed")
	assert.Equal(t,
		`{"level":"warn","leftover":"rule a","manual_command":"ip rule del a",`+
			`"message":"network configuration left after restoring it"}`+"\n",
		logs.String())
}
