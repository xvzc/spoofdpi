package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFormatConns(t *testing.T) {
	tcs := []struct {
		name     string
		n        int64
		expected string
	}{
		{name: "none", n: 0, expected: "active connections: 0"},
		{name: "one", n: 1, expected: "active connections: 1"},
		{name: "many", n: 42, expected: "active connections: 42"},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, formatConns(tc.n))
		})
	}
}

func TestModel_Update_ActiveConns(t *testing.T) {
	m := initialModel(nil)
	assert.Equal(t, "active connections: 0", m.conns, "before the server exists")

	active := int64(2)
	updated, _ := m.Update(activeConnsMsg(func() int64 { return active }))
	assert.Equal(t, "active connections: 2", updated.(model).conns)

	active = 5
	updated, _ = updated.Update(tickMsg(time.Now()))
	assert.Equal(t, "active connections: 5", updated.(model).conns,
		"each tick reads the count again")
}
