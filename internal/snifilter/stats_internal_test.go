package snifilter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCounters_snapshot(t *testing.T) {
	var c counters

	// The counters are cumulative and independent, so a single packet may
	// increase several of them.
	for i := 0; i < 7; i++ {
		c.received.Add(1)
	}

	for i := 0; i < 5; i++ {
		c.inspected.Add(1)
	}

	c.truncated.Add(1)

	for i := 0; i < 3; i++ {
		c.sni.Add(1)
	}

	for i := 0; i < 2; i++ {
		c.logged.Add(1)
	}

	// A single blocked connection is reset on both sides.
	for i := 0; i < 4; i++ {
		c.resets.Add(1)
	}

	c.verdictErrors.Add(1)

	assert.Equal(t, countersSnapshot{
		received:      7,
		inspected:     5,
		truncated:     1,
		sni:           3,
		logged:        2,
		resets:        4,
		verdictErrors: 1,
	}, c.snapshot())
}

func TestCountersSnapshot_changedSince(t *testing.T) {
	var c counters

	idle := c.snapshot()
	assert.False(t, idle.changedSince(idle))

	c.received.Add(1)
	busy := c.snapshot()
	assert.True(t, busy.changedSince(idle))

	// The reporter compares against the last reported snapshot, so an idle
	// filter stays silent.
	assert.False(t, busy.changedSince(busy))

	// A later report must not be silent if anything has changed since it.
	c.truncated.Add(1)
	assert.True(t, c.snapshot().changedSince(busy))
}

func TestCountersSnapshot_attrPairs(t *testing.T) {
	s := countersSnapshot{
		received:      1,
		inspected:     2,
		truncated:     1,
		sni:           3,
		logged:        4,
		resets:        5,
		verdictErrors: 6,
	}

	pairs := s.attrPairs()

	// slog requires the whole argument list to consist of key-value pairs.
	assert.Len(t, pairs, 14)

	attrs := map[string]any{}
	for i := 0; i < len(pairs); i += 2 {
		key, ok := pairs[i].(string)
		assert.True(t, ok, "key %d is not a string", i)

		_, dup := attrs[key]
		assert.False(t, dup, "duplicate key %q", key)

		attrs[key] = pairs[i+1]
	}

	assert.Equal(t, map[string]any{
		"sni_pkts_received":    uint64(1),
		"sni_pkts_inspected":   uint64(2),
		"sni_truncated":        uint64(1),
		"sni_names_parsed":     uint64(3),
		"sni_querylog_written": uint64(4),
		"sni_resets_sent":      uint64(5),
		"sni_verdict_errors":   uint64(6),
	}, attrs)
}
