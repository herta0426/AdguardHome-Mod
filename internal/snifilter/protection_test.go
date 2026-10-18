package snifilter

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testProtectionSrc returns the source endpoint of a connection inspected by the
// protection tests.  Every connection of the tests has its own source port, so
// that they don't share the state within a single filter.
func testProtectionSrc(port uint16) (src netip.AddrPort) {
	return netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), port)
}

// TestFilter_protectionActive tests the decision about whether the connections
// must be blocked at the given time.
func TestFilter_protectionActive(t *testing.T) {
	t.Parallel()

	now := time.Now()
	past := now.Add(-1 * time.Minute)
	future := now.Add(1 * time.Minute)

	testCases := []struct {
		until   *time.Time
		name    string
		enabled bool
		set     bool
		want    bool
	}{{
		name: "no_state",
		want: true,
	}, {
		name:    "enabled",
		set:     true,
		enabled: true,
		want:    true,
	}, {
		name:    "enabled_with_deadline",
		set:     true,
		enabled: true,
		until:   &future,
		want:    true,
	}, {
		name:  "paused_without_deadline",
		set:   true,
		until: nil,
		want:  false,
	}, {
		name:  "paused_until_future",
		set:   true,
		until: &future,
		want:  false,
	}, {
		name:  "paused_until_past",
		set:   true,
		until: &past,
		want:  true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := &Filter{}
			if tc.set {
				f.SetProtectionStatus(tc.enabled, tc.until)
			}

			assert.Equal(t, tc.want, f.protectionActive(now))
		})
	}
}

// TestFilter_SetProtectionStatus_snapshot tests that the filter keeps its own
// copy of the pause deadline instead of the structure of the caller.
func TestFilter_SetProtectionStatus_snapshot(t *testing.T) {
	t.Parallel()

	now := time.Now()
	until := now.Add(1 * time.Minute)

	f := &Filter{}
	f.SetProtectionStatus(false, &until)

	assert.False(t, f.protectionActive(now))

	// The caller reuses its structure, which must not affect the filter.
	until = now.Add(-1 * time.Minute)

	assert.False(t, f.protectionActive(now))
}

// TestFilter_inspect_paused tests that a connection that hits a blocking rule
// while the protection is paused is recorded in the query log, but accepted
// instead of reset.
func TestFilter_inspect_paused(t *testing.T) {
	t.Parallel()

	const (
		serverName = "ads.example.com"
		seq0       = uint32(1000)
	)

	hello := captureClientHello(t, serverName)
	require.NotEmpty(t, hello)

	ql := &countingQueryLog{}
	f := newTestFilter(t, ql)

	// The protection is paused while the ClientHello is inspected.
	f.SetProtectionStatus(false, nil)

	pkt := tcpPacket4(testProtectionSrc(12346), testReassemblyDst, seq0, 1, tcpFlagACK, hello)
	res := feedPacket(t, f, pkt)

	assert.Equal(t, verdictAccept, res.verdict, "the paused protection must not reset the connection")
	assert.Equal(t, 1, ql.count, "the connection must still be recorded")
	require.NotNil(t, ql.added)
	assert.Equal(t, serverName+".", ql.added.Question.Question[0].Name)

	// The filtering engine still reports the connection as blocked, and the
	// query log keeps its verdict, so the entry says what would have happened.
	assert.True(t, ql.added.Result.IsFiltered)
	assert.Equal(t, filtering.FilteredSNI, ql.added.Result.Reason)

	key := keyOf(t, f, pkt)
	fl := f.flows[key]
	require.NotNil(t, fl)
	assert.True(t, fl.decided)
	assert.False(t, fl.blocked, "the paused connection is recorded as accepted")

	// The rest of the paused connection stays on the fast path.
	cont := tcpPacket4(
		testProtectionSrc(12346),
		testReassemblyDst,
		seq0+uint32(len(hello)),
		1,
		tcpFlagACK,
		[]byte("application data"),
	)
	assert.False(t, f.needsInspect(cont))
	assert.Equal(t, verdictAccept, feedPacket(t, f, cont).verdict)
	assert.Equal(t, 1, ql.count)

	// The protection is back on, and the same ClientHello of another
	// connection is reset.
	f.SetProtectionStatus(true, nil)

	pkt = tcpPacket4(testProtectionSrc(12347), testReassemblyDst, seq0, 1, tcpFlagACK, hello)
	assert.Equal(t, verdictReset, feedPacket(t, f, pkt).verdict)
	assert.Equal(t, 2, ql.count)

	// A pause that is already over is the same as the protection being on.
	past := time.Now().Add(-1 * time.Minute)
	f.SetProtectionStatus(false, &past)

	pkt = tcpPacket4(testProtectionSrc(12348), testReassemblyDst, seq0, 1, tcpFlagACK, hello)
	assert.Equal(t, verdictReset, feedPacket(t, f, pkt).verdict)
	assert.Equal(t, 3, ql.count)
}

// TestFilter_inspect_pausedBlockedContinuation tests that the packets of a
// connection that was blocked before the pause are let through, while the
// verdict itself is kept.
func TestFilter_inspect_pausedBlockedContinuation(t *testing.T) {
	t.Parallel()

	const seq0 = uint32(1000)

	hello := captureClientHello(t, "ads.example.com")
	require.NotEmpty(t, hello)

	src := testProtectionSrc(12349)

	ql := &countingQueryLog{}
	f := newTestFilter(t, ql)

	pkt := tcpPacket4(src, testReassemblyDst, seq0, 1, tcpFlagACK, hello)
	require.Equal(t, verdictReset, feedPacket(t, f, pkt).verdict)
	require.Equal(t, 1, ql.count)

	key := keyOf(t, f, pkt)
	fl := f.flows[key]
	require.NotNil(t, fl)
	require.True(t, fl.blocked)

	// The protection is paused after the verdict was made.
	f.SetProtectionStatus(false, nil)

	cont := tcpPacket4(
		src,
		testReassemblyDst,
		seq0+uint32(len(hello)),
		1,
		tcpFlagACK,
		[]byte("application data"),
	)
	require.True(t, f.needsInspect(cont), "the blocked connection is still tracked")

	assert.Equal(
		t,
		verdictAccept,
		feedPacket(t, f, cont).verdict,
		"the connection blocked before the pause must be let through",
	)

	// The verdict is kept, so the connection is dropped again once the
	// protection is back on.
	f.SetProtectionStatus(true, nil)

	assert.Equal(t, verdictDrop, feedPacket(t, f, cont).verdict)
	assert.Equal(t, 1, ql.count, "the continuation must not be recorded again")
}
