package snifilter

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingQueryLog is a [querylog.QueryLog] implementation that counts the added
// entries on top of the last one kept by [testQueryLog].
type countingQueryLog struct {
	testQueryLog
	count int
}

// type check
var _ querylog.QueryLog = (*countingQueryLog)(nil)

// Add implements the [querylog.QueryLog] interface for *countingQueryLog.
func (l *countingQueryLog) Add(p *querylog.AddParams) {
	l.count++
	l.testQueryLog.Add(p)
}

// testReassemblySrc and testReassemblyDst are the endpoints of the connections
// inspected by the reassembly tests.
var (
	testReassemblySrc = netip.MustParseAddrPort("10.0.0.1:12345")
	testReassemblyDst = netip.MustParseAddrPort("192.0.2.1:443")
)

// newTestFilter returns a filter that the tests drive themselves: it doesn't
// touch the netfilter queue, so it needs neither the root privileges nor the
// kernel support.
func newTestFilter(t *testing.T, ql querylog.QueryLog) (f *Filter) {
	t.Helper()

	df, err := filtering.New(&filtering.Config{
		Logger:            slogutil.NewDiscardLogger(),
		ProtectionEnabled: true,
	}, []filtering.Filter{{
		ID:   1,
		Data: []byte("||ads.example.com^"),
	}})
	require.NoError(t, err)

	df.SetEnabled(true)

	f = &Filter{
		logger:   slogutil.NewDiscardLogger(),
		filter:   df,
		queryLog: ql,
		flows:    map[flowKey]*flow{},
		ports:    []uint16{443},
	}

	// The tests that go through the queue callback need the pool, since
	// sync.Pool.Get returns nil for an empty pool without a New function,
	// while the callback type-asserts the result.  [New] sets it up the same
	// way.
	f.pktPool.New = func() (v any) { return &packet{} }

	return f
}

// feedPacket passes the raw packet pkt through the gate and the inspection the
// same way the queue callback does and returns the verdict.
func feedPacket(t *testing.T, f *Filter, pkt []byte) (res inspection) {
	t.Helper()

	if !f.needsInspect(pkt) {
		return inspection{verdict: verdictAccept}
	}

	p, err := parsePacket(pkt)
	require.NoError(t, err)

	return f.inspect(p)
}

// keyOf returns the key of the connection of the raw packet pkt.
func keyOf(t *testing.T, f *Filter, pkt []byte) (k flowKey) {
	t.Helper()

	k, ok := f.flowKeyOf(pkt)
	require.True(t, ok)

	return k
}

// TestFilter_inspect_splitHello tests that a ClientHello that doesn't fit into a
// single TCP segment is accumulated and inspected once its last segment
// arrives.
func TestFilter_inspect_splitHello(t *testing.T) {
	t.Parallel()

	const serverName = "ads.example.com"

	hello := captureClientHello(t, serverName)
	require.NotEmpty(t, hello)

	const seq0 = uint32(1000)
	mid := len(hello) / 2

	ql := &countingQueryLog{}
	f := newTestFilter(t, ql)

	first := tcpPacket4(testReassemblySrc, testReassemblyDst, seq0, 1, tcpFlagACK, hello[:mid])
	second := tcpPacket4(
		testReassemblySrc,
		testReassemblyDst,
		seq0+uint32(mid),
		1,
		tcpFlagACK,
		hello[mid:],
	)

	res := feedPacket(t, f, first)
	assert.Equal(t, verdictAccept, res.verdict)

	key := keyOf(t, f, first)
	fl := f.flows[key]
	require.NotNil(t, fl)
	assert.False(t, fl.decided)
	assert.Equal(t, 0, ql.count)
	assert.Equal(t, int64(mid), f.bufferedBytes)

	res = feedPacket(t, f, second)
	assert.Equal(t, verdictReset, res.verdict)

	assert.Equal(t, 1, ql.count)
	require.NotNil(t, ql.added)
	assert.Equal(t, serverName+".", ql.added.Question.Question[0].Name)
	assert.Equal(t, filtering.FilteredSNI, ql.added.Result.Reason)

	// The buffered data must be released once the verdict is known.
	fl = f.flows[key]
	require.NotNil(t, fl)
	assert.True(t, fl.decided)
	assert.True(t, fl.blocked)
	assert.Empty(t, fl.handshake)
	assert.Empty(t, fl.pending)
	assert.Zero(t, f.bufferedBytes)
	assert.Zero(t, f.pendingFlows)
}

// TestFilter_inspect_outOfOrder tests that the segments that arrive before the
// ones that precede them are kept and appended once the gap is filled.
func TestFilter_inspect_outOfOrder(t *testing.T) {
	t.Parallel()

	const serverName = "ads.example.com"

	hello := captureClientHello(t, serverName)
	require.NotEmpty(t, hello)

	const seq0 = uint32(1000)
	first, third := len(hello)/3, len(hello)*2/3

	ql := &countingQueryLog{}
	f := newTestFilter(t, ql)

	part := func(off, end int) (pkt []byte) {
		return tcpPacket4(
			testReassemblySrc,
			testReassemblyDst,
			seq0+uint32(off),
			1,
			tcpFlagACK,
			hello[off:end],
		)
	}

	// The first part creates the connection.
	res := feedPacket(t, f, part(0, first))
	assert.Equal(t, verdictAccept, res.verdict)

	key := keyOf(t, f, part(0, first))
	fl := f.flows[key]
	require.NotNil(t, fl)
	assert.False(t, fl.decided)

	// The third part arrives before the second one, so it must be kept.
	res = feedPacket(t, f, part(third, len(hello)))
	assert.Equal(t, verdictAccept, res.verdict)
	assert.False(t, fl.decided)
	assert.Equal(t, 1, f.pendingFlows)
	assert.Equal(t, len(hello)-third, fl.buffered)
	assert.Equal(t, int64(len(hello)-third+first), f.bufferedBytes)
	assert.Equal(t, 0, ql.count)

	// The second part fills the gap, and the kept part is appended after it.
	res = feedPacket(t, f, part(first, third))
	assert.Equal(t, verdictReset, res.verdict)

	assert.Equal(t, 1, ql.count)
	require.NotNil(t, ql.added)
	assert.Equal(t, serverName+".", ql.added.Question.Question[0].Name)

	assert.True(t, fl.decided)
	assert.Zero(t, f.pendingFlows)
	assert.Zero(t, f.bufferedBytes)
}

// TestFilter_inspect_retransmission tests that the repeated segments neither
// duplicate the handshake data nor produce extra query log entries.
func TestFilter_inspect_retransmission(t *testing.T) {
	t.Parallel()

	hello := captureClientHello(t, "ads.example.com")
	require.NotEmpty(t, hello)

	const seq0 = uint32(1000)

	ql := &countingQueryLog{}
	f := newTestFilter(t, ql)

	pkt := tcpPacket4(testReassemblySrc, testReassemblyDst, seq0, 1, tcpFlagACK, hello)

	res := feedPacket(t, f, pkt)
	assert.Equal(t, verdictReset, res.verdict)
	require.Equal(t, 1, ql.count)

	assert.NotPanics(t, func() {
		// The same segment again, and the segment that overlaps it.
		feedPacket(t, f, pkt)
		feedPacket(t, f, tcpPacket4(
			testReassemblySrc,
			testReassemblyDst,
			seq0+10,
			1,
			tcpFlagACK,
			hello[10:],
		))
	})

	assert.Equal(t, 1, ql.count, "the repeated segments must not be logged")
	assert.Zero(t, f.bufferedBytes)
	assert.Zero(t, f.pendingFlows)
}

// TestFilter_inspect_blockedContinuation tests that the packets that follow the
// one that got the connection blocked are dropped, so that the client cannot
// continue the connection after the reset.
func TestFilter_inspect_blockedContinuation(t *testing.T) {
	t.Parallel()

	hello := captureClientHello(t, "ads.example.com")
	require.NotEmpty(t, hello)

	const seq0 = uint32(1000)

	ql := &countingQueryLog{}
	f := newTestFilter(t, ql)

	pkt := tcpPacket4(testReassemblySrc, testReassemblyDst, seq0, 1, tcpFlagACK, hello)
	res := feedPacket(t, f, pkt)
	require.Equal(t, verdictReset, res.verdict)
	require.Equal(t, 1, ql.count)

	cont := tcpPacket4(
		testReassemblySrc,
		testReassemblyDst,
		seq0+uint32(len(hello)),
		1,
		tcpFlagACK,
		[]byte("application data"),
	)

	assert.True(t, f.needsInspect(cont))

	res = feedPacket(t, f, cont)
	assert.Equal(t, verdictDrop, res.verdict)
	assert.Equal(t, 1, ql.count)
}

// TestFilter_needsInspect tests the gate that decides whether the packet reaches
// the inspection.
func TestFilter_needsInspect(t *testing.T) {
	t.Parallel()

	hello := captureClientHello(t, "ads.example.com")
	require.NotEmpty(t, hello)

	const seq0 = uint32(1000)

	f := newTestFilter(t, &countingQueryLog{})

	pkt := tcpPacket4(testReassemblySrc, testReassemblyDst, seq0, 1, tcpFlagACK, hello)
	assert.True(t, f.needsInspect(pkt), "the beginning of a ClientHello")

	assert.False(t, f.needsInspect(nil), "empty")
	assert.False(t, f.needsInspect([]byte{0x45}), "truncated")

	assert.False(t, f.needsInspect(tcpPacket4(
		testReassemblySrc,
		netip.MustParseAddrPort("192.0.2.1:80"),
		seq0,
		1,
		tcpFlagACK,
		hello,
	)), "another port")

	cont := tcpPacket4(
		testReassemblySrc,
		testReassemblyDst,
		seq0+uint32(len(hello)),
		1,
		tcpFlagACK,
		[]byte("application data"),
	)

	assert.False(t, f.needsInspect(cont), "no connection is tracked yet")

	key := keyOf(t, f, cont)
	f.flows[key] = &flow{decided: true}
	assert.False(t, f.needsInspect(cont), "the connection is decided and allowed")

	f.flows[key].blocked = true
	assert.True(t, f.needsInspect(cont), "the connection is decided and blocked")

	delete(f.flows, key)
	f.flows[key] = &flow{}
	assert.True(t, f.needsInspect(cont), "the connection is still being inspected")
}

// TestFilter_inspect_memoryBudget tests that a new connection is not inspected
// once the handshake budget of the whole table is exhausted.
func TestFilter_inspect_memoryBudget(t *testing.T) {
	t.Parallel()

	hello := captureClientHello(t, "ads.example.com")
	require.NotEmpty(t, hello)

	ql := &countingQueryLog{}
	f := newTestFilter(t, ql)
	f.bufferedBytes = maxHandshakeBytes

	pkt := tcpPacket4(testReassemblySrc, testReassemblyDst, 1000, 1, tcpFlagACK, hello)

	res := feedPacket(t, f, pkt)
	assert.Equal(t, verdictAccept, res.verdict, "the traffic must not stop")

	key := keyOf(t, f, pkt)
	fl := f.flows[key]
	require.NotNil(t, fl)
	assert.True(t, fl.decided)
	assert.False(t, fl.blocked)
	assert.Empty(t, fl.handshake)
	assert.Equal(t, 0, ql.count)
	assert.Equal(t, uint64(1), f.overflowCount)

	// The rest of the packets of the connection stay on the fast path.
	assert.False(t, f.needsInspect(tcpPacket4(
		testReassemblySrc,
		testReassemblyDst,
		1000+uint32(len(hello)),
		1,
		tcpFlagACK,
		[]byte("application data"),
	)))
}

// TestFilter_evict tests the layered eviction of the connections.
func TestFilter_evict(t *testing.T) {
	t.Parallel()

	const limit = 16

	now := time.Now()

	keyOfPort := func(port uint16) (k flowKey) {
		return flowKey{
			src: netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), port),
			dst: testReassemblyDst,
		}
	}

	// newTable fills the table up to limit with the connections that are seen
	// less and less time ago, so that keys are ordered from the oldest one to
	// the newest one.  The first decided connections are marked as decided and
	// blocked.  All of them stay within the TTL, so that only the eviction
	// removes them.
	newTable := func(t *testing.T, decided int) (f *Filter, keys []flowKey) {
		t.Helper()

		f = newTestFilter(t, &countingQueryLog{})
		for i := 0; i < limit; i++ {
			k := keyOfPort(uint16(2000 + i))
			fl := &flow{
				handshake: make([]byte, 10),
				seen:      now.Add(-time.Duration(limit-i) * 100 * time.Millisecond),
			}
			if i < decided {
				fl.decided = true
				fl.blocked = true
			}

			f.flows[k] = fl
			f.bufferedBytes += 10
			keys = append(keys, k)
		}

		require.Len(t, f.flows, limit)
		require.Equal(t, int64(limit*10), f.bufferedBytes)

		return f, keys
	}

	// batch is the number of the connections the eviction removes at once.
	batch := evictBatchFor(limit)
	require.Equal(t, 2, batch)

	t.Run("decided_first", func(t *testing.T) {
		t.Parallel()

		f, keys := newTable(t, 8)

		require.True(t, f.evictLocked(now, limit))

		assert.Len(t, f.flows, limit-batch)
		for _, k := range keys[:batch] {
			assert.Nil(t, f.flows[k])
		}

		// The decisions about the rest of the connections are still there,
		// and the ones that are still being inspected are not touched.
		for _, k := range keys[batch:] {
			fl := f.flows[k]
			require.NotNil(t, fl)
			assert.Len(t, fl.handshake, 10)
		}

		for _, k := range keys[2:8] {
			assert.True(t, f.flows[k].decided)
			assert.True(t, f.flows[k].blocked)
		}

		assert.Equal(t, int64((limit-batch)*10), f.bufferedBytes)
	})

	t.Run("undecided_second", func(t *testing.T) {
		t.Parallel()

		f, keys := newTable(t, 0)

		require.True(t, f.evictLocked(now, limit))

		// There is nothing to evict in the first tier, so the oldest
		// connections are removed instead.
		assert.Len(t, f.flows, limit-batch)
		for _, k := range keys[:batch] {
			assert.Nil(t, f.flows[k])
		}

		for _, k := range keys[batch:] {
			assert.NotNil(t, f.flows[k])
		}

		assert.Equal(t, int64((limit-batch)*10), f.bufferedBytes)
	})

	t.Run("outdated", func(t *testing.T) {
		t.Parallel()

		f, keys := newTable(t, 8)
		for _, k := range keys {
			f.flows[k].seen = now.Add(-2 * flowTTL)
		}

		require.True(t, f.evictLocked(now, limit))

		assert.Empty(t, f.flows)
		assert.Zero(t, f.bufferedBytes)
	})

	t.Run("pending", func(t *testing.T) {
		t.Parallel()

		f, keys := newTable(t, limit)
		k := keys[0]
		f.flows[k].pending = []pendingSeg{{seq: 100, data: make([]byte, 100)}}
		f.flows[k].buffered = 100
		f.bufferedBytes += 100
		f.pendingFlows = 1

		require.True(t, f.evictLocked(now, limit))

		// The evicted connection must not keep its bytes accounted.
		require.Nil(t, f.flows[k])
		assert.Zero(t, f.pendingFlows)
		assert.Equal(t, int64((limit-batch)*10), f.bufferedBytes)
	})
}
