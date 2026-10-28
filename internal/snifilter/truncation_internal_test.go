package snifilter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTruncHelloPrefix makes a payload pass the cheap gate of
// [Filter.needsInspect].
var testTruncHelloPrefix = []byte{0x16, 0x03, 0x01, 0x00, 0x00, 0x01}

func TestParsePacketInto_truncated(t *testing.T) {
	src, dst := testReassemblySrc, testReassemblyDst

	pkt4 := tcpPacket4(src, dst, 1000, 1, tcpFlagACK, testTruncHelloPrefix)
	pkt6 := tcpPacket6(src, dst, 1000, 1, tcpFlagACK, testTruncHelloPrefix)

	// The IP headers of the packets keep the length of the whole packet, so
	// the cuts below are indistinguishable from the kernel copying only the
	// beginning of them.
	testCases := []struct {
		name string
		pkt  []byte
		want bool
	}{{
		name: "ipv4 whole",
		pkt:  pkt4,
		want: false,
	}, {
		name: "ipv4 with a trailer",
		pkt:  append(pkt4, 0, 0, 0, 0),
		want: false,
	}, {
		name: "ipv4 cut in the payload",
		pkt:  pkt4[:ipv4HeaderLen+tcpHeaderLen+2],
		want: true,
	}, {
		name: "ipv4 cut to the tcp header",
		pkt:  pkt4[:ipv4HeaderLen+tcpHeaderLen],
		want: true,
	}, {
		name: "ipv6 whole",
		pkt:  pkt6,
		want: false,
	}, {
		name: "ipv6 cut in the payload",
		pkt:  pkt6[:ipv6HeaderLen+tcpHeaderLen+2],
		want: true,
	}, {
		name: "ipv6 cut to the tcp header",
		pkt:  pkt6[:ipv6HeaderLen+tcpHeaderLen],
		want: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parsePacket(tc.pkt)
			require.NoError(t, err)

			assert.Equal(t, tc.want, p.truncated)
		})
	}
}

func TestFilter_addSegmentLocked_truncated(t *testing.T) {
	f := newTestFilter(t, nil)

	p := &packet{
		src:       testReassemblySrc,
		dst:       testReassemblyDst,
		payload:   make([]byte, 100),
		seq:       1000,
		truncated: true,
	}

	key := flowKey{src: p.src, dst: p.dst}

	f.mu.Lock()
	fl := f.newFlowLocked(key, time.Now())
	f.mu.Unlock()

	require.NotNil(t, fl)

	f.mu.Lock()
	changed := f.addSegmentLocked(fl, p)
	f.mu.Unlock()

	assert.False(t, changed)
	assert.False(t, fl.seqKnown)
	assert.Equal(t, uint32(0), fl.nextSeq)
	assert.Empty(t, fl.handshake)
	assert.Empty(t, fl.pending)
	assert.Equal(t, int64(0), f.bufferedBytes)

	// The same packet without the flag still grows the handshake, so the
	// check above is about the flag and not about some other limit.
	p.truncated = false

	f.mu.Lock()
	changed = f.addSegmentLocked(fl, p)
	f.mu.Unlock()

	assert.True(t, changed)
	assert.True(t, fl.seqKnown)
	assert.Equal(t, uint32(1100), fl.nextSeq)
	assert.Len(t, fl.handshake, 100)
}

func TestFilter_inspect_truncated(t *testing.T) {
	payload := make([]byte, 100)
	copy(payload, testTruncHelloPrefix)

	f := newTestFilter(t, nil)
	pkt := tcpPacket4(testReassemblySrc, testReassemblyDst, 1000, 1, tcpFlagACK, payload)

	// The kernel has copied only the first 70 bytes of the 140-byte packet,
	// so the payload is 30 bytes long instead of 100.
	cut := pkt[:ipv4HeaderLen+tcpHeaderLen+30]
	require.Less(t, len(cut), len(pkt))
	require.True(t, f.needsInspect(cut))

	assert.Equal(t, verdictAccept, feedPacket(t, f, cut).verdict)
	assert.Equal(t, uint64(1), f.counters.truncated.Load())

	key := keyOf(t, f, cut)

	f.mu.Lock()
	fl := f.flows[key]

	var (
		decided  bool
		seqKnown bool
		lens     [2]int
		nextSeq  uint32
	)
	if fl != nil {
		decided, seqKnown, nextSeq = fl.decided, fl.seqKnown, fl.nextSeq
		lens = [2]int{len(fl.handshake), len(fl.pending)}
	}
	f.mu.Unlock()

	require.NotNil(t, fl)
	assert.False(t, decided)
	assert.False(t, seqKnown)
	assert.Equal(t, uint32(0), nextSeq)
	assert.Equal(t, [2]int{0, 0}, lens)

	// The retransmission that fits into the copy range is still usable: the
	// truncated packet has not advanced the sequence bookkeeping.
	assert.Equal(t, verdictAccept, feedPacket(t, f, pkt).verdict)
	assert.Equal(t, uint64(1), f.counters.truncated.Load())

	f.mu.Lock()
	seqKnown, nextSeq = fl.seqKnown, fl.nextSeq
	f.mu.Unlock()

	assert.True(t, seqKnown)
	assert.Equal(t, uint32(1100), nextSeq)
}
