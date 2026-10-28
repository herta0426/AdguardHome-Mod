package snifilter

import (
	"context"
	"sync/atomic"
	"time"
)

// statsInterval is the interval at which the packet counters are reported, see
// [Filter.watchCounters].
const statsInterval = 60 * time.Second

// counters are the cumulative packet counters of the filter.  The packet
// handler is the only writer, but the reporter reads them from another
// goroutine, so the fields are atomic: the fast path neither takes a lock nor
// allocates.  A single packet may be counted by several fields, they are not
// exclusive.
type counters struct {
	// received is the number of the packets the kernel has handed over to the
	// queue.
	received atomic.Uint64

	// inspected is the number of the packets that reached [Filter.inspect],
	// that is the packets that passed both the cheap gate and the parsing of
	// the headers.
	inspected atomic.Uint64

	// truncated is the number of the packets that reached the inspection
	// with only the beginning of their payload copied into the userspace, see
	// queueCopyRange in firewall_linux.go.  A growing value means that the
	// copy range is too small for the segments the sender produces.
	truncated atomic.Uint64

	// sni is the number of the connections the server name was extracted
	// from.
	sni atomic.Uint64

	// logged is the number of the entries added to the query log.
	logged atomic.Uint64

	// resets is the number of the injected reset segments.  A blocked
	// connection produces up to two of them, one for each side, so this
	// counter grows twice as fast as the number of the blocked connections.
	resets atomic.Uint64

	// verdictErrors is the number of the failed [verdictSetter.SetVerdict]
	// calls.  Each of them makes the queue be re-registered.
	verdictErrors atomic.Uint64
}

// countersSnapshot is a copy of [counters] taken at a single point in time.
type countersSnapshot struct {
	received      uint64
	inspected     uint64
	truncated     uint64
	sni           uint64
	logged        uint64
	resets        uint64
	verdictErrors uint64
}

// snapshot returns the current values of c.
func (c *counters) snapshot() (s countersSnapshot) {
	return countersSnapshot{
		received:      c.received.Load(),
		inspected:     c.inspected.Load(),
		truncated:     c.truncated.Load(),
		sni:           c.sni.Load(),
		logged:        c.logged.Load(),
		resets:        c.resets.Load(),
		verdictErrors: c.verdictErrors.Load(),
	}
}

// attrPairs returns the attributes of s for logging.  The keys are stable, so
// that the field crews can grep for them, and are not renamed without a note in
// SNI_HANDOVER.md.
func (s countersSnapshot) attrPairs() []any {
	return []any{
		"sni_pkts_received", s.received,
		"sni_pkts_inspected", s.inspected,
		"sni_truncated", s.truncated,
		"sni_names_parsed", s.sni,
		"sni_querylog_written", s.logged,
		"sni_resets_sent", s.resets,
		"sni_verdict_errors", s.verdictErrors,
	}
}

// changedSince reports whether s differs from prev.  The reporter uses it to
// stay silent while the filter is idle, so that an idle AdGuard Home doesn't
// write a line every minute.
func (s countersSnapshot) changedSince(prev countersSnapshot) bool {
	return s != prev
}

// watchCounters reports the packet counters once per [statsInterval], but only
// if they have changed since the previous report.  It exits when ctx is
// canceled, so it must be started with f.wg incremented.
func (f *Filter) watchCounters(ctx context.Context) {
	defer f.wg.Done()

	ticker := time.NewTicker(statsInterval)
	defer ticker.Stop()

	prev := f.counters.snapshot()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		cur := f.counters.snapshot()
		if !cur.changedSince(prev) {
			continue
		}

		f.logger.InfoContext(ctx, "sni filter counters", cur.attrPairs()...)

		prev = cur
	}
}

// truncatedLogInterval is the number of the truncated packets after which the
// condition is logged once, so that a flood of such packets doesn't flood the
// log.  The very first one is logged as well.
const truncatedLogInterval = 512

// logTruncated records the packet that the kernel has copied only partially in
// the log periodically.  It's called from the packet handler, so it never blocks
// and does no work on the packets that are not logged.
func (f *Filter) logTruncated(p *packet) {
	n := f.counters.truncated.Load()
	if n != 1 && n%truncatedLogInterval != 0 {
		return
	}

	f.logger.Debug(
		"the packet is truncated by the nfqueue copy range; its payload is "+
			"not used for the handshake",
		"src", p.src,
		"dst", p.dst,
		"payload_len", len(p.payload),
		"truncated_packets", n,
	)
}
