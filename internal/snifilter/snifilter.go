// Package snifilter implements the blocking of TLS connections by their SNI
// values.
//
// Filter lists of AdGuard Home know nothing about TLS connections that don't
// use the DNS of AdGuard Home, for example the ones made by applications that
// use their own DNS-over-HTTPS resolvers or connect to hard-coded addresses.
// The server name in a ClientHello, however, is not encrypted, so it can be
// used to block those connections as well.
//
// The Linux implementation, see firewall_linux.go, uses NFQUEUE to peek at the
// beginning of every outgoing TLS connection without taking over the routing,
// and injects a TCP RST into the ones that are blocked.  It requires the
// netfilter support for the "connbytes" and "NFQUEUE" targets in the kernel.
package snifilter

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/miekg/dns"
)

const (
	// maxHandshakeSize is the maximum number of bytes of a ClientHello kept
	// per connection.
	maxHandshakeSize = 1 << 15

	// maxHandshakeBytes is the maximum number of the handshake bytes that the
	// connection table keeps in total, including the out-of-order segments.
	maxHandshakeBytes = 16 << 20

	// maxFlows is the maximum number of connections tracked at the same time.
	maxFlows = 1 << 14

	// maxFlowPendingSegs is the maximum number of the out-of-order segments
	// kept per connection.
	maxFlowPendingSegs = 4

	// maxPendingBytes is the maximum number of bytes kept in the
	// out-of-order segments of a single connection.
	maxPendingBytes = 4096

	// maxPendingFlows is the maximum number of connections that may wait for
	// the missing segments at the same time.
	maxPendingFlows = 256

	// flowTTL is the time during which the state of a connection is kept
	// after the last packet of it was inspected.
	flowTTL = 1 * time.Minute

	// flowsCheckInterval is the interval at which the state of the
	// connections that are not active anymore is removed.
	flowsCheckInterval = 30 * time.Second

	// evictBatch is the number of the connections removed at once when the
	// connection table overflows, see [evictBatchFor].
	evictBatch = maxFlows / 8

	// overflowLogInterval is the number of the connections that were not
	// inspected because of the exhausted budgets after which the condition is
	// logged once, so that a flood of the packets doesn't flood the log too.
	overflowLogInterval = 1024
)

// TCP flags used by the filter.
const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagACK = 0x10
)

// Lengths of the protocol headers used by the filter.
const (
	// tcpHeaderLen is the length of a TCP header without options.
	tcpHeaderLen = 20

	// ipv4HeaderLen is the length of an IPv4 header without options.
	ipv4HeaderLen = 20

	// ipv6HeaderLen is the length of an IPv6 header.
	ipv6HeaderLen = 40

	// ipProtoTCP is the IP protocol number of TCP.
	ipProtoTCP = 6
)

// Protocol numbers of the IPv6 extension headers and of the protocols that
// prevent the filter from inspecting the upper layer.
const (
	ipProtoHopByHop     = 0
	ipProtoRouting      = 43
	ipProtoFragment     = 44
	ipProtoESP          = 50
	ipProtoAH           = 51
	ipProtoNoNextHeader = 59
	ipProtoDestOpts     = 60
	ipProtoMobility     = 135
	ipProtoHIP          = 139
	ipProtoShim6        = 140
)

// Limits of the walk through the IPv6 extension headers.
const (
	// ipv6MaxExtHdrs is the maximum number of the IPv6 extension headers
	// inspected before giving up.
	ipv6MaxExtHdrs = 8

	// ipv6MaxExtLen is the maximum total length of the IPv6 extension headers
	// inspected before giving up.
	ipv6MaxExtLen = 256
)

// Errors returned by [parsePacket].
var (
	errNotIPPacket  = errors.Error("not an ip packet")
	errNotTCPPacket = errors.Error("not a tcp packet")
)

// Params is the configuration of the SNI filter read from the configuration
// file.
type Params struct {
	// Ports is the list of TCP ports to inspect.  It must not be empty.
	Ports []uint16 `yaml:"ports"`

	// QueueNum is the number of the NFQUEUE queue used to receive the packets.
	QueueNum uint16 `yaml:"queue_num"`

	// UIDs is the list of the ranges of the IDs of the users the processes of
	// which should be inspected, for example "10000-19999".  An empty slice
	// means all processes.
	UIDs []string `yaml:"uids"`

	// DropQUIC defines whether to reject the UDP traffic to Ports in order to
	// make the clients fall back to TCP.  The server names in QUIC are
	// encrypted, so the SNI filter cannot inspect it.
	DropQUIC bool `yaml:"drop_quic"`
}

// Validate returns an error if p isn't valid.
func (p *Params) Validate() (err error) {
	if len(p.Ports) == 0 {
		return errors.Error("ports: empty")
	}

	for _, port := range p.Ports {
		if port == 0 {
			return fmt.Errorf("ports: invalid port %d", port)
		}
	}

	for _, uids := range p.UIDs {
		if !validUIDRange(uids) {
			return fmt.Errorf("uids: invalid range %q", uids)
		}
	}

	return nil
}

// validUIDRange returns true if r is a valid user ID or a range of them, for
// example "1000" or "10000-19999".
func validUIDRange(r string) (ok bool) {
	first, last, found := strings.Cut(r, "-")
	if !found {
		_, ok = parseUID(r)

		return ok
	}

	firstID, firstOK := parseUID(first)
	lastID, lastOK := parseUID(last)

	return firstOK && lastOK && firstID <= lastID
}

// parseUID parses a user ID.
func parseUID(s string) (id uint32, ok bool) {
	if s == "" {
		return 0, false
	}

	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, false
		}
	}

	var v uint64
	for _, c := range []byte(s) {
		v = v*10 + uint64(c-'0')
		if v > 1<<32-1 {
			return 0, false
		}
	}

	return uint32(v), true
}

// Config is the configuration of the SNI filter.
type Config struct {
	// Logger is used to log the operation of the filter.  It must not be nil.
	Logger *slog.Logger

	// Filter is the DNS filtering engine used to check the host names.  It
	// must not be nil.
	Filter *filtering.DNSFilter

	// QueryLog, if not nil, is used to record the blocked connections, so
	// that they can be analyzed in the admin UI.
	QueryLog querylog.QueryLog

	// Params are the settings read from the configuration file.
	Params
}

// Filter inspects outgoing TLS connections and resets the ones whose server
// name is blocked by the filtering rules.
type Filter struct {
	logger *slog.Logger
	filter *filtering.DNSFilter

	// flows is the state of the connections being inspected.  It's protected
	// by mu.
	flows map[flowKey]*flow

	// queryLog is used to record the blocked connections.  It's nil if the
	// query log is not available.
	queryLog querylog.QueryLog

	// bufferedBytes is the total number of the handshake bytes kept in the
	// connection table.  It's protected by mu.
	bufferedBytes int64

	// pendingFlows is the number of the connections that wait for the missing
	// segments.  It's protected by mu.
	pendingFlows int

	// lastExpire is the time when the outdated connections were removed last
	// time.  It's protected by mu.
	lastExpire time.Time

	// overflowCount is the number of the connections that were not inspected
	// because of the exhausted budgets.  It's protected by mu.
	overflowCount uint64

	ports    []uint16
	uids     []string
	queueNum uint16
	dropQUIC bool

	cancel context.CancelFunc
	wg     sync.WaitGroup
	mu     sync.Mutex

	// pktPool reuses the parsed-packet structures between the packets that
	// reach the connection table, keeping the allocation rate low.
	pktPool sync.Pool

	// platform is the platform-specific state of the filter.
	platform
}

// flowKey uniquely identifies a TCP connection.
type flowKey struct {
	src netip.AddrPort
	dst netip.AddrPort
}

// flow is the state of a single inspected connection.
type flow struct {
	// handshake is the accumulated client's handshake data.
	handshake []byte

	// pending are the out-of-order segments of the handshake.  They are kept
	// until the missing bytes arrive, and the order is not significant.
	pending []pendingSeg

	// seen is the time when the last packet of the connection was inspected.
	seen time.Time

	// nextSeq is the sequence number of the byte that must follow the last
	// byte of handshake.  It's only meaningful if seqKnown is true.
	nextSeq uint32

	// buffered is the number of bytes in the payloads of pending.
	buffered int

	// seqKnown is true if nextSeq has been synchronized with the sequence
	// number of a packet of the connection.
	seqKnown bool

	// decided is true if the verdict for the connection is already known.
	decided bool

	// blocked is true if the connection must be dropped.
	blocked bool
}

// pendingSeg is an out-of-order TCP segment kept until the missing bytes of the
// handshake arrive.
type pendingSeg struct {
	// data is the payload of the segment.  It's a copy of the bytes of the
	// packet, since the kernel reuses its buffer.
	data []byte

	// seq is the sequence number of the first byte of data.
	seq uint32
}

// New returns a new SNI filter.  c must not be nil.
func New(c *Config) (f *Filter, err error) {
	err = c.Params.Validate()
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	f = &Filter{
		logger:   c.Logger,
		filter:   c.Filter,
		flows:    map[flowKey]*flow{},
		queryLog: c.QueryLog,
		ports:    slices.Clone(c.Ports),
		uids:     slices.Clone(c.UIDs),
		queueNum: c.QueueNum,
		dropQUIC: c.DropQUIC,
	}
	f.pktPool.New = func() (v any) { return &packet{} }

	return f, nil
}

// Start starts inspecting the connections.  It returns an error if the
// platform support is unavailable.
func (f *Filter) Start(ctx context.Context) (err error) {
	// The filter outlives the caller of Start, which may be an HTTP request
	// handler, so its context must not be canceled along with the request.
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	f.mu.Lock()
	f.cancel = cancel
	f.mu.Unlock()

	err = f.startFirewall(ctx)
	if err != nil {
		cancel()

		return err
	}

	f.logger.InfoContext(
		ctx,
		"sni filter started",
		"ports", f.ports,
		"queue_num", f.queueNum,
		"uid_ranges", f.uids,
		"drop_quic", f.dropQUIC,
	)

	return nil
}

// Shutdown stops inspecting the connections.
func (f *Filter) Shutdown(ctx context.Context) {
	f.mu.Lock()
	cancel := f.cancel
	f.cancel = nil
	f.mu.Unlock()

	if cancel != nil {
		cancel()
	}

	f.wg.Wait()
	f.stopFirewall(ctx)

	f.mu.Lock()
	f.clearLocked()
	f.mu.Unlock()
}

// packet is a parsed TCP packet.
type packet struct {
	// src and dst are the sender and the receiver of the packet.
	src, dst netip.AddrPort

	// payload is the TCP payload of the packet.
	payload []byte

	// seq is the sequence number of the packet.
	seq uint32

	// ack is the acknowledgment number of the packet.
	ack uint32

	// flags are the TCP flags of the packet.
	flags uint8

	// fragmented is true if the packet is the first fragment of a fragmented
	// IPv4 packet.  The rest of the handshake stays in the other fragments,
	// which the filter cannot inspect.
	fragmented bool
}

// rstSegment describes a TCP RST segment to inject.
type rstSegment struct {
	src, dst netip.AddrPort
	seq, ack uint32
}

// verdict is the action to take for an inspected packet.
type verdict int

const (
	// verdictAccept means that the packet must be passed through.
	verdictAccept verdict = iota

	// verdictDrop means that the packet must be dropped.
	verdictDrop

	// verdictReset means that the packet must be dropped and the connection
	// must be reset.
	verdictReset
)

// inspection is the result of inspecting a packet.
type inspection struct {
	// toClient is the reset segment that the client must receive.  It's only
	// meaningful when verdict is [verdictReset].
	toClient rstSegment

	// toServer is the reset segment that the server must receive.  It's only
	// meaningful when verdict is [verdictReset].
	toServer rstSegment

	// verdict is the action to take for the packet.
	verdict verdict
}

// inspect checks the packet against the filtering rules and returns the action
// to take for it.
func (f *Filter) inspect(p *packet) (res inspection) {
	res.verdict = verdictAccept

	if p.flags&tcpFlagRST != 0 {
		// The connection is already being torn down, nothing to inspect.
		return res
	}

	key := flowKey{src: p.src, dst: p.dst}
	now := time.Now()

	f.mu.Lock()
	fl := f.flows[key]
	if fl == nil {
		fl = f.newFlowLocked(key, now)
		if fl == nil {
			// The budgets of the connection table are exhausted, see
			// [Filter.newFlowLocked].
			f.mu.Unlock()

			return res
		}
	}
	fl.seen = now

	if fl.decided {
		blocked := fl.blocked
		f.mu.Unlock()

		if blocked {
			res.verdict = verdictDrop
		}

		return res
	}

	if !f.addSegmentLocked(fl, p) {
		// The packet has added nothing to the handshake, so there is nothing
		// new to sniff: it's either a repeated or an out-of-order segment.
		f.mu.Unlock()

		return res
	}
	handshake := fl.handshake
	f.mu.Unlock()

	name, err := sniffSNI(handshake)
	switch {
	case err == nil && name != "":
		filterRes := f.checkHost(name)
		blocked := filterRes.IsFiltered
		f.decide(key, blocked)
		f.logConnection(p, name, filterRes)
		if blocked {
			res.verdict = verdictReset
			res.toClient, res.toServer = resetSegments(p)
		}
	case err == nil:
		f.decide(key, false)
	case errors.Is(err, errNeedMore):
		// Wait for the next packet of the connection.  Only the first
		// fragment of a fragmented IPv4 packet is inspected, so its server
		// name is likely to stay out of reach.
		if p.fragmented {
			f.logger.Debug(
				"fragmented ClientHello, the SNI is likely missed",
				"src", p.src,
				"dst", p.dst,
			)
		}
	default:
		// The connection doesn't carry a TLS ClientHello, so there is no
		// server name to check.
		f.decide(key, false)
	}

	return res
}

// decide stores the verdict for the connection identified by key.
func (f *Filter) decide(key flowKey, blocked bool) {
	f.mu.Lock()
	fl := f.flows[key]
	if fl != nil {
		fl.decided = true
		fl.blocked = blocked
		f.releaseLocked(fl)
	}
	f.mu.Unlock()
}

// newFlowLocked adds the connection identified by key to the table and returns
// it.  It returns nil if the connection must not be inspected: either nothing
// has been added because the table is full, or the connection has been recorded
// as a decided and accepted one because the memory budget is exhausted.  f.mu
// must be locked.
func (f *Filter) newFlowLocked(key flowKey, now time.Time) (fl *flow) {
	if !f.evictLocked(now, maxFlows) {
		f.skipFlowLocked("flow_table_full")

		return nil
	}

	fl = &flow{seen: now}
	if !f.canBufferLocked() {
		// The handshake data kept in the table has already reached the
		// global budget, so the connection is not inspected.  The verdict
		// is a fail-open one, since the memory limits must not stop the
		// traffic, and the connection is recorded as decided to keep the
		// rest of its packets on the fast path.
		fl.decided = true
		f.flows[key] = fl
		f.skipFlowLocked("memory_budget")

		return nil
	}

	f.flows[key] = fl

	return fl
}

// canBufferLocked returns true if a new connection may keep its handshake data.
// f.mu must be locked.
func (f *Filter) canBufferLocked() (ok bool) {
	return f.bufferedBytes < maxHandshakeBytes && f.pendingFlows < maxPendingFlows
}

// skipFlowLocked records the connection that was not inspected because of the
// exhausted budgets and logs the condition periodically.  f.mu must be locked.
func (f *Filter) skipFlowLocked(reason string) {
	f.overflowCount++
	if f.overflowCount != 1 && f.overflowCount%overflowLogInterval != 0 {
		return
	}

	f.logger.Warn(
		"sni filter is over its budgets, the connections are not inspected",
		"reason", reason,
		"skipped", f.overflowCount,
		"flows", len(f.flows),
		"buffered_bytes", f.bufferedBytes,
		"pending_flows", f.pendingFlows,
	)
}

// seqDiff returns the distance from a to b, that is a - b modulo 2^{32}, as the
// TCP sequence numbers wrap around.  The result is never the minimum int32, so
// that its negation is safe.
func seqDiff(a, b uint32) (d int64) {
	d = int64(int32(a - b))
	if d == -1<<31 {
		return 1 << 31
	}

	return d
}

// addSegmentLocked adds the payload of the packet p to the handshake of fl,
// dropping the repeated bytes and keeping the out-of-order segments until the
// missing ones arrive.  changed is true if the handshake has grown, in which case
// there is something new to sniff.  f.mu must be locked.
//
// The rule that sends the packets to the queue filters the SYN segments out, so
// the sequence number of the first segment seen is the best estimate of the
// beginning of the handshake, and the segments that arrive before that estimate
// are dropped.
func (f *Filter) addSegmentLocked(fl *flow, p *packet) (changed bool) {
	data := p.payload
	if len(data) == 0 || len(fl.handshake) >= maxHandshakeSize {
		return false
	}

	prevLen := len(fl.handshake)

	if !fl.seqKnown {
		fl.seqKnown = true
		fl.nextSeq = p.seq
		if p.flags&tcpFlagSYN != 0 {
			fl.nextSeq++
		}
	}

	// The comparison must be a signed one, since the sequence numbers wrap
	// around.
	switch diff := seqDiff(p.seq, fl.nextSeq); {
	case diff == 0:
		// The segment continues the handshake.
		f.appendHandshakeLocked(fl, data)
		f.drainPendingLocked(fl)
	case diff < 0:
		// The segment starts before the expected byte, so it either
		// overlaps the data that is already there or repeats it.  Only the
		// tail of it is new.
		if off := -diff; off < int64(len(data)) {
			f.appendHandshakeLocked(fl, data[off:])
			f.drainPendingLocked(fl)
		}
	default:
		// The segment is ahead of the expected byte, so the segment that
		// precedes it is lost or reordered.  Keep it until it arrives.
		f.bufferSegmentLocked(fl, p.seq, data)
	}

	return len(fl.handshake) != prevLen
}

// appendHandshakeLocked appends data, which continues the handshake of fl, to it
// and advances the expected sequence number.  The bytes that overflow
// [maxHandshakeSize] are dropped, but the sequence number is still advanced.
// f.mu must be locked.
func (f *Filter) appendHandshakeLocked(fl *flow, data []byte) {
	fl.nextSeq += uint32(len(data))

	n := min(len(data), maxHandshakeSize-len(fl.handshake))
	if n <= 0 {
		return
	}

	fl.handshake = append(fl.handshake, data[:n]...)
	f.bufferedBytes += int64(n)
}

// bufferSegmentLocked keeps the out-of-order segment with the sequence number
// seq until the missing bytes of the handshake arrive.  The segment is dropped
// if the connection already holds [maxFlowPendingSegs] segments or
// [maxPendingBytes] bytes of them, in which case the connection is left to the
// TTL.  f.mu must be locked.
func (f *Filter) bufferSegmentLocked(fl *flow, seq uint32, data []byte) {
	if len(fl.pending) >= maxFlowPendingSegs || fl.buffered+len(data) > maxPendingBytes {
		return
	}

	seg := pendingSeg{seq: seq, data: slices.Clone(data)}
	fl.pending = append(fl.pending, seg)
	fl.buffered += len(seg.data)
	f.bufferedBytes += int64(len(seg.data))

	if len(fl.pending) == 1 {
		f.pendingFlows++
	}
}

// drainPendingLocked appends the kept out-of-order segments that continue the
// handshake of fl to it, until a gap or no segments are left.  f.mu must be
// locked.
func (f *Filter) drainPendingLocked(fl *flow) {
	for len(fl.pending) > 0 {
		di := -1
		for i, seg := range fl.pending {
			if seqDiff(seg.seq, fl.nextSeq) <= 0 {
				di = i

				break
			}
		}
		if di < 0 {
			// All the kept segments are still ahead of the expected byte.
			return
		}

		seg := f.removePendingLocked(fl, di)
		// The segment may start before the expected byte, in which case only
		// its tail is new, or it may be entirely behind it, in which case it
		// is a duplicate.
		if off := seqDiff(fl.nextSeq, seg.seq); off < int64(len(seg.data)) {
			f.appendHandshakeLocked(fl, seg.data[off:])
		}
	}
}

// removePendingLocked removes the segment at i from the out-of-order segments of
// fl and returns it.  f.mu must be locked.
func (f *Filter) removePendingLocked(fl *flow, i int) (seg pendingSeg) {
	seg = fl.pending[i]
	fl.pending = slices.Delete(fl.pending, i, i+1)
	fl.buffered -= len(seg.data)
	f.bufferedBytes -= int64(len(seg.data))

	if len(fl.pending) == 0 {
		f.pendingFlows--
	}

	return seg
}

// releaseLocked drops the buffered bytes of fl and subtracts them from the
// global accounting.  f.mu must be locked.
func (f *Filter) releaseLocked(fl *flow) {
	if len(fl.pending) > 0 {
		f.pendingFlows--
	}

	f.bufferedBytes -= int64(len(fl.handshake) + fl.buffered)
	fl.handshake = nil
	fl.pending = nil
	fl.buffered = 0
}

// deleteLocked removes the connection identified by key from the table and drops
// its buffers.  ok is false if there was no such connection.  f.mu must be
// locked.
func (f *Filter) deleteLocked(key flowKey) (ok bool) {
	fl, ok := f.flows[key]
	if !ok {
		return false
	}

	f.releaseLocked(fl)
	delete(f.flows, key)

	return true
}

// clearLocked removes all the connections and drops their buffers.  f.mu must be
// locked.
func (f *Filter) clearLocked() {
	clear(f.flows)
	f.bufferedBytes = 0
	f.pendingFlows = 0
}

// logConnection records the inspected connection in the query log, so that the
// server names, both the blocked and the allowed ones, can be analyzed in the
// admin UI.  res is the result of checking host against the filtering rules,
// and it must not be nil.
func (f *Filter) logConnection(p *packet, host string, res *filtering.Result) {
	if f.queryLog == nil {
		return
	}

	// The modules of AdGuard Home have their own lists of the hosts that
	// shouldn't be written to the query log, so respect them as well.
	if !f.queryLog.ShouldLog(host, dns.TypeA, dns.ClassINET, nil) {
		return
	}

	// A TLS connection isn't a DNS request, so the question is composed to
	// make the server name visible in the query log.  The blocked connections
	// and the allowed ones get the reasons of the SNI filtering, which tells
	// them apart from the DNS requests, including the allowed ones.  The rules
	// found by the filtering engine are kept, so an allowlist hit is still
	// visible in the details of the entry.
	logRes := &filtering.Result{
		Rules:      res.Rules,
		Reason:     filtering.NotFilteredSNI,
		IsFiltered: res.IsFiltered,
	}
	if res.IsFiltered {
		logRes.Reason = filtering.FilteredSNI
	}

	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(host), dns.TypeA)
	req.RecursionDesired = true

	// A TLS connection has no upstream, but it does have a destination, which
	// the DNS requests don't make visible.  Record it, so that the address the
	// application actually connected to can be seen in the details.
	var dst string
	if p.dst.IsValid() {
		dst = p.dst.String()
	}

	f.queryLog.Add(&querylog.AddParams{
		Question: req,
		Result:   logRes,
		Dst:      dst,
		ClientIP: p.src.Addr().AsSlice(),
	})
}

// evictLocked removes the connections that are needed the least to make room
// for a new one.  limit is the maximum number of the connections kept in the
// table at the same time.  ok is false if the table is still full, in which case
// the caller must not add a new connection.  f.mu must be locked.
func (f *Filter) evictLocked(now time.Time, limit int) (ok bool) {
	if len(f.flows) < limit {
		return true
	}

	f.expireLocked(now)

	if len(f.flows) < limit {
		return true
	}

	// The verdicts of the inspected connections are worth less than the data
	// of the connections that are still being inspected, so the decided ones
	// go first.
	batch := evictBatchFor(limit)
	removed := f.evictOldestLocked(batch, true)
	if removed > 0 {
		f.logEvictionLocked("decided", removed)
	}

	if len(f.flows) < limit {
		return true
	}

	removed = f.evictOldestLocked(batch, false)
	if removed > 0 {
		f.logEvictionLocked("undecided", removed)
	}

	return len(f.flows) < limit
}

// evictBatchFor returns the number of the connections removed from the table
// with limit connections at once.  It's a fraction of [evictBatch], but at least
// one connection, so that the small limits used in the tests make progress.
func evictBatchFor(limit int) (batch int) {
	batch = limit * evictBatch / maxFlows
	if batch < 1 {
		return 1
	}

	return batch
}

// evictOldestLocked removes up to batch connections with the given decided state
// starting from the ones that were seen the longest time ago.  It returns the
// number of the removed connections.  f.mu must be locked.
func (f *Filter) evictOldestLocked(batch int, decided bool) (removed int) {
	keys := make([]flowKey, 0, len(f.flows))
	for k, fl := range f.flows {
		if fl.decided == decided {
			keys = append(keys, k)
		}
	}

	// The allocation above only happens when the table overflows, which is
	// the emergency path, and it is bounded by the size of the table.
	slices.SortFunc(keys, func(a, b flowKey) (res int) {
		return f.flows[a].seen.Compare(f.flows[b].seen)
	})

	removed = min(len(keys), batch)
	for _, k := range keys[:removed] {
		f.deleteLocked(k)
	}

	return removed
}

// logEvictionLocked records the eviction of the connections.  f.mu must be
// locked.
func (f *Filter) logEvictionLocked(reason string, removed int) {
	f.logger.Warn(
		"evicting the sni filter connections",
		"reason", reason,
		"removed", removed,
		"flows", len(f.flows),
		"buffered_bytes", f.bufferedBytes,
		"pending_flows", f.pendingFlows,
	)
}

// expireFlows removes the state of the connections that are not active
// anymore.
func (f *Filter) expireFlows() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.expireLocked(time.Now())
}

// expireLocked removes the outdated connections.  The pass over the whole table
// runs at most once per [flowsCheckInterval], since the new connections trigger
// it as well.  f.mu must be locked.
func (f *Filter) expireLocked(now time.Time) {
	if now.Sub(f.lastExpire) < flowsCheckInterval {
		return
	}
	f.lastExpire = now

	for k, fl := range f.flows {
		if now.Sub(fl.seen) > flowTTL {
			f.deleteLocked(k)
		}
	}
}

// checkHost returns the result of checking the host name against the filtering
// rules.  It never returns nil.
func (f *Filter) checkHost(host string) (res *filtering.Result) {
	setts := f.filter.Settings()
	setts.ProtectionEnabled = true

	resVal, err := f.filter.CheckHostRules(host, dns.TypeA, setts)
	if err != nil {
		f.logger.Error("checking host rules", "host", host, slogutil.KeyError, err)

		return &filtering.Result{}
	}

	return &resVal
}

// resetSegments returns the reset segments that must be sent to the endpoints
// of the blocked connection.
func resetSegments(p *packet) (toClient, toServer rstSegment) {
	// The endpoints accept the reset only if its sequence number is the one
	// they expect to get from the other side.
	ack := p.seq + uint32(len(p.payload))
	if p.flags&tcpFlagSYN != 0 {
		ack++
	}
	if p.flags&tcpFlagFIN != 0 {
		ack++
	}

	toClient = rstSegment{
		src: p.dst,
		dst: p.src,
		seq: p.ack,
		ack: ack,
	}

	toServer = rstSegment{
		src: p.src,
		dst: p.dst,
		seq: p.seq,
		ack: p.ack,
	}

	return toClient, toServer
}

// flowKeyOf returns the connection that b, a raw IPv4 or IPv6 packet, belongs
// to.  ok is false if b cannot be a segment of an inspected TCP connection, for
// example if it isn't a TCP packet, if it goes to a port the filter doesn't look
// at, or if its TCP header is malformed.  flowKeyOf never allocates and never
// panics, because its input comes from the network.
func (f *Filter) flowKeyOf(b []byte) (k flowKey, ok bool) {
	proto, ipHdrLen, hdrOK := upperLayer(b)
	if !hdrOK || proto != ipProtoTCP {
		return flowKey{}, false
	}

	// Only the first fragment of an IPv4 packet carries the TCP header, see
	// [Filter.isTLSHandshake].
	if b[0]>>4 == 4 && binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return flowKey{}, false
	}

	if len(b) < ipHdrLen+tcpHeaderLen {
		return flowKey{}, false
	}
	tcp := b[ipHdrLen:]
	if !f.isInspectedPort(binary.BigEndian.Uint16(tcp[2:4])) {
		return flowKey{}, false
	}

	if int(tcp[12]>>4)*4 < tcpHeaderLen {
		return flowKey{}, false
	}

	var src, dst netip.Addr
	switch b[0] >> 4 {
	case 4:
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
	case 6:
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
	default:
		return flowKey{}, false
	}

	k = flowKey{
		src: netip.AddrPortFrom(src, binary.BigEndian.Uint16(tcp[0:2])),
		dst: netip.AddrPortFrom(dst, binary.BigEndian.Uint16(tcp[2:4])),
	}

	return k, true
}

// needsInspect returns true if b, a raw IPv4 or IPv6 packet, either begins a TLS
// ClientHello or continues a connection that still has to be inspected.  It is
// the gate of the packet-processing path: it compares the first bytes of the
// packet and, at most, looks the connection up in the table, so the packets that
// cannot carry a server name are released without parsing.
func (f *Filter) needsInspect(b []byte) (ok bool) {
	// The fast path first: a new connection is only worth a look if it begins
	// a TLS ClientHello.
	if f.isTLSHandshake(b) {
		return true
	}

	key, ok := f.flowKeyOf(b)
	if !ok {
		return false
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	fl := f.flows[key]

	return fl != nil && (!fl.decided || fl.blocked)
}

// isTLSHandshake checks whether b, a raw IPv4 or IPv6 packet, may carry the
// beginning of a TLS ClientHello sent to one of the inspected ports.  It is
// the fast path that runs before the general parser: it only compares the
// bytes that are already there and never allocates, so the packets that cannot
// contain a server name are released without touching the connection table.
//
// The checks are, in order: the IP header and the IPv6 extension headers, the
// TCP protocol number, the destination port, the TCP header, and the first
// bytes of the TLS record.  b must contain the whole packet, as it comes from
// the NFQUEUE.
func (f *Filter) isTLSHandshake(b []byte) (ok bool) {
	proto, ipHdrLen, hdrOK := upperLayer(b)
	if !hdrOK || proto != ipProtoTCP {
		return false
	}

	// Only the first fragment of an IPv4 packet carries the TCP header, and
	// the rest of the packet cannot be inspected before it is reassembled.
	if b[0]>>4 == 4 && binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return false
	}

	if len(b) < ipHdrLen+tcpHeaderLen {
		return false
	}
	tcp := b[ipHdrLen:]

	if !f.isInspectedPort(binary.BigEndian.Uint16(tcp[2:4])) {
		return false
	}

	tcpHdrLen := int(tcp[12]>>4) * 4
	if tcpHdrLen < tcpHeaderLen || len(tcp) < tcpHdrLen {
		return false
	}
	payload := tcp[tcpHdrLen:]

	// A TLS record containing a ClientHello starts with the handshake record
	// type, the TLS major version, and the ClientHello handshake type.
	return len(payload) >= 6 &&
		payload[0] == tlsRecordHandshake &&
		payload[1] == tlsVersionMajor &&
		payload[5] == tlsHandshakeClientHello
}

// isInspectedPort returns true if port is one of the ports the filter looks
// at.
func (f *Filter) isInspectedPort(port uint16) (ok bool) {
	return slices.Contains(f.ports, port)
}

// parsePacket parses a raw IPv4 or IPv6 packet and returns its TCP part.  b
// must contain the whole packet.
func parsePacket(b []byte) (p *packet, err error) {
	p = &packet{}
	err = parsePacketInto(b, p)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// parsePacketInto parses a raw IPv4 or IPv6 packet into p.  b must contain the
// whole packet.  p must not be nil and is fully overwritten.
func parsePacketInto(b []byte, p *packet) (err error) {
	*p = packet{}

	if len(b) < 1 {
		return errNotIPPacket
	}

	switch b[0] >> 4 {
	case 4:
		return parseIPv4PacketInto(b, p)
	case 6:
		return parseIPv6PacketInto(b, p)
	default:
		return errNotIPPacket
	}
}

// upperLayer returns the protocol number of the upper layer of the raw IP
// packet b and the offset at which that layer starts within b.  It walks the
// IPv6 extension headers, so that the fast path and the parser judge the
// packets of the same connection the same way.
//
// The first fragment of a fragmented IPv4 packet is not distinguished from a
// regular packet, so the callers are responsible for checking the fragment
// offset of the IPv4 packets themselves.  The fragments of IPv6 packets that
// aren't the first one are not supported and make ok false, as do the
// protocols that encrypt or hide the transport layer.
//
// b must contain the whole packet.  ok is false if b is malformed, if the
// chain of the IPv6 extension headers is unreasonably long, or if the upper
// layer cannot be inspected.  upperLayer never panics, because its input comes
// from the network.
func upperLayer(b []byte) (proto uint8, off int, ok bool) {
	if len(b) < 1 {
		return 0, 0, false
	}

	switch b[0] >> 4 {
	case 4:
		if len(b) < ipv4HeaderLen {
			return 0, 0, false
		}

		ihl := int(b[0]&0x0f) * 4
		if ihl < ipv4HeaderLen || ihl > len(b) {
			return 0, 0, false
		}

		return b[9], ihl, true
	case 6:
		if len(b) < ipv6HeaderLen {
			return 0, 0, false
		}
	default:
		return 0, 0, false
	}

	proto = b[6]
	off = ipv6HeaderLen
	for n := 0; ; n++ {
		switch proto {
		case ipProtoHopByHop, ipProtoRouting, ipProtoDestOpts, ipProtoAH, ipProtoFragment:
			// Go on below.
		case ipProtoESP, ipProtoNoNextHeader, ipProtoMobility, ipProtoHIP, ipProtoShim6:
			// The transport layer is either absent or hidden, so there is
			// nothing to inspect.
			return 0, 0, false
		default:
			return proto, off, true
		}

		hdrLen, next, hdrOK := ipv6ExtHdrLen(proto, b[off:])
		if !hdrOK {
			return 0, 0, false
		}

		if n >= ipv6MaxExtHdrs {
			return 0, 0, false
		}

		proto, off = next, off+hdrLen
		if off > len(b) || off-ipv6HeaderLen > ipv6MaxExtLen {
			return 0, 0, false
		}
	}
}

// ipv6ExtHdrLen returns the length of the IPv6 extension header of the type
// proto that starts at the beginning of b and the protocol number of the
// header that follows it.  ok is false if b is too short or if the fragment
// isn't the first one, and thus doesn't contain the header of the upper layer.
func ipv6ExtHdrLen(proto uint8, b []byte) (hdrLen int, next uint8, ok bool) {
	switch proto {
	case ipProtoHopByHop, ipProtoRouting, ipProtoDestOpts:
		if len(b) < 2 {
			return 0, 0, false
		}

		return (int(b[1]) + 1) * 8, b[0], true
	case ipProtoAH:
		if len(b) < 2 {
			return 0, 0, false
		}

		return (int(b[1]) + 2) * 4, b[0], true
	case ipProtoFragment:
		if len(b) < 8 {
			return 0, 0, false
		}

		// Only the first fragment contains the header of the upper layer.
		if binary.BigEndian.Uint16(b[2:4])&0xfff8 != 0 {
			return 0, 0, false
		}

		return 8, b[0], true
	default:
		return 0, 0, false
	}
}

// parseIPv4PacketInto parses an IPv4 packet into p.
func parseIPv4PacketInto(b []byte, p *packet) (err error) {
	proto, headerLen, hdrOK := upperLayer(b)
	if !hdrOK {
		return errNotIPPacket
	}

	if proto != ipProtoTCP {
		return errNotTCPPacket
	}

	// Don't try to parse the fragments that don't contain the TCP header.
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		return errNotTCPPacket
	}

	msgLen := int(binary.BigEndian.Uint16(b[2:4]))
	if msgLen > len(b) {
		msgLen = len(b)
	}
	if headerLen > msgLen {
		return errNotIPPacket
	}

	src := netip.AddrFrom4([4]byte(b[12:16]))
	dst := netip.AddrFrom4([4]byte(b[16:20]))

	err = parseTCPPacketInto(b[headerLen:msgLen], src, dst, p)
	if err != nil {
		return err
	}

	// The more-fragments flag means that the TCP segment continues in the
	// fragments that cannot be inspected.
	p.fragmented = binary.BigEndian.Uint16(b[6:8])&0x2000 != 0

	return nil
}

// parseIPv6PacketInto parses an IPv6 packet into p.  The extension headers
// that can precede a TCP segment are skipped, see [upperLayer].
func parseIPv6PacketInto(b []byte, p *packet) (err error) {
	if len(b) < ipv6HeaderLen {
		return errNotIPPacket
	}

	proto, headerLen, hdrOK := upperLayer(b)
	if !hdrOK {
		// The packet is an IP packet, but its upper layer cannot be reached.
		return errNotTCPPacket
	}

	if proto != ipProtoTCP {
		return errNotTCPPacket
	}

	msgLen := ipv6HeaderLen + int(binary.BigEndian.Uint16(b[4:6]))
	if msgLen > len(b) {
		msgLen = len(b)
	}
	if headerLen > msgLen {
		return errNotTCPPacket
	}

	src := netip.AddrFrom16([16]byte(b[8:24]))
	dst := netip.AddrFrom16([16]byte(b[24:40]))

	return parseTCPPacketInto(b[headerLen:msgLen], src, dst, p)
}

// parseTCPPacketInto parses a TCP packet into p.
func parseTCPPacketInto(b []byte, src, dst netip.Addr, p *packet) (err error) {
	if len(b) < tcpHeaderLen {
		return errNotTCPPacket
	}

	headerLen := int(b[12]>>4) * 4
	if headerLen < tcpHeaderLen || headerLen > len(b) {
		return errNotTCPPacket
	}

	p.src = netip.AddrPortFrom(src, binary.BigEndian.Uint16(b[0:2]))
	p.dst = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(b[2:4]))
	p.seq = binary.BigEndian.Uint32(b[4:8])
	p.ack = binary.BigEndian.Uint32(b[8:12])
	p.flags = b[13]
	p.payload = b[headerLen:]

	return nil
}
