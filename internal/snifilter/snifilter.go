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

	// maxFlows is the maximum number of connections tracked at the same time.
	maxFlows = 1 << 14

	// flowTTL is the time during which the state of a connection is kept
	// after the last packet of it was inspected.
	flowTTL = 1 * time.Minute
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

	// seen is the time when the last packet of the connection was inspected.
	seen time.Time

	// decided is true if the verdict for the connection is already known.
	decided bool

	// blocked is true if the connection must be dropped.
	blocked bool
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
	clear(f.flows)
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
		fl = &flow{}
		f.evictLocked(now)
		f.flows[key] = fl
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

	if len(p.payload) > 0 && len(fl.handshake) < maxHandshakeSize {
		fl.handshake = append(fl.handshake, p.payload...)
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
		// Wait for the next packet of the connection.
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
		fl.handshake = nil
	}
	f.mu.Unlock()
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

// evictLocked removes the outdated connections.  f.mu must be locked.
func (f *Filter) evictLocked(now time.Time) {
	if len(f.flows) < maxFlows {
		return
	}

	f.expireLocked(now)

	if len(f.flows) < maxFlows {
		return
	}

	// This should never happen unless something is very wrong with the
	// accounting of the packets, but the memory usage must stay bounded.
	f.logger.Warn("too many tracked connections, resetting the state")
	clear(f.flows)
}

// expireFlows removes the state of the connections that are not active
// anymore.
func (f *Filter) expireFlows() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.expireLocked(time.Now())
}

// expireLocked removes the outdated connections.  f.mu must be locked.
func (f *Filter) expireLocked(now time.Time) {
	for k, fl := range f.flows {
		if now.Sub(fl.seen) > flowTTL {
			delete(f.flows, k)
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

// isTLSHandshake checks whether b, a raw IPv4 or IPv6 packet, may carry the
// beginning of a TLS ClientHello sent to one of the inspected ports.  It is
// the fast path that runs before the general parser: it only compares the
// bytes that are already there and never allocates, so the packets that cannot
// contain a server name are released without touching the connection table.
//
// The checks are, in order: the IP header, the TCP protocol number, the
// destination port, the TCP header, and the first bytes of the TLS record.
// b must contain the whole packet, as it comes from the NFQUEUE.
func (f *Filter) isTLSHandshake(b []byte) (ok bool) {
	if len(b) < 1 {
		return false
	}

	var ipHdrLen int
	switch b[0] >> 4 {
	case 4:
		if len(b) < ipv4HeaderLen || b[9] != ipProtoTCP {
			return false
		}

		// Only the first fragment carries the TCP header, and the rest of the
		// packet cannot be inspected before it is reassembled.
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return false
		}

		ipHdrLen = int(b[0]&0x0f) * 4
		if ipHdrLen < ipv4HeaderLen {
			return false
		}
	case 6:
		if len(b) < ipv6HeaderLen || b[6] != ipProtoTCP {
			return false
		}

		ipHdrLen = ipv6HeaderLen
	default:
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

// parseIPv4PacketInto parses an IPv4 packet into p.
func parseIPv4PacketInto(b []byte, p *packet) (err error) {
	if len(b) < ipv4HeaderLen {
		return errNotIPPacket
	}

	if b[9] != ipProtoTCP {
		return errNotTCPPacket
	}

	// Don't try to parse the fragments that don't contain the TCP header.
	fragOffset := binary.BigEndian.Uint16(b[6:8]) & 0x1fff
	if fragOffset != 0 {
		return errNotTCPPacket
	}

	headerLen := int(b[0]&0x0f) * 4
	if headerLen < ipv4HeaderLen || headerLen > len(b) {
		return errNotIPPacket
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

	return parseTCPPacketInto(b[headerLen:msgLen], src, dst, p)
}

// parseIPv6PacketInto parses an IPv6 packet into p.  The packets with
// extension headers are not parsed and are considered not TCP.
func parseIPv6PacketInto(b []byte, p *packet) (err error) {
	if len(b) < ipv6HeaderLen {
		return errNotIPPacket
	}

	if b[6] != ipProtoTCP {
		return errNotTCPPacket
	}

	msgLen := ipv6HeaderLen + int(binary.BigEndian.Uint16(b[4:6]))
	if msgLen > len(b) {
		msgLen = len(b)
	}

	src := netip.AddrFrom16([16]byte(b[8:24]))
	dst := netip.AddrFrom16([16]byte(b[24:40]))

	return parseTCPPacketInto(b[ipv6HeaderLen:msgLen], src, dst, p)
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
