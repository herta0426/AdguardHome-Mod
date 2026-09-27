//go:build linux

package snifilter

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
)

const (
	// chainName is the name of the netfilter chain the rules that send the
	// packets to the queue are expected to be in.  AdGuard Home doesn't
	// install these rules itself, see the sni_filter documentation.
	chainName = "AGH_SNI"

	// maxQueueLen is the maximum number of packets waiting for the verdict.
	// The rest of the packets are passed through by the kernel, see the
	// queue-bypass option of the rules.
	maxQueueLen = 1024

	// queueReadTimeout is the time the queue waits for the packets.
	queueReadTimeout = 100 * time.Millisecond

	// queueWriteTimeout is the time the queue waits to hand the packet over
	// to the kernel.
	queueWriteTimeout = 20 * time.Millisecond

	// flowsCheckInterval is the interval at which the state of the
	// connections that are not active anymore is removed.
	flowsCheckInterval = 30 * time.Second
)

// platform is the Linux-specific state of the SNI filter.
type platform struct {
	// nf is the connection to the netfilter queue subsystem.
	nf *nfqueue.Nfqueue

	// raw4 is the raw socket used to inject the IPv4 reset segments.  It's
	// negative if the socket is not available.
	raw4 int

	// raw6 is the raw socket used to inject the IPv6 reset segments.  It's
	// negative if the socket is not available.
	raw6 int
}

// startFirewall opens the packet queue and the sockets used to reset the
// blocked connections.  The netfilter rules that send the packets to the queue
// are installed and removed by the operator, for example by a Magisk module
// script, so AdGuard Home doesn't touch iptables at all.  ctx must be canceled
// when the filter is shut down.
func (f *Filter) startFirewall(ctx context.Context) (err error) {
	f.openRawSockets()

	err = f.openQueue(ctx)
	if err != nil {
		f.closeRawSockets()

		return fmt.Errorf("opening the queue: %w", err)
	}

	f.wg.Add(1)
	go f.watchFlows(ctx)

	// The ports, the UIDs, and the drop_quic setting are only used to build
	// the rules, so they don't affect AdGuard Home anymore.
	f.logger.InfoContext(
		ctx,
		"waiting for the packets; the netfilter rules are installed by the "+
			"operator",
		"chain", chainName,
		"queue_num", f.queueNum,
	)

	f.checkReversePathFilter(ctx)

	return nil
}

// stopFirewall closes the packet queue and the raw sockets.  The netfilter
// rules aren't touched, since they are installed by the operator.
func (f *Filter) stopFirewall(_ context.Context) {
	f.closeQueue()
	f.closeRawSockets()
}

// watchFlows removes the state of the connections that are not active anymore.
func (f *Filter) watchFlows(ctx context.Context) {
	defer f.wg.Done()

	ticker := time.NewTicker(flowsCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.expireFlows()
		}
	}
}

// checkReversePathFilter warns if the kernel is likely to drop the injected
// reset segments, since the blocked connections would then hang instead of
// failing fast.  See the rp_filter description in
// https://docs.kernel.org/networking/ip-sysctl.html.
func (f *Filter) checkReversePathFilter(ctx context.Context) {
	// The effective mode is the strictest of the per-interface and the "all"
	// values.
	for _, name := range []string{"all", "lo"} {
		path := "/proc/sys/net/ipv4/conf/" + name + "/rp_filter"

		data, err := os.ReadFile(path)
		if err != nil {
			f.logger.DebugContext(ctx, "reading rp_filter", "path", path, slogutil.KeyError, err)

			continue
		}

		if strings.TrimSpace(string(data)) != "1" {
			continue
		}

		f.logger.WarnContext(
			ctx,
			"ipv4 reverse path filtering is strict, so the resets for the "+
				"blocked connections may not reach the clients and those "+
				"connections will hang instead of failing fast",
			"path",
			path,
		)
	}
}

// openQueue opens the netfilter queue and starts processing the packets.  ctx
// must be canceled to stop the processing.
func (f *Filter) openQueue(ctx context.Context) (err error) {
	conf := &nfqueue.Config{
		NfQueue:      f.queueNum,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  maxQueueLen,
		Copymode:     nfqueue.NfQnlCopyPacket,
		// The family of the queue is not used by the kernel to route the
		// packets anymore, so the packets of both IPv4 and IPv6 arrive into
		// the same queue.
		AfFamily:     unix.AF_UNSPEC,
		ReadTimeout:  queueReadTimeout,
		WriteTimeout: queueWriteTimeout,
	}

	f.nf, err = nfqueue.Open(conf)
	if err != nil {
		return err
	}

	err = f.nf.Register(ctx, f.handlePacket)
	if err != nil {
		f.closeQueue()

		return err
	}

	return nil
}

// closeQueue closes the netfilter queue.
func (f *Filter) closeQueue() {
	if f.nf == nil {
		return
	}

	err := f.nf.Close()
	if err != nil {
		f.logger.Debug("closing the queue", slogutil.KeyError, err)
	}

	f.nf = nil
}

// handlePacket processes a packet received from the kernel and reports the
// verdict for it.
func (f *Filter) handlePacket(a nfqueue.Attribute) (ret int) {
	if a.PacketID == nil || a.Payload == nil {
		return 0
	}

	verdict := nfqueue.NfAccept

	p, err := parsePacket(*a.Payload)
	if err == nil {
		res := f.inspect(p)
		switch res.verdict {
		case verdictDrop:
			verdict = nfqueue.NfDrop
		case verdictReset:
			f.sendReset(&res.toClient)
			f.sendReset(&res.toServer)

			verdict = nfqueue.NfDrop
		default:
			// Pass the packet through.
		}
	}

	err = f.nf.SetVerdict(*a.PacketID, verdict)
	if err != nil {
		f.logger.Debug("setting the verdict", "id", *a.PacketID, slogutil.KeyError, err)
	}

	return 0
}

// openRawSockets opens the sockets used to inject the reset segments.  The
// errors are logged, since the filter can still block the connections by
// dropping the packets.
func (f *Filter) openRawSockets() {
	f.raw4, f.raw6 = -1, -1

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		f.logger.Warn(
			"opening the ipv4 raw socket; blocked connections will hang instead of being reset",
			slogutil.KeyError,
			err,
		)
	} else {
		f.raw4 = sock
	}

	sock, err = unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		f.logger.Warn(
			"opening the ipv6 raw socket; blocked connections will hang instead of being reset",
			slogutil.KeyError,
			err,
		)
	} else {
		f.raw6 = sock
	}
}

// closeRawSockets closes the sockets used to inject the reset segments.
func (f *Filter) closeRawSockets() {
	for _, sock := range []*int{&f.raw4, &f.raw6} {
		if *sock < 0 {
			continue
		}

		err := unix.Close(*sock)
		if err != nil {
			f.logger.Debug("closing the raw socket", slogutil.KeyError, err)
		}

		*sock = -1
	}
}

// sendReset injects the reset segment into the network stack.  The errors are
// only logged, since the packet processing must not be interrupted by them.
func (f *Filter) sendReset(seg *rstSegment) {
	addr := seg.dst.Addr()

	// A zoned address requires the interface to be resolved, which the raw
	// sockets don't do.
	if addr.Zone() != "" {
		f.logger.Debug("not sending a reset to a zoned address", "dst", seg.dst.String())

		return
	}

	var err error
	switch {
	case addr.Is4():
		if f.raw4 < 0 {
			f.logger.Debug("not sending a reset: no ipv4 raw socket")

			return
		}

		err = unix.Sendto(f.raw4, buildReset4(seg), 0, &unix.SockaddrInet4{Addr: addr.As4()})
	case addr.Is6():
		if f.raw6 < 0 {
			f.logger.Debug("not sending a reset: no ipv6 raw socket")

			return
		}

		err = unix.Sendto(f.raw6, buildReset6(seg), 0, &unix.SockaddrInet6{Addr: addr.As16()})
	default:
		// Can't happen, since an address is either IPv4 or IPv6.
		return
	}

	if err != nil {
		f.logger.Debug("sending the reset segment", "dst", seg.dst.String(), slogutil.KeyError, err)
	}
}

// buildReset4 returns an IPv4 packet with a TCP reset segment.
func buildReset4(seg *rstSegment) (pkt []byte) {
	src := seg.src.Addr().As4()
	dst := seg.dst.Addr().As4()

	pkt = make([]byte, 0, ipv4HeaderLen+tcpHeaderLen)
	pkt = appendIPv4Header(pkt, src[:], dst[:], tcpHeaderLen)

	return appendTCPHeader(pkt, seg, src[:], dst[:], false)
}

// buildReset6 returns an IPv6 packet with a TCP reset segment.
func buildReset6(seg *rstSegment) (pkt []byte) {
	src := seg.src.Addr().As16()
	dst := seg.dst.Addr().As16()

	pkt = make([]byte, 0, ipv6HeaderLen+tcpHeaderLen)
	pkt = appendIPv6Header(pkt, src[:], dst[:], tcpHeaderLen)

	return appendTCPHeader(pkt, seg, src[:], dst[:], true)
}

// appendIPv4Header appends an IPv4 header of a TCP segment of payloadLen
// bytes to b and returns the result.
func appendIPv4Header(b, src, dst []byte, payloadLen int) []byte {
	// Version, IHL, DSCP, and ECN.
	b = append(b, 0x45, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(ipv4HeaderLen+payloadLen))
	// Identification.
	b = binary.BigEndian.AppendUint16(b, 0)
	// The don't-fragment flag.
	b = binary.BigEndian.AppendUint16(b, 0x4000)
	// TTL and the protocol.
	b = append(b, 64, unix.IPPROTO_TCP)
	// The header checksum, which is filled in below.
	b = binary.BigEndian.AppendUint16(b, 0)
	b = append(b, src...)
	b = append(b, dst...)

	header := b[len(b)-ipv4HeaderLen:]
	cs := newChecksummer()
	cs.add(header)
	binary.BigEndian.PutUint16(header[10:12], cs.value())

	return b
}

// appendIPv6Header appends an IPv6 header of a TCP segment of payloadLen bytes
// to b and returns the result.
func appendIPv6Header(b, src, dst []byte, payloadLen int) []byte {
	// Version, traffic class, and flow label.
	b = append(b, 0x60, 0, 0, 0)
	// The payload length.
	b = binary.BigEndian.AppendUint16(b, uint16(payloadLen))
	// The next header and the hop limit.
	b = append(b, unix.IPPROTO_TCP, 64)
	b = append(b, src...)
	b = append(b, dst...)

	return b
}

// appendTCPHeader appends a TCP header with the reset flag to b and returns
// the result with the checksum filled in.
func appendTCPHeader(b []byte, seg *rstSegment, src, dst []byte, ipv6 bool) []byte {
	b = binary.BigEndian.AppendUint16(b, seg.src.Port())
	b = binary.BigEndian.AppendUint16(b, seg.dst.Port())
	b = binary.BigEndian.AppendUint32(b, seg.seq)
	b = binary.BigEndian.AppendUint32(b, seg.ack)
	// The data offset and the flags.
	b = append(b, tcpHeaderLen/4<<4, tcpFlagRST|tcpFlagACK)
	// The window, the checksum, and the urgent pointer.
	b = append(b, 0, 0, 0, 0, 0, 0)

	header := b[len(b)-tcpHeaderLen:]
	cs := newChecksummer()
	cs.add(src)
	cs.add(dst)
	if ipv6 {
		// The upper-layer packet length, see RFC 8200.
		cs.add([]byte{0, 0, 0, uint8(tcpHeaderLen)})
		cs.add([]byte{0, 0, 0, unix.IPPROTO_TCP})
	} else {
		// The zero field and the protocol, see RFC 793.
		cs.add([]byte{0, unix.IPPROTO_TCP})
		cs.add([]byte{0, uint8(tcpHeaderLen)})
	}
	cs.add(header)

	binary.BigEndian.PutUint16(header[16:18], cs.value())

	return b
}

// checksummer accumulates the one's complement sum of bytes.
type checksummer struct {
	sum uint32
}

// newChecksummer returns a new checksummer.
func newChecksummer() (cs *checksummer) {
	return &checksummer{}
}

// add adds the bytes of b to the sum.
func (cs *checksummer) add(b []byte) {
	for len(b) >= 2 {
		cs.sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}

	if len(b) > 0 {
		cs.sum += uint32(b[0]) << 8
	}
}

// value returns the one's complement checksum.
func (cs *checksummer) value() (sum uint16) {
	for cs.sum > 0xffff {
		cs.sum = (cs.sum & 0xffff) + (cs.sum >> 16)
	}

	return ^uint16(cs.sum)
}
