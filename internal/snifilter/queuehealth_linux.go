//go:build linux

package snifilter

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

const (
	// queueStatInterval is the interval at which the state of the queue is
	// read from [queueStatPath].
	queueStatInterval = 10 * time.Second

	// queueStatPath is the file the kernel exposes the state of the netfilter
	// queues in.  See the description of the columns in SNI_HANDOVER.md §2.2.
	queueStatPath = "/proc/net/netfilter/nfnetlink_queue"

	// queueStatFields is the number of the columns of a line of
	// [queueStatPath] that are needed by [parseQueueStat].
	queueStatFields = 8

	// queueBacklogThreshold is the number of the packets waiting for the
	// verdict above which the queue is considered backed up: three quarters of
	// [maxQueueLen].  A short burst near the limit is normal, see
	// SNI_HANDOVER.md §2.2.
	queueBacklogThreshold int64 = maxQueueLen * 3 / 4

	// queueBacklogSamples is the number of the consecutive samples above
	// [queueBacklogThreshold] after which the queue is reported.  With
	// [queueStatInterval] it is about thirty seconds, which filters out the
	// bursts and still catches a stuck receiver.
	queueBacklogSamples = 3
)

// queueStat is the state of a single netfilter queue.  The column numbers refer
// to [queueStatPath], see SNI_HANDOVER.md §2.2.
type queueStat struct {
	// total is the third column, the number of the packets waiting for the
	// verdict, queue_total.
	total int64

	// dropped is the sixth column, the number of the packets the kernel has
	// dropped, for example because the queue was full.
	dropped uint64

	// userDropped is the seventh column, the number of the packets that could
	// not be delivered to this process.
	userDropped uint64

	// idSeq is the eighth column, the cumulative number of the packets the
	// kernel has enqueued.
	idSeq uint64
}

// parseQueueStat reads r and returns the state of the queue queueNum.  ok is
// false if r has no line for that queue, if the line is malformed, or if r
// can't be read.  It is a pure function, so the tests and the callers may use
// any reader.
func parseQueueStat(r io.Reader, queueNum uint16) (st queueStat, ok bool) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < queueStatFields {
			continue
		}

		// The first column is the only one that holds the queue number, so
		// the number is compared numerically and never as a prefix.  This
		// keeps the queues 7 and 17 apart, as well as a queue number that
		// happens to appear in another column.
		num, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil || uint16(num) != queueNum {
			continue
		}

		return parseQueueStatFields(fields)
	}

	return queueStat{}, false
}

// parseQueueStatFields parses the columns of a line of [queueStatPath] whose
// first column is already known to be the queue number of the caller.
func parseQueueStatFields(fields []string) (st queueStat, ok bool) {
	total, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || total < 0 {
		return queueStat{}, false
	}

	dropped, err := strconv.ParseUint(fields[5], 10, 64)
	if err != nil {
		return queueStat{}, false
	}

	userDropped, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return queueStat{}, false
	}

	idSeq, err := strconv.ParseUint(fields[7], 10, 64)
	if err != nil {
		return queueStat{}, false
	}

	return queueStat{
		total:       total,
		dropped:     dropped,
		userDropped: userDropped,
		idSeq:       idSeq,
	}, true
}

// queueHealth is the state of the queue watcher.  It is not safe for concurrent
// use, since only the watcher goroutine owns it.
type queueHealth struct {
	// prev is the state read at lastSample.
	prev queueStat

	// lastSample is the time when prev was read.
	lastSample time.Time

	// backlogSamples is the number of the consecutive samples at or above
	// [queueBacklogThreshold].
	backlogSamples int

	// backlogLogged is true if the backed-up queue has already been reported
	// and hasn't recovered since.
	backlogLogged bool

	// dropsLogged is true if the growing drop counters have already been
	// reported and haven't stopped growing since.
	dropsLogged bool

	// havePrev is true if prev is set.
	havePrev bool

	// readFailed is true if the state was unavailable on the previous sample.
	readFailed bool
}

// watchQueueHealth reads the state of the queue every [queueStatInterval] and
// reports the backed-up queue as well as the growing drop counters.  It exits
// when ctx is canceled, so it must be started with f.wg incremented.
//
// The watcher is read-only on purpose: it never re-registers, rebinds, or kills
// the queue, since rebuilding a queue that hasn't been unbound yet is what
// breaks the recovery, see SNI_HANDOVER.md §8.4.
func (f *Filter) watchQueueHealth(ctx context.Context) {
	defer f.wg.Done()

	ticker := time.NewTicker(queueStatInterval)
	defer ticker.Stop()

	state := &queueHealth{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		st, ok := f.readQueueStat(ctx, state)
		if !ok {
			continue
		}

		state.observe(ctx, f.logger, f.queueNum, st, time.Now())
	}
}

// readQueueStat returns the current state of the queue of f.  ok is false if the
// state is unavailable, which is not an error: [queueStatPath] doesn't exist in
// most containers and the queue may be temporarily unbound.  The failure is
// logged once per episode and only at the debug level, so that a missing procfs
// never floods the log nor stops the filter.
func (f *Filter) readQueueStat(ctx context.Context, state *queueHealth) (st queueStat, ok bool) {
	file, err := os.Open(queueStatPath)
	if err != nil {
		if !state.readFailed {
			state.readFailed = true

			f.logger.DebugContext(
				ctx,
				"reading the queue state; not reporting it",
				"path",
				queueStatPath,
				slogutil.KeyError,
				err,
			)
		}

		return queueStat{}, false
	}

	defer func() { _ = file.Close() }()

	st, ok = parseQueueStat(file, f.queueNum)
	if !ok {
		if !state.readFailed {
			state.readFailed = true

			f.logger.DebugContext(
				ctx,
				"no state for the queue; not reporting it",
				"path",
				queueStatPath,
				"queue_num",
				f.queueNum,
			)
		}

		return queueStat{}, false
	}

	state.readFailed = false

	return st, true
}

// observe handles a single sample of the state of the queue.  The regular
// sample goes to the debug log once, while the problems are reported at the
// warning level once per episode, so that a problem that lasts for hours is
// reported once and doesn't flood the log.
func (h *queueHealth) observe(
	ctx context.Context,
	logger *slog.Logger,
	queueNum uint16,
	st queueStat,
	now time.Time,
) {
	hasPrev := h.havePrev
	prev := h.prev
	elapsed := now.Sub(h.lastSample)

	h.prev = st
	h.lastSample = now
	h.havePrev = true

	// A re-registered queue starts its counters from zero, so a smaller value
	// than the previous one is a new queue rather than an anomaly.
	var idDelta, droppedDelta, userDroppedDelta uint64
	if hasPrev && elapsed > 0 {
		idDelta = diffCounter(st.idSeq, prev.idSeq)
		droppedDelta = diffCounter(st.dropped, prev.dropped)
		userDroppedDelta = diffCounter(st.userDropped, prev.userDropped)
	}

	var idRate float64
	if elapsed > 0 {
		idRate = float64(idDelta) / elapsed.Seconds()
	}

	if st.total < queueBacklogThreshold {
		h.backlogSamples = 0
		h.backlogLogged = false
	} else {
		h.backlogSamples++
	}

	if droppedDelta == 0 && userDroppedDelta == 0 {
		h.dropsLogged = false
	}

	// The regular sample.  It's only visible with the debug logging turned
	// on, which is what the verbose mode of AdGuard Home does.
	logger.DebugContext(
		ctx,
		"nfqueue state",
		"queue_num",
		queueNum,
		"queue_total",
		st.total,
		"queue_threshold",
		queueBacklogThreshold,
		"id_seq",
		st.idSeq,
		"id_seq_delta",
		idDelta,
		"dropped",
		st.dropped,
		"user_dropped",
		st.userDropped,
	)

	if h.backlogSamples >= queueBacklogSamples && !h.backlogLogged {
		h.backlogLogged = true

		logger.WarnContext(
			ctx,
			"the nfqueue is backed up; the packets wait for the verdict for "+
				"too long",
			"queue_num",
			queueNum,
			"queue_total",
			st.total,
			"queue_threshold",
			queueBacklogThreshold,
			"samples",
			h.backlogSamples,
			"id_seq",
			st.idSeq,
			"id_seq_per_sec",
			idRate,
			"dropped_delta",
			droppedDelta,
			"user_dropped_delta",
			userDroppedDelta,
		)
	}

	if (droppedDelta > 0 || userDroppedDelta > 0) && !h.dropsLogged {
		h.dropsLogged = true

		logger.WarnContext(
			ctx,
			"the nfqueue is dropping the packets",
			"queue_num",
			queueNum,
			"queue_total",
			st.total,
			"dropped",
			st.dropped,
			"dropped_delta",
			droppedDelta,
			"user_dropped",
			st.userDropped,
			"user_dropped_delta",
			userDroppedDelta,
			"id_seq",
			st.idSeq,
		)
	}
}

// diffCounter returns the increment of the cumulative counter cur over prev.  It
// returns zero if cur is smaller than prev, which means that the counter has been
// reset along with the queue.
func diffCounter(cur, prev uint64) uint64 {
	if cur < prev {
		return 0
	}

	return cur - prev
}
