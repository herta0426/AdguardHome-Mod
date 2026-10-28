//go:build linux

package snifilter

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
)

// errReader is an [io.Reader] that fails on the first read.
type errReader struct{}

// Read implements the [io.Reader] interface for errReader.
func (errReader) Read(_ []byte) (n int, err error) { return 0, errors.New("test error") }

func TestParseQueueStat(t *testing.T) {
	// The first line is the sample from SNI_HANDOVER.md §2.2, the second one
	// is the queue 17 that must never be confused with the queue 7.
	const (
		sample7  = "7 2076 5 2 65531 0 0 88016 1"
		sample17 = "17 2076 142 2 4096 3 1 900000 1"
	)

	testCases := []struct {
		name     string
		input    string
		want     queueStat
		queueNum uint16
		wantOK   bool
	}{{
		name:     "target line",
		input:    sample7 + "\n" + sample17 + "\n",
		want:     queueStat{total: 5, dropped: 0, userDropped: 0, idSeq: 88016},
		queueNum: 7,
		wantOK:   true,
	}, {
		name:     "second queue",
		input:    sample7 + "\n" + sample17 + "\n",
		want:     queueStat{total: 142, dropped: 3, userDropped: 1, idSeq: 900000},
		queueNum: 17,
		wantOK:   true,
	}, {
		name:     "queue 7 is not queue 17",
		input:    sample17 + "\n",
		want:     queueStat{},
		queueNum: 7,
		wantOK:   false,
	}, {
		name:     "queue number in another column",
		input:    "8 2076 5 2 7 0 0 88016 1\n",
		want:     queueStat{},
		queueNum: 7,
		wantOK:   false,
	}, {
		name:     "no such queue",
		input:    sample17 + "\n",
		want:     queueStat{},
		queueNum: 7,
		wantOK:   false,
	}, {
		name:     "empty input",
		input:    "",
		want:     queueStat{},
		queueNum: 7,
		wantOK:   false,
	}, {
		name:     "too few columns",
		input:    "7 2076 5 2 65531 0 0\n",
		want:     queueStat{},
		queueNum: 7,
		wantOK:   false,
	}, {
		name:     "malformed queue total",
		input:    "7 2076 five 2 65531 0 0 88016 1\n",
		want:     queueStat{},
		queueNum: 7,
		wantOK:   false,
	}, {
		name:     "negative queue total",
		input:    "7 2076 -1 2 65531 0 0 88016 1\n",
		want:     queueStat{},
		queueNum: 7,
		wantOK:   false,
	}, {
		name:     "malformed id sequence",
		input:    "7 2076 5 2 65531 0 0 88016x 1\n",
		want:     queueStat{},
		queueNum: 7,
		wantOK:   false,
	}, {
		name:     "malformed dropped",
		input:    "7 2076 5 2 65531 -0 0 88016 1\n",
		want:     queueStat{},
		queueNum: 7,
		wantOK:   false,
	}, {
		name:     "queue number out of range",
		input:    "70000 2076 5 2 65531 0 0 88016 1\n",
		want:     queueStat{},
		queueNum: 7,
		wantOK:   false,
	}, {
		name:     "tabs and repeated spaces",
		input:    "7\t2076   5 2 65531\t0 0   88016 1\n",
		want:     queueStat{total: 5, dropped: 0, userDropped: 0, idSeq: 88016},
		queueNum: 7,
		wantOK:   true,
	}, {
		name:     "garbage line before the target",
		input:    "not a queue line\n255\n" + sample7 + "\n",
		want:     queueStat{total: 5, dropped: 0, userDropped: 0, idSeq: 88016},
		queueNum: 7,
		wantOK:   true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			st, ok := parseQueueStat(strings.NewReader(tc.input), tc.queueNum)

			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, st)
		})
	}
}

func TestParseQueueStat_readError(t *testing.T) {
	st, ok := parseQueueStat(errReader{}, 7)

	assert.False(t, ok)
	assert.Equal(t, queueStat{}, st)
}

func TestDiffCounter(t *testing.T) {
	assert.Equal(t, uint64(10), diffCounter(110, 100))
	assert.Equal(t, uint64(0), diffCounter(100, 100))

	// The queue has been re-registered and its counters have started from
	// zero.
	assert.Equal(t, uint64(0), diffCounter(5, 100))
}

func TestQueueHealth_observe(t *testing.T) {
	var h queueHealth

	// The first sample is the baseline, so it can't be above or below
	// anything yet.
	now := time.Unix(0, 0)
	h.observe(context.Background(), slogutil.NewDiscardLogger(), 7, queueStat{
		total:   0,
		dropped: 0,
		idSeq:   100,
	}, now)

	h.observe(context.Background(), slogutil.NewDiscardLogger(), 7, queueStat{
		total:       queueBacklogThreshold,
		dropped:     0,
		userDropped: 0,
		idSeq:       200,
	}, now.Add(queueStatInterval))

	assert.Equal(t, 1, h.backlogSamples)
	assert.False(t, h.backlogLogged)
	assert.False(t, h.dropsLogged)

	// The third sample of the backed-up queue reaches the reporting
	// threshold and must be reported once.
	h.observe(context.Background(), slogutil.NewDiscardLogger(), 7, queueStat{
		total:       queueBacklogThreshold + 1,
		dropped:     2,
		userDropped: 0,
		idSeq:       300,
	}, now.Add(2*queueStatInterval))

	assert.Equal(t, 2, h.backlogSamples)
	assert.False(t, h.backlogLogged)
	assert.True(t, h.dropsLogged)

	h.observe(context.Background(), slogutil.NewDiscardLogger(), 7, queueStat{
		total:       queueBacklogThreshold + 1,
		dropped:     3,
		userDropped: 0,
		idSeq:       400,
	}, now.Add(3*queueStatInterval))

	assert.Equal(t, 3, h.backlogSamples)
	assert.True(t, h.backlogLogged)
	assert.True(t, h.dropsLogged)

	// The queue recovers, so the next episode must be reported again.
	h.observe(context.Background(), slogutil.NewDiscardLogger(), 7, queueStat{
		total:       0,
		dropped:     3,
		userDropped: 0,
		idSeq:       500,
	}, now.Add(4*queueStatInterval))

	assert.Equal(t, 0, h.backlogSamples)
	assert.False(t, h.backlogLogged)
	assert.False(t, h.dropsLogged)
}
