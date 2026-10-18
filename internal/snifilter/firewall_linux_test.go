//go:build linux

package snifilter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/florianl/go-nfqueue/v2"
	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// testVerdictSetter is a [verdictSetter] implementation that records the last
// verdict and returns a predefined error.
type testVerdictSetter struct {
	err     error
	calls   int
	id      uint32
	verdict int
}

// SetVerdict implements the [verdictSetter] interface for *testVerdictSetter.
func (s *testVerdictSetter) SetVerdict(id uint32, verdict int) error {
	s.calls++
	s.id = id
	s.verdict = verdict

	return s.err
}

func TestFilter_handlePacket(t *testing.T) {
	t.Parallel()

	id := uint32(42)
	payload := []byte("not a tls handshake")

	testCases := []struct {
		packetID      *uint32
		payload       *[]byte
		setterErr     error
		name          string
		wantRet       int
		wantCalls     int
		wantVerdict   int
		wantVerdictID uint32
	}{{
		name:    "missing_packet_id",
		payload: &payload,
		wantRet: 1,
	}, {
		name:          "missing_payload",
		packetID:      &id,
		wantRet:       0,
		wantCalls:     1,
		wantVerdict:   nfqueue.NfAccept,
		wantVerdictID: id,
	}, {
		name:          "set_verdict_error",
		packetID:      &id,
		payload:       &payload,
		setterErr:     errors.New("test verdict error"),
		wantRet:       1,
		wantCalls:     1,
		wantVerdict:   nfqueue.NfAccept,
		wantVerdictID: id,
	}, {
		name:          "accepted",
		packetID:      &id,
		payload:       &payload,
		wantRet:       0,
		wantCalls:     1,
		wantVerdict:   nfqueue.NfAccept,
		wantVerdictID: id,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			setter := &testVerdictSetter{err: tc.setterErr}
			f := &Filter{
				logger:   slogutil.NewDiscardLogger(),
				queueNum: 7,
			}
			attr := nfqueue.Attribute{
				PacketID: tc.packetID,
				Payload:  tc.payload,
			}

			assert.Equal(t, tc.wantRet, f.handlePacket(setter, attr))
			assert.Equal(t, tc.wantCalls, setter.calls)
			if tc.wantCalls != 0 {
				assert.Equal(t, tc.wantVerdictID, setter.id)
				assert.Equal(t, tc.wantVerdict, setter.verdict)
			}
		})
	}
}

// TestFilter_handlePacket_paused tests that a connection that hits a blocking
// rule is accepted and recorded in the query log while the protection is
// paused, and that no reset segment is sent for it.
func TestFilter_handlePacket_paused(t *testing.T) {
	t.Parallel()

	const serverName = "ads.example.com"

	hello := captureClientHello(t, serverName)
	require.NotEmpty(t, hello)

	ql := &countingQueryLog{}
	f := newTestFilter(t, ql)

	// The protection is paused while the ClientHello is inspected.
	f.SetProtectionStatus(false, nil)

	id := uint32(42)
	pkt := tcpPacket4(testReassemblySrc, testReassemblyDst, 1000, 1, tcpFlagACK, hello)
	setter := &testVerdictSetter{}

	require.Equal(t, 0, f.handlePacket(setter, nfqueue.Attribute{
		PacketID: &id,
		Payload:  &pkt,
	}))
	assert.Equal(t, 1, setter.calls)
	assert.Equal(t, id, setter.id)
	assert.Equal(t, nfqueue.NfAccept, setter.verdict)
	assert.Equal(t, 1, ql.count)
	require.NotNil(t, ql.added)
	assert.Equal(t, serverName+".", ql.added.Question.Question[0].Name)
}

func TestIsRecoverableQueueError(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		err  error
		name string
		want bool
	}{{
		name: "deadline",
		err:  &netlink.OpError{Op: "receive", Err: os.ErrDeadlineExceeded},
		want: true,
	}, {
		name: "wrapped_deadline",
		err: fmt.Errorf(
			"receiving: %w",
			&netlink.OpError{Op: "receive", Err: os.ErrDeadlineExceeded},
		),
		want: true,
	}, {
		name: "permanent",
		err:  errors.New("permanent"),
		want: false,
	}, {
		name: "netlink_permanent",
		err:  &netlink.OpError{Op: "receive", Err: errors.New("permanent")},
		want: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, isRecoverableQueueError(tc.err))
		})
	}
}

func TestWaitQueueEventStopped(t *testing.T) {
	t.Parallel()

	queueRead, queueWrite, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = queueRead.Close() }()
	defer func() { _ = queueWrite.Close() }()

	wakeFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	require.NoError(t, err)
	defer func() { _ = unix.Close(wakeFD) }()

	stoppedFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	require.NoError(t, err)
	defer func() { _ = unix.Close(stoppedFD) }()

	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	require.NoError(t, err)
	defer func() { _ = unix.Close(epfd) }()

	err = unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, wakeFD, &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(wakeFD),
	})
	require.NoError(t, err)

	signalQueueStopped(stoppedFD)

	assert.True(
		t,
		waitQueueEvent(context.Background(), epfd, int(queueRead.Fd()), wakeFD, stoppedFD),
	)
}

func TestWaitQueueEventQueueClosed(t *testing.T) {
	t.Parallel()

	queueRead, queueWrite, err := os.Pipe()
	require.NoError(t, err)
	defer func() { _ = queueRead.Close() }()

	wakeFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	require.NoError(t, err)
	defer func() { _ = unix.Close(wakeFD) }()

	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	require.NoError(t, err)
	defer func() { _ = unix.Close(epfd) }()

	err = unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, wakeFD, &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(wakeFD),
	})
	require.NoError(t, err)

	require.NoError(t, queueWrite.Close())

	assert.True(
		t,
		waitQueueEvent(context.Background(), epfd, int(queueRead.Fd()), wakeFD, -1),
	)
}
