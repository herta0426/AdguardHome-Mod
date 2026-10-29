package home

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordState is the part of [recordingHandler] that is shared between a handler
// and the ones derived from it, so that a test can inspect the records a derived
// handler has received.
type recordState struct {
	// records are the records the handler and its derivatives have received.
	records []slog.Record
}

// recordingHandler is a [slog.Handler] that stores the records it receives, the
// attributes and groups added to it, and that returns err from
// [recordingHandler.Handle].
type recordingHandler struct {
	// state is the shared list of the received records.
	state *recordState

	// attrs are the attributes added with [recordingHandler.WithAttrs].
	attrs []slog.Attr

	// groups are the groups added with [recordingHandler.WithGroup].
	groups []string

	// level is the minimum level the handler is enabled for.
	level slog.Level

	// err is returned by [recordingHandler.Handle].
	err error
}

// type check
var _ slog.Handler = (*recordingHandler)(nil)

// newRecordingHandler returns a new recording handler enabled for lvl and above.
func newRecordingHandler(lvl slog.Level) (h *recordingHandler) {
	return &recordingHandler{
		state: &recordState{},
		level: lvl,
	}
}

// Enabled implements the [slog.Handler] interface for *recordingHandler.
func (h *recordingHandler) Enabled(_ context.Context, lvl slog.Level) (ok bool) {
	return lvl >= h.level
}

// Handle implements the [slog.Handler] interface for *recordingHandler.
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) (err error) {
	h.state.records = append(h.state.records, r)

	return h.err
}

// WithAttrs implements the [slog.Handler] interface for *recordingHandler.
func (h *recordingHandler) WithAttrs(attrs []slog.Attr) (d slog.Handler) {
	clone := *h
	clone.attrs = append(clone.attrs, attrs...)

	return &clone
}

// WithGroup implements the [slog.Handler] interface for *recordingHandler.
func (h *recordingHandler) WithGroup(name string) (d slog.Handler) {
	clone := *h
	clone.groups = append(clone.groups, name)

	return &clone
}

// newTestRecord returns a record with the given level and message.
func newTestRecord(lvl slog.Level, msg string) (r slog.Record) {
	return slog.NewRecord(time.Now(), lvl, msg, 0)
}

func TestFanoutHandler(t *testing.T) {
	t.Parallel()

	t.Run("enabled", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		strict := newRecordingHandler(slog.LevelError)
		loose := newRecordingHandler(slog.LevelDebug)

		both := newFanoutHandler(strict, loose)
		assert.True(t, both.Enabled(ctx, slog.LevelInfo))
		assert.True(t, both.Enabled(ctx, slog.LevelError))

		onlyStrict := newFanoutHandler(strict, newRecordingHandler(slog.LevelError))
		assert.False(t, onlyStrict.Enabled(ctx, slog.LevelInfo))
		assert.True(t, onlyStrict.Enabled(ctx, slog.LevelError))
	})

	t.Run("handle_both", func(t *testing.T) {
		t.Parallel()

		first := newRecordingHandler(slog.LevelDebug)
		second := newRecordingHandler(slog.LevelWarn)
		l := slog.New(newFanoutHandler(first, second))

		l.Warn("message", "key", "value")

		require.Len(t, first.state.records, 1)
		require.Len(t, second.state.records, 1)
		assert.Equal(t, "message", first.state.records[0].Message)
		assert.Equal(t, slog.LevelWarn, second.state.records[0].Level)

		// The child below its level must not receive anything.
		l.Info("another message")
		assert.Len(t, first.state.records, 2)
		assert.Len(t, second.state.records, 1)
	})

	t.Run("errors_ignored", func(t *testing.T) {
		t.Parallel()

		failing := newRecordingHandler(slog.LevelDebug)
		failing.err = errors.New("disk is full")
		working := newRecordingHandler(slog.LevelDebug)

		h := newFanoutHandler(failing, working)
		require.NoError(t, h.Handle(t.Context(), newTestRecord(slog.LevelError, "message")))
		require.Len(t, working.state.records, 1)
	})

	t.Run("with_attrs", func(t *testing.T) {
		t.Parallel()

		first := newRecordingHandler(slog.LevelDebug)
		second := newRecordingHandler(slog.LevelDebug)
		grouped := slog.New(newFanoutHandler(first, second)).With("key", "value")
		require.NotNil(t, grouped)

		h, ok := grouped.Handler().(*fanoutHandler)
		require.True(t, ok)
		require.Len(t, h.handlers, 2)

		for i, child := range h.handlers {
			rec, isRec := child.(*recordingHandler)
			require.True(t, isRec, "child %d", i)
			require.Len(t, rec.attrs, 1, "child %d", i)
			assert.Equal(t, "key", rec.attrs[0].Key, "child %d", i)
			assert.Equal(t, "value", rec.attrs[0].Value.String(), "child %d", i)
		}

		grouped.Info("message")

		// The children share the state, so both have received the record.
		require.Len(t, first.state.records, 1)
		require.Len(t, second.state.records, 1)
	})

	t.Run("with_group", func(t *testing.T) {
		t.Parallel()

		first := newRecordingHandler(slog.LevelDebug)
		second := newRecordingHandler(slog.LevelDebug)
		grouped := slog.New(newFanoutHandler(first, second)).WithGroup("group")

		grouped.Info("message")

		h, ok := grouped.Handler().(*fanoutHandler)
		require.True(t, ok)
		require.Len(t, h.handlers, 2)

		for i, child := range h.handlers {
			rec, isRec := child.(*recordingHandler)
			require.True(t, isRec, "child %d", i)
			assert.Equal(t, []string{"group"}, rec.groups, "child %d", i)
		}

		require.Len(t, first.state.records, 1)
		require.Len(t, second.state.records, 1)
	})
}
