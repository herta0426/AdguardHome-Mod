package home

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestRingLogger returns a logger that stores its records in a new breadcrumb
// ring as well as that ring.
func newTestRingLogger(lvl slog.Level) (l *slog.Logger, b *breadcrumbRing) {
	b = newBreadcrumbRing()

	return slog.New(newRingHandler(b, &slog.HandlerOptions{Level: lvl})), b
}

// dumpRing returns the breadcrumbs of b, without the section delimiters that
// [writeBreadcrumbs] adds.
func dumpRing(t *testing.T, b *breadcrumbRing) (s string) {
	t.Helper()

	buf := &bytes.Buffer{}
	b.writeTo(buf)

	return buf.String()
}

func TestBreadcrumbRing(t *testing.T) {
	t.Parallel()

	t.Run("records", func(t *testing.T) {
		t.Parallel()

		l, b := newTestRingLogger(slog.LevelInfo)
		l.Info("first")
		l.Warn("second", "key", "value")

		lines := strings.Split(strings.TrimSuffix(dumpRing(t, b), "\n"), "\n")
		require.Len(t, lines, 2)
		assert.Contains(t, lines[0], "msg=first")
		assert.Contains(t, lines[1], "msg=second")
		assert.Contains(t, lines[1], "key=value")
	})

	t.Run("level", func(t *testing.T) {
		t.Parallel()

		l, b := newTestRingLogger(slog.LevelWarn)
		l.Info("dropped by the level")
		l.Warn("kept")

		s := dumpRing(t, b)
		assert.NotContains(t, s, "dropped by the level")
		assert.Contains(t, s, "kept")
	})

	t.Run("overflow", func(t *testing.T) {
		t.Parallel()

		l, b := newTestRingLogger(slog.LevelInfo)
		l.Info("the oldest marker")

		// About 100 KB, well over the size of the ring.
		msg := strings.Repeat("x", 100)
		for i := range 1000 {
			l.Info(msg, "n", i)
		}
		l.Info("the newest marker")

		s := dumpRing(t, b)
		assert.LessOrEqual(t, len(s), breadcrumbsSize)
		assert.Contains(t, s, "the newest marker")
		assert.NotContains(t, s, "the oldest marker")

		// The oldest retained bytes must still be the beginning of a whole line.
		head := s[:min(40, len(s))]
		assert.True(t, strings.HasPrefix(s, "time="), "unexpected head %q", head)
	})

	t.Run("truncated", func(t *testing.T) {
		t.Parallel()

		l, b := newTestRingLogger(slog.LevelInfo)
		l.Info(strings.Repeat("y", 4*breadcrumbMaxLen))

		s := dumpRing(t, b)
		assert.LessOrEqual(t, len(s), breadcrumbMaxLen)
		assert.Contains(t, s, breadcrumbTruncatedMark)
		assert.True(t, strings.HasSuffix(s, "\n"))
		assert.True(t, utf8.ValidString(s))
	})

	t.Run("with_attrs", func(t *testing.T) {
		t.Parallel()

		l, b := newTestRingLogger(slog.LevelInfo)
		l.With("component", "test").Info("with attributes")

		assert.Contains(t, dumpRing(t, b), "component=test")
	})

	t.Run("busy_lock", func(t *testing.T) {
		t.Parallel()

		l, b := newTestRingLogger(slog.LevelInfo)

		// Simulate another goroutine formatting a record.
		b.mu.Lock()
		l.Info("dropped, the ring is busy")
		b.mu.Unlock()

		assert.EqualValues(t, 1, b.dropped.Load())
		assert.Equal(t, "no breadcrumbs recorded\n", dumpRing(t, b))

		l.Info("kept")
		assert.Contains(t, dumpRing(t, b), "kept")
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, "no breadcrumbs recorded\n", dumpRing(t, newBreadcrumbRing()))
	})
}

func TestWriteBreadcrumbs(t *testing.T) {
	prev := breadcrumbs
	t.Cleanup(func() { breadcrumbs = prev })

	buf := &bytes.Buffer{}

	breadcrumbs = nil
	writeBreadcrumbs(buf)
	assert.Contains(t, buf.String(), "=== breadcrumbs ===\nnot collected")

	breadcrumbs = newBreadcrumbRing()
	buf.Reset()
	writeBreadcrumbs(buf)
	assert.Contains(t, buf.String(), "=== breadcrumbs, ring of ")
	assert.Contains(t, buf.String(), "=== end of breadcrumbs ===")
	assert.Contains(t, buf.String(), "no breadcrumbs recorded")
}
