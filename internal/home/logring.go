package home

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

// Breadcrumbs are the most recent log records, formatted as one line each and
// kept in memory in a ring buffer, so that [recoverAndLog] can write them into
// the crash log before the stack, see [writeBreadcrumbs].
//
// NOTE: Only the panics that [recover] can handle, that is the ones of the
// goroutine protected by [recoverAndLog], get the breadcrumbs.  A panic in any
// other goroutine terminates the process from the runtime itself, so only the
// stack is written then.
const (
	// breadcrumbsSize is the size of the breadcrumb ring buffer in bytes.
	breadcrumbsSize = 64 * 1024

	// breadcrumbMaxLen is the maximum length of a single breadcrumb in bytes,
	// including the truncation mark.
	breadcrumbMaxLen = 1024

	// breadcrumbTruncatedMark replaces the tail of a breadcrumb that is longer
	// than breadcrumbMaxLen.  It ends with the newline that terminates every
	// breadcrumb.
	breadcrumbTruncatedMark = "…truncated\n"
)

// breadcrumbs is the ring buffer that keeps the most recent log records in
// memory.  It is assigned in [newSlogLogger] before any other goroutine may
// write a log record, and is nil until then as well as when logging is
// disabled.
var breadcrumbs *breadcrumbRing

// lineWriter is an [io.Writer] that accumulates everything written to it in
// buf.  It never fails, since it only writes into memory.
type lineWriter struct {
	// buf is the accumulated data.
	buf []byte
}

// type check
var _ io.Writer = (*lineWriter)(nil)

// Write implements the [io.Writer] interface for *lineWriter.
func (w *lineWriter) Write(p []byte) (n int, err error) {
	w.buf = append(w.buf, p...)

	return len(p), nil
}

// reset drops the accumulated data, keeping the underlying array for reuse.
func (w *lineWriter) reset() {
	w.buf = w.buf[:0]
}

// breadcrumbRing is the fixed-size ring buffer of formatted log records.  All
// fields except dropped are guarded by mu, which is taken with
// [sync.Mutex.TryLock] on the logging path, see [ringHandler.Handle].
type breadcrumbRing struct {
	// line is the scratch space the formatting handler writes the current
	// record into.  It is only used while mu is held.
	line lineWriter

	// mu guards the fields below as well as line.
	mu sync.Mutex

	// buf is the ring buffer itself.
	buf []byte

	// start is the index in buf of the oldest byte.
	start int

	// size is the number of bytes of buf that are in use.
	size int

	// dropped is the number of breadcrumbs that have been discarded, either
	// because the lock was busy or because the record could not be formatted.
	dropped atomic.Uint64
}

// newBreadcrumbRing returns a new empty breadcrumb ring buffer.
func newBreadcrumbRing() (b *breadcrumbRing) {
	return &breadcrumbRing{
		buf: make([]byte, breadcrumbsSize),
	}
}

// append stores line in the ring buffer, dropping the oldest breadcrumbs to make
// room for it.  line must end with a newline.  mu must be held.
func (b *breadcrumbRing) append(line []byte) {
	for b.size+len(line) > len(b.buf) {
		if !b.dropOldestLine() {
			return
		}
	}

	n := len(b.buf)

	// end is the index the new data starts at.  Since start is always less
	// than n and size is at most n, a single subtraction is enough.
	end := b.start + b.size
	if end >= n {
		end -= n
	}

	copied := copy(b.buf[end:], line)
	copy(b.buf, line[copied:])

	b.size += len(line)
}

// dropOldestLine removes the oldest whole line from the ring buffer and reports
// whether it has removed anything.  A buffer that holds an unterminated
// fragment only is emptied instead.  mu must be held.
func (b *breadcrumbRing) dropOldestLine() (ok bool) {
	n := len(b.buf)
	for i := 0; i < b.size; i++ {
		if b.buf[(b.start+i)%n] != '\n' {
			continue
		}

		drop := i + 1
		b.start = (b.start + drop) % n
		b.size -= drop

		return true
	}

	// There is no line boundary left, so the buffer holds an unterminated
	// fragment only, which must never be reported as a breadcrumb.
	b.start, b.size = 0, 0

	return false
}

// writeTo writes the buffered breadcrumbs, oldest first, to w.  It never waits
// for the lock: if it is busy, the breadcrumbs are reported as unavailable
// instead of risking a deadlock in the recovery path.  w must not be nil.
func (b *breadcrumbRing) writeTo(w io.Writer) {
	if !b.mu.TryLock() {
		_, _ = io.WriteString(w, "breadcrumbs unavailable: the buffer is busy\n")

		return
	}
	defer b.mu.Unlock()

	if b.size == 0 {
		_, _ = io.WriteString(w, "no breadcrumbs recorded\n")

		return
	}

	n := len(b.buf)
	if b.start+b.size <= n {
		// NOTE: Every breadcrumb ends with a newline and the buffer only drops
		// whole lines, so the oldest byte is always the beginning of a line.
		_, _ = w.Write(b.buf[b.start : b.start+b.size])

		return
	}

	// The data wraps around, write it in two chunks.
	_, _ = w.Write(b.buf[b.start:])
	_, _ = w.Write(b.buf[:b.start+b.size-n])
}

// truncateLine shortens line so that it fits into breadcrumbMaxLen bytes
// together with [breadcrumbTruncatedMark].  The result stays a valid UTF-8
// string if line was one.  line must be longer than breadcrumbMaxLen bytes.
func truncateLine(line []byte) (truncated []byte) {
	keep := breadcrumbMaxLen - len(breadcrumbTruncatedMark)
	for keep > 0 && !utf8.RuneStart(line[keep]) {
		keep--
	}

	// NOTE: This allocates, but only for the records longer than a kilobyte,
	// which are rare, and the allocation is bounded by breadcrumbMaxLen.
	return append(line[:keep:keep], breadcrumbTruncatedMark...)
}

// ringHandler is a [slog.Handler] that formats every record into a single line
// and keeps the last ones in a [breadcrumbRing].
//
// It must not slow the logging path down: the lock is taken with
// [sync.Mutex.TryLock], and a record is dropped and counted if it is busy.  The
// formatting is done by a [slog.TextHandler] that writes into memory, so no
// file is touched and no large objects are allocated.
type ringHandler struct {
	// ring is the ring buffer, shared by the handlers derived from this one.
	ring *breadcrumbRing

	// h formats the records into ring.line.
	h slog.Handler
}

// type check
var _ slog.Handler = (*ringHandler)(nil)

// newRingHandler returns a new breadcrumb handler that stores the records in b.
// opts are the options of the formatting handler and control, in particular,
// the levels that are collected.  b and opts must not be nil.
func newRingHandler(b *breadcrumbRing, opts *slog.HandlerOptions) (h *ringHandler) {
	return &ringHandler{
		ring: b,
		h:    slog.NewTextHandler(&b.line, opts),
	}
}

// Enabled implements the [slog.Handler] interface for *ringHandler.
func (h *ringHandler) Enabled(ctx context.Context, lvl slog.Level) (ok bool) {
	return h.h.Enabled(ctx, lvl)
}

// Handle implements the [slog.Handler] interface for *ringHandler.  It never
// blocks and never returns an error, since a missing breadcrumb is not worth
// reporting.
func (h *ringHandler) Handle(ctx context.Context, r slog.Record) (err error) {
	b := h.ring

	// Use TryLock instead of Lock, so that a slow or contended logger never
	// stalls the goroutine that writes the record.  A dropped breadcrumb is
	// only a lost diagnostic detail.
	if !b.mu.TryLock() {
		b.dropped.Add(1)

		return nil
	}
	defer b.mu.Unlock()

	b.line.reset()
	err = h.h.Handle(ctx, r)
	if err != nil {
		b.dropped.Add(1)

		return nil
	}

	line := b.line.buf
	if len(line) > breadcrumbMaxLen {
		line = truncateLine(line)
	}

	b.append(line)

	return nil
}

// WithAttrs implements the [slog.Handler] interface for *ringHandler.
func (h *ringHandler) WithAttrs(attrs []slog.Attr) (d slog.Handler) {
	return &ringHandler{
		ring: h.ring,
		h:    h.h.WithAttrs(attrs),
	}
}

// WithGroup implements the [slog.Handler] interface for *ringHandler.
func (h *ringHandler) WithGroup(name string) (d slog.Handler) {
	return &ringHandler{
		ring: h.ring,
		h:    h.h.WithGroup(name),
	}
}

// writeBreadcrumbs writes the section of the crash log that contains the log
// records which precede the panic.  It must be called before the stack is
// written, since the breadcrumbs explain what led to it.  w must not be nil.
func writeBreadcrumbs(w io.Writer) {
	b := breadcrumbs
	if b == nil {
		_, _ = io.WriteString(w, "=== breadcrumbs ===\nnot collected\n")

		return
	}

	_, _ = fmt.Fprintf(
		w,
		"=== breadcrumbs, ring of %d bytes, %d dropped ===\n",
		breadcrumbsSize,
		b.dropped.Load(),
	)

	b.writeTo(w)

	_, _ = io.WriteString(w, "=== end of breadcrumbs ===\n")
}
