package home

import (
	"context"
	"log/slog"
)

// fanoutHandler is a [slog.Handler] that sends every record to all of its
// children, for example to the regular output of AdGuard Home and to the crash
// log.  It has no build constraints and must not depend on the platform
// specific parts of the crash log, see [crashLogWriter].
type fanoutHandler struct {
	// handlers are the children, in the order they are called in.
	handlers []slog.Handler
}

// newFanoutHandler returns a new fanout handler that writes to hs.  hs must not
// be empty.
func newFanoutHandler(hs ...slog.Handler) (h *fanoutHandler) {
	return &fanoutHandler{
		handlers: hs,
	}
}

// type check
var _ slog.Handler = (*fanoutHandler)(nil)

// Enabled implements the [slog.Handler] interface for *fanoutHandler.  A record
// is enabled if at least one child is interested in it, since [Handle] skips
// the children that are not.
func (h *fanoutHandler) Enabled(ctx context.Context, lvl slog.Level) (ok bool) {
	for _, c := range h.handlers {
		if c.Enabled(ctx, lvl) {
			return true
		}
	}

	return false
}

// Handle implements the [slog.Handler] interface for *fanoutHandler.  The
// errors of the children are ignored, since a failure of one of them, for
// example a full disk behind the crash log, must not silence the others.  It
// always returns nil.
func (h *fanoutHandler) Handle(ctx context.Context, r slog.Record) (err error) {
	for _, c := range h.handlers {
		// NOTE: A handler is not required to filter the records it handles
		// itself, so check the level here as well.
		if !c.Enabled(ctx, r.Level) {
			continue
		}

		_ = c.Handle(ctx, r)
	}

	return nil
}

// WithAttrs implements the [slog.Handler] interface for *fanoutHandler.  The
// attributes are passed to every child, otherwise they would be lost the first
// time a logger derived with [slog.Logger.With] writes a record.
func (h *fanoutHandler) WithAttrs(attrs []slog.Attr) (d slog.Handler) {
	derived := make([]slog.Handler, len(h.handlers))
	for i, c := range h.handlers {
		derived[i] = c.WithAttrs(attrs)
	}

	return newFanoutHandler(derived...)
}

// WithGroup implements the [slog.Handler] interface for *fanoutHandler.  The
// group name is passed to every child for the same reason as in [WithAttrs].
func (h *fanoutHandler) WithGroup(name string) (d slog.Handler) {
	derived := make([]slog.Handler, len(h.handlers))
	for i, c := range h.handlers {
		derived[i] = c.WithGroup(name)
	}

	return newFanoutHandler(derived...)
}
