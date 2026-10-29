//go:build !linux

package home

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
)

// crashLogWriter returns nil, since there is no crash log on this platform.
func crashLogWriter() (w io.Writer) {
	return nil
}

// crashLogUID returns the value reported on the platforms where the crash log
// is not implemented.
func crashLogUID() (uid int) {
	return -1
}

// redirectStderrToCrashLog is a stub for the platforms where redirecting fd 2
// into a file is not implemented.  The panic traces go into the stderr of the
// process as usual.
func redirectStderrToCrashLog(_ context.Context, _ *slog.Logger, _, _ string) (err error) {
	return nil
}

// installCrashHandler is a stub, see [redirectStderrToCrashLog].  l must not be
// nil.
func installCrashHandler(ctx context.Context, l *slog.Logger, path, workDir string) {
	err := redirectStderrToCrashLog(ctx, l, path, workDir)
	if err != nil {
		l.WarnContext(ctx, "failed to set up the crash log", slogutil.KeyError, err)
	}
}

// recoverAndLog is intended to be deferred at the very beginning of the
// function whose goroutine it protects:
//
//	defer recoverAndLog(ctx, l, &workDir)
//
// It must be the deferred call itself and not a function that wraps it, since
// [recover] returns nil unless it is called directly by the deferred function.
// workDir is passed by pointer, because the arguments of a deferred call are
// evaluated immediately, while the working directory is only known later.  It
// may be nil.  l must not be nil.
func recoverAndLog(ctx context.Context, l *slog.Logger, workDir *string) {
	v := recover()
	if v == nil {
		return
	}

	dir := ""
	if workDir != nil {
		dir = *workDir
	}

	stack := debug.Stack()

	w := io.Writer(os.Stderr)
	_ = writeCrashLogRecord(w, dir, crashLogEventPanic, "panic", fmt.Sprint(v))

	writeBreadcrumbs(w)

	_, _ = io.WriteString(w, "=== stack ===\n")
	_, _ = w.Write(stack)

	l.ErrorContext(
		ctx,
		"panic recovered",
		"panic", v,
		"workdir", dir,
		"stack", string(stack),
	)

	os.Exit(osutil.ExitCodeFailure)
}
