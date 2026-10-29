//go:build linux

package home

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime/debug"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/osutil"
	"golang.org/x/sys/unix"
)

// crashLogMaxSize is the size in bytes that the crash log must reach to be
// rotated into the backup file on the next start.  The stack of a panic is only
// a few tens of kilobytes, so 8 MiB leaves plenty of room for the breadcrumbs
// and the mirrored warnings, while the file and its backup take at most 16 MiB
// together.  That matters on Android, where the crash log lives in /data, the
// space of which is scarce.
const crashLogMaxSize = 8 * 1024 * 1024

// crashLogBackupSuffix is appended to the crash log path on rotation.
const crashLogBackupSuffix = ".1"

// stderrFD is the file descriptor of the standard error stream.
const stderrFD = 2

// crashLogFile is the file that fd 2 is a duplicate of after
// [redirectStderrToCrashLog] succeeds.  It is deliberately kept here instead of
// being closed when the redirection is installed: an [*os.File] that becomes
// unreachable is closed by a finalizer, and a close racing with the writes the
// runtime performs while panicking is exactly what a crash log must not do.
var crashLogFile *os.File

// crashLogWriter returns the crash log file the logger mirrors the warnings
// into, or nil if the crash log has not been set up.  It is used by
// [newSlogLogger], which must not refer to [crashLogFile] directly, since that
// variable only exists on Linux.
func crashLogWriter() (w io.Writer) {
	if crashLogFile == nil {
		return nil
	}

	return crashLogFile
}

// crashLogUID returns the user ID of the process, which tells whether AdGuard
// Home runs as root.
func crashLogUID() (uid int) {
	return os.Getuid()
}

// rotateCrashLog renames path into path+[crashLogBackupSuffix] if the file
// exists and is at least maxSize bytes long.  An already existing backup is
// overwritten.  A missing file is not an error.
func rotateCrashLog(path string, maxSize int64) (err error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}

		return fmt.Errorf("checking crash log: %w", err)
	}

	if fi.Size() < maxSize {
		return nil
	}

	err = os.Rename(path, path+crashLogBackupSuffix)
	if err != nil {
		return fmt.Errorf("rotating crash log: %w", err)
	}

	return nil
}

// openCrashLogFile rotates the crash log at path if it is too big and opens it
// for appending, creating it if necessary.  Rotation errors are only logged,
// since an oversized crash log is not a reason to lose the current one.  l must
// not be nil.
func openCrashLogFile(ctx context.Context, l *slog.Logger, path string) (f *os.File, err error) {
	err = rotateCrashLog(path, crashLogMaxSize)
	if err != nil {
		l.WarnContext(ctx, "failed to rotate crash log", slogutil.KeyError, err)
	}

	f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening crash log: %w", err)
	}

	return f, nil
}

// redirectStderrToCrashLog creates or opens the crash log at path, writes the
// startup header into it and points fd 2, that is the stderr of the whole
// process, at it.  From that moment on the Go runtime writes the panic traces
// of every goroutine into the file, no matter how the process was started.
// workDir is only used for the header.  l must not be nil.
func redirectStderrToCrashLog(
	ctx context.Context,
	l *slog.Logger,
	path string,
	workDir string,
) (err error) {
	l.InfoContext(ctx, "using crash log", "path", path)

	f, err := openCrashLogFile(ctx, l, path)
	if err != nil {
		return err
	}

	err = unix.Dup2(int(f.Fd()), stderrFD)
	if err != nil {
		_ = f.Close()

		return fmt.Errorf("redirecting stderr to %s: %w", path, err)
	}

	// Store the file before anything else may fail, so that it never becomes
	// unreachable, see the docs for [crashLogFile].
	crashLogFile = f

	err = writeCrashLogHeader(f, workDir)
	if err != nil {
		l.WarnContext(ctx, "failed to write crash log header", slogutil.KeyError, err)
	}

	// NOTE: This message goes into the crash log itself as well, since the
	// logger mirrors the warnings into it.
	logLocalTimeZoneStatus(ctx, l)

	// NOTE: This message goes into the crash log itself, since fd 2 has already
	// been redirected by now.
	l.InfoContext(ctx, "redirected stderr to the crash log", "path", path)

	return nil
}

// installCrashHandler redirects the stderr of the process into the crash log at
// path, see [redirectStderrToCrashLog].  workDir is only used for the header.
// Errors are only logged, since the crash log itself must never keep AdGuard
// Home from starting.  l must not be nil.
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

	// If the crash log is unavailable, for example because workDir is not
	// writable, write to stderr directly, so that the trace is not lost
	// silently.
	w := io.Writer(os.Stderr)
	if crashLogFile != nil {
		w = crashLogFile
	}

	_ = writeCrashLogRecord(w, dir, crashLogEventPanic, "panic", fmt.Sprint(v))

	// NOTE: The breadcrumbs are written before the stack, since they explain
	// what led to the panic.  Only the panics recovered here have them, see the
	// docs for [breadcrumbs].
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
