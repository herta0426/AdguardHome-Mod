package home

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/version"
)

// Event names reported in the event field of the crash log records.
const (
	// crashLogEventStart is the event of the record that opens a run.
	crashLogEventStart = "start"

	// crashLogEventPanic is the event of the record written by
	// [recoverAndLog].
	crashLogEventPanic = "panic"
)

// crashLogStart is the time this package has been initialized at.  It is used
// as the base of the uptime reported in the crash log, since the initialization
// of the package is close enough to the start of the process.
var crashLogStart = time.Now()

// writeCrashLogRecord writes the single line of key=value pairs that opens
// every record of the crash log.  The format is meant to be readable by humans
// and parseable by scripts: one record per line, the identification of the
// process first, then event.
//
// workDir is the working directory of AdGuard Home.  If it is empty, the
// current working directory is used.  extra is an even number of additional
// key, value pairs, the values of which are quoted.  w must not be nil.
func writeCrashLogRecord(w io.Writer, workDir, event string, extra ...string) (err error) {
	if workDir == "" {
		// The error is not important, the field is informational only.
		workDir, _ = os.Getwd()
	}

	_, err = fmt.Fprintf(
		w,
		"time=%s version=%q channel=%s arch=%s os=%s pid=%d uptime=%s"+
			" workdir=%q gomaxprocs=%d uid=%d event=%s",
		time.Now().Format(time.RFC3339Nano),
		version.Full(),
		version.Channel(),
		runtime.GOARCH,
		runtime.GOOS,
		os.Getpid(),
		time.Since(crashLogStart).Round(time.Millisecond).String(),
		workDir,
		runtime.GOMAXPROCS(0),
		crashLogUID(),
		event,
	)
	if err != nil {
		return fmt.Errorf("writing crash log record: %w", err)
	}

	for i := 0; i+1 < len(extra); i += 2 {
		_, err = fmt.Fprintf(w, " %s=%q", extra[i], extra[i+1])
		if err != nil {
			return fmt.Errorf("writing crash log record: %w", err)
		}
	}

	_, err = io.WriteString(w, "\n")
	if err != nil {
		return fmt.Errorf("writing crash log record: %w", err)
	}

	return nil
}

// writeCrashLogHeader writes the one line that identifies the run the following
// records belong to, so that the traces of several processes can be told apart
// in the same file.  It shares the formatter with the panic record, so that the
// two cannot drift apart.  w must not be nil.
func writeCrashLogHeader(w io.Writer, workDir string) (err error) {
	return writeCrashLogRecord(w, workDir, crashLogEventStart)
}
