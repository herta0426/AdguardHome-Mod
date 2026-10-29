package home

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

	now := time.Now()

	_, err = fmt.Fprintf(
		w,
		"time=%s tz=%s version=%q channel=%s arch=%s os=%s pid=%d uptime=%s"+
			" workdir=%q gomaxprocs=%d uid=%d event=%s",
		formatCrashLogTime(now),
		formatCrashLogTimeZone(now),
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

// formatCrashLogTime formats t as the value of the time field of a crash log
// record.
func formatCrashLogTime(t time.Time) (s string) {
	return t.Format(time.RFC3339Nano)
}

// formatCrashLogTimeZone formats the time zone of t as the value of the tz field
// of a crash log record.  It is reported next to the timestamp, since the
// timestamp alone does not tell whether the process knew its local time zone or
// fell back to UTC.
func formatCrashLogTimeZone(t time.Time) (s string) {
	return t.Location().String()
}

// localtimePath is the path of the system-wide time zone file that the process
// reads its local time zone from.
var localtimePath = "/etc/localtime"

// localTimeZoneMissingReason is the reason returned by [localTimeZoneStatus]
// when the process has no local time zone.
const localTimeZoneMissingReason = "TZ is empty, there is no local time zone" +
	" file, and the local time zone is UTC"

// localTimeZoneStatus reports whether the process has a usable local time zone
// and, if it does not, why.  tzEnv is the value of the TZ environment variable,
// localtimeErr is the result of statting [localtimePath], and localName is the
// name of [time.Local].
//
// All three are required to tell that the local time zone is unavailable: TZ
// alone is not enough, since a zone set with any other mechanism still works,
// and a missing [localtimePath] alone is not enough, since TZ may point at a
// zone from the embedded tzdata.
func localTimeZoneStatus(tzEnv string, localtimeErr error, localName string) (ok bool, reason string) {
	if tzEnv != "" {
		return true, ""
	}

	if !errors.Is(localtimeErr, os.ErrNotExist) {
		// The file exists or could not be checked, so assume that the local
		// time zone is available rather than warn about it wrongly.
		return true, ""
	}

	if localName != "UTC" {
		return true, ""
	}

	return false, localTimeZoneMissingReason
}

// localTimeZone returns the status of the local time zone of the process, see
// [localTimeZoneStatus].
func localTimeZone() (ok bool, reason string) {
	_, err := os.Stat(localtimePath)

	return localTimeZoneStatus(os.Getenv("TZ"), err, time.Local.String())
}

// logLocalTimeZoneStatus writes a warning into l if the process has no local
// time zone, so that timestamps falling back to UTC do not go unnoticed.  l
// must not be nil.
func logLocalTimeZoneStatus(ctx context.Context, l *slog.Logger) {
	ok, reason := localTimeZone()
	if ok {
		return
	}

	l.WarnContext(
		ctx,
		"the time zone is UTC; set TZ to the IANA name of your zone, for"+
			" example TZ=Asia/Shanghai, to get local timestamps",
		"tz", time.Local.String(),
		"localtime_missing", true,
		"reason", reason,
	)
}

// writeCrashLogHeader writes the one line that identifies the run the following
// records belong to, so that the traces of several processes can be told apart
// in the same file.  It shares the formatter with the panic record, so that the
// two cannot drift apart.  w must not be nil.
func writeCrashLogHeader(w io.Writer, workDir string) (err error) {
	return writeCrashLogRecord(w, workDir, crashLogEventStart)
}
