package home

import (
	"bytes"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testWorkDir is the working directory the crash log records of the tests use.
const testWorkDir = "/data/adb/agh"

func TestWriteCrashLogRecord(t *testing.T) {
	t.Parallel()

	t.Run("header", func(t *testing.T) {
		t.Parallel()

		buf := &bytes.Buffer{}
		require.NoError(t, writeCrashLogHeader(buf, testWorkDir))

		line := buf.String()
		require.True(t, strings.HasSuffix(line, "\n"))
		assert.Equal(t, 1, strings.Count(line, "\n"), "the header must be a single line")

		for _, key := range []string{
			"time=",
			"tz=",
			"version=",
			"channel=",
			"arch=",
			"os=",
			"pid=",
			"uptime=",
			"workdir=",
			"gomaxprocs=",
			"uid=",
			"event=" + crashLogEventStart,
		} {
			assert.Contains(t, line, key)
		}

		assert.Contains(t, line, version.Full())
		assert.Contains(t, line, `workdir="`+testWorkDir+`"`)

		// The record is written with the time zone of this process, so the
		// field must name exactly that zone, whatever it is on this machine.
		assert.Contains(t, line, "tz="+time.Local.String())
	})

	t.Run("panic", func(t *testing.T) {
		t.Parallel()

		buf := &bytes.Buffer{}
		require.NoError(t, writeCrashLogRecord(
			buf,
			"",
			crashLogEventPanic,
			"panic", "boom\nsecond line",
		))

		line := buf.String()
		assert.Contains(t, line, "event="+crashLogEventPanic)
		assert.Contains(t, line, `panic="boom\nsecond line"`)

		// The values are quoted, so that a multi-line panic value keeps the
		// record a single line.
		assert.Equal(t, 1, strings.Count(line, "\n"))
	})
}

func TestFormatCrashLogTimeAndZone(t *testing.T) {
	t.Parallel()

	// The moment is the one from the report of the timestamps that were
	// formatted as UTC on a device in +08:00.
	moment := time.Date(2026, 10, 28, 16, 43, 16, 71217151, time.UTC)

	// NOTE: The zones are built without time.LoadLocation, so that the tests do
	// not depend on the tzdata of the machine they run on.
	plus8 := time.FixedZone("Asia/Shanghai", 8*60*60)

	testCases := []struct {
		loc      *time.Location
		name     string
		timeWant string
		tzWant   string
	}{
		{
			loc:      time.UTC,
			name:     "utc",
			timeWant: "2026-10-28T16:43:16.071217151Z",
			tzWant:   "UTC",
		},
		{
			loc:      plus8,
			name:     "plus8",
			timeWant: "2026-10-29T00:43:16.071217151+08:00",
			tzWant:   "Asia/Shanghai",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			at := moment.In(tc.loc)
			assert.Equal(t, tc.timeWant, formatCrashLogTime(at))
			assert.Equal(t, tc.tzWant, formatCrashLogTimeZone(at))
		})
	}
}

func TestLocalTimeZoneStatus(t *testing.T) {
	t.Parallel()

	const utcName = "UTC"

	statErr := &fs.PathError{Op: "stat", Path: localtimePath, Err: fs.ErrNotExist}

	testCases := []struct {
		name         string
		tzEnv        string
		localtimeErr error
		localName    string
		wantOK       bool
		wantReason   string
	}{
		{
			name:         "tz_set",
			tzEnv:        "Asia/Shanghai",
			localtimeErr: statErr,
			localName:    utcName,
			wantOK:       true,
		},
		{
			name:         "localtime_exists",
			tzEnv:        "",
			localtimeErr: nil,
			localName:    utcName,
			wantOK:       true,
		},
		{
			name:         "localtime_unreadable",
			tzEnv:        "",
			localtimeErr: &fs.PathError{Op: "stat", Path: localtimePath, Err: fs.ErrPermission},
			localName:    utcName,
			wantOK:       true,
		},
		{
			name:         "local_zone_known",
			tzEnv:        "",
			localtimeErr: statErr,
			localName:    "Local",
			wantOK:       true,
		},
		{
			name:         "missing",
			tzEnv:        "",
			localtimeErr: statErr,
			localName:    utcName,
			wantOK:       false,
			wantReason:   localTimeZoneMissingReason,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ok, reason := localTimeZoneStatus(tc.tzEnv, tc.localtimeErr, tc.localName)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.wantReason, reason)
		})
	}
}
