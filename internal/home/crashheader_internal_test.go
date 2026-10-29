package home

import (
	"bytes"
	"strings"
	"testing"

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
