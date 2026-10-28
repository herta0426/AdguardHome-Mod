//go:build linux

package home

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/AdguardTeam/AdGuardHome/internal/version"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCrashLogMaxSize is the size limit used instead of [crashLogMaxSize], so
// that the tests do not have to create files of tens of megabytes.
const testCrashLogMaxSize = 16

// writeTestFile writes a file of size bytes at path.
func writeTestFile(t *testing.T, path string, size int) {
	t.Helper()

	data := bytes.Repeat([]byte{'x'}, size)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func TestRotateCrashLog(t *testing.T) {
	t.Parallel()

	t.Run("rotated", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), crashLogName)

		// The new content is one byte longer than the limit, so that the
		// backup below is distinguishable by its size.
		require.NoError(t, writeTestFile(path, testCrashLogMaxSize+1))
		require.NoError(t, writeTestFile(path+crashLogBackupSuffix, 3))

		require.NoError(t, rotateCrashLog(path, testCrashLogMaxSize))

		_, err := os.Stat(path)
		require.ErrorIs(t, err, os.ErrNotExist)

		data, err := os.ReadFile(path + crashLogBackupSuffix)
		require.NoError(t, err)
		assert.Len(t, data, testCrashLogMaxSize+1)
	})

	t.Run("below_limit", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), crashLogName)
		require.NoError(t, writeTestFile(path, testCrashLogMaxSize-1))

		require.NoError(t, rotateCrashLog(path, testCrashLogMaxSize))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Len(t, data, testCrashLogMaxSize-1)

		_, err = os.Stat(path + crashLogBackupSuffix)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("missing", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), crashLogName)

		require.NoError(t, rotateCrashLog(path, testCrashLogMaxSize))

		_, err := os.Stat(path + crashLogBackupSuffix)
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}

func TestOpenCrashLogFile(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	l := slogutil.NewDiscardLogger()

	dir := t.TempDir()
	path := crashLogPath(dir)
	require.Equal(t, filepath.Join(dir, crashLogName), path)

	// NOTE: The file is opened, the header is written and the file is closed,
	// but fd 2 is not redirected here, since that would change the stderr of
	// the test process itself.
	f, err := openCrashLogFile(ctx, l, path)
	require.NoError(t, err)

	require.NoError(t, writeCrashLogHeader(f))
	require.NoError(t, writeCrashLogHeader(f))
	require.NoError(t, f.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	s := string(data)
	assert.Contains(t, s, version.Full())
	assert.Contains(t, s, strconv.Itoa(os.Getpid()))

	// Opening an existing file appends to it instead of truncating it.
	f, err = openCrashLogFile(ctx, l, path)
	require.NoError(t, err)

	require.NoError(t, writeCrashLogHeader(f))
	require.NoError(t, f.Close())

	data, err = os.ReadFile(path)
	require.NoError(t, err)
	assert.Greater(t, len(data), len(s))
}
