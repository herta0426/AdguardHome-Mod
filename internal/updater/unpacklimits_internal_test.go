package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testUnpackLimits are small enough to be exceeded by the tiny packages
// generated in these tests.
var testUnpackLimits = unpackLimits{
	maxFile:    8,
	maxTotal:   20,
	maxEntries: 3,
}

// testEntry is a regular file to be put into a test package.
type testEntry struct {
	// name is the entry name inside the package.
	name string

	// size is the size of the entry data in bytes.
	size int
}

// newTestUpdater returns an Updater that only discards the log messages, which
// is enough for the unpacking methods.
func newTestUpdater() (u *Updater) {
	return &Updater{
		logger: slogutil.NewDiscardLogger(),
	}
}

// writeTarGz generates a .tar.gz package containing entries as regular files
// filled with the same byte and returns its path.
func writeTarGz(t *testing.T, dir string, entries []testEntry) (path string) {
	t.Helper()

	path = filepath.Join(dir, "pkg.tar.gz")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()

	gzWriter := gzip.NewWriter(f)
	tarWriter := tar.NewWriter(gzWriter)
	for _, e := range entries {
		require.NoError(t, tarWriter.WriteHeader(&tar.Header{
			Name:     e.name,
			Typeflag: tar.TypeReg,
			Size:     int64(e.size),
			Mode:     0o644,
		}))

		_, err = tarWriter.Write(bytes.Repeat([]byte{'x'}, e.size))
		require.NoError(t, err)
	}

	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzWriter.Close())

	return path
}

// writeZip generates a .zip package containing entries as regular files filled
// with the same byte and returns its path.
func writeZip(t *testing.T, dir string, entries []testEntry) (path string) {
	t.Helper()

	path = filepath.Join(dir, "pkg.zip")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()

	zipWriter := zip.NewWriter(f)
	for _, e := range entries {
		w, werr := zipWriter.Create(e.name)
		require.NoError(t, werr)

		_, werr = w.Write(bytes.Repeat([]byte{'x'}, e.size))
		require.NoError(t, werr)
	}

	require.NoError(t, zipWriter.Close())

	return path
}

// unpackTestCase is a single test case for the unpacking limits.
type unpackTestCase struct {
	// name is the name of the test case.
	name string

	// entries are the package contents.
	entries []testEntry

	// wantErrMsg is the expected error message, if any.
	wantErrMsg string
}

// unpackTestCases returns the test cases covering all the unpacking limits.
func unpackTestCases() (testCases []unpackTestCase) {
	return []unpackTestCase{{
		name:       "single_file_too_large",
		entries:    []testEntry{{name: "a", size: 9}},
		wantErrMsg: `unpacking "a": file size 9 exceeds the limit 8`,
	}, {
		name: "total_too_large",
		entries: []testEntry{
			{name: "a", size: 8},
			{name: "b", size: 8},
			{name: "c", size: 8},
		},
		wantErrMsg: `unpacking "c": total size 24 exceeds the limit 20`,
	}, {
		name: "too_many_entries",
		entries: []testEntry{
			{name: "a", size: 1},
			{name: "b", size: 1},
			{name: "c", size: 1},
			{name: "d", size: 1},
		},
		wantErrMsg: "unpacking 4 entries: exceeds the limit 3",
	}, {
		name: "exactly_at_limits",
		entries: []testEntry{
			{name: "a", size: 8},
			{name: "b", size: 8},
			{name: "c", size: 4},
		},
	}}
}

func TestUpdater_unpackTarGz_limits(t *testing.T) {
	for _, tc := range unpackTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pkgPath := writeTarGz(t, dir, tc.entries)
			outDir := filepath.Join(dir, "out")
			require.NoError(t, os.Mkdir(outDir, 0o755))

			u := newTestUpdater()
			files, err := u.unpackTarGz(context.Background(), pkgPath, outDir, testUnpackLimits)
			if tc.wantErrMsg == "" {
				require.NoError(t, err)
				assert.Len(t, files, len(tc.entries))
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.wantErrMsg, err.Error())
			}
		})
	}
}

func TestUpdater_unpackZip_limits(t *testing.T) {
	for _, tc := range unpackTestCases() {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pkgPath := writeZip(t, dir, tc.entries)
			outDir := filepath.Join(dir, "out")
			require.NoError(t, os.Mkdir(outDir, 0o755))

			u := newTestUpdater()
			files, err := u.unpackZip(context.Background(), pkgPath, outDir, testUnpackLimits)
			if tc.wantErrMsg == "" {
				require.NoError(t, err)
				assert.Len(t, files, len(tc.entries))
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.wantErrMsg, err.Error())
			}
		})
	}
}
