package home

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveCrashLogPath(t *testing.T) {
	dir := t.TempDir()

	flagPath := filepath.Join(dir, "flag.log")
	envPath := filepath.Join(dir, "env.log")
	relPath := filepath.Join("relative", crashLogName)
	defPath := filepath.Join(dir, crashLogName)

	testCases := []struct {
		name    string
		flag    string
		env     string
		workDir string
		want    string
	}{
		{name: "flag_wins", flag: flagPath, env: envPath, workDir: dir, want: flagPath},
		{name: "env_wins", env: envPath, workDir: dir, want: envPath},
		{name: "default", workDir: dir, want: defPath},
		{name: "flag_relative", flag: relPath, workDir: dir, want: relPath},
		{name: "env_relative", env: relPath, workDir: dir, want: relPath},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolveCrashLogPath(tc.flag, tc.env, tc.workDir))
		})
	}

	t.Run("empty_work_dir", func(t *testing.T) {
		t.Chdir(dir)

		got := resolveCrashLogPath("", "", "")
		assert.Equal(t, crashLogName, filepath.Base(got))
		assert.True(t, filepath.IsAbs(got))
	})
}
