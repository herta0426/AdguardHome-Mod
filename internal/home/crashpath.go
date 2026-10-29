package home

import (
	"os"
	"path/filepath"
)

// crashLogName is the name of the file that receives everything the process
// writes to stderr, in particular the panic traces printed by the Go runtime.
const crashLogName = "crash.log"

// envCrashLog is the name of the environment variable that overrides the path
// to the crash log, see [resolveCrashLogPath].
const envCrashLog = "AGH_CRASH_LOG"

// resolveCrashLogPath returns the path to the crash log.  flagValue is the value
// of the --crash-log command-line option, envValue is the value of the
// [envCrashLog] environment variable, and workDir is the working directory of
// AdGuard Home.
//
// A non-empty flagValue takes precedence over envValue, which takes precedence
// over the default path in workDir.  Both are used as is, since users may pass
// absolute as well as relative paths.
func resolveCrashLogPath(flagValue, envValue, workDir string) (path string) {
	if flagValue != "" {
		return flagValue
	}

	if envValue != "" {
		return envValue
	}

	if workDir == "" {
		// Fall back to the current directory, so that the crash log is still
		// created somewhere predictable.  The error is not important, since a
		// bare file name is used if even that fails.
		workDir, _ = os.Getwd()
	}

	return filepath.Join(workDir, crashLogName)
}
