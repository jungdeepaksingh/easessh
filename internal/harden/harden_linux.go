package harden

import (
	"errors"

	"golang.org/x/sys/unix"
)

func apply() error {
	return errors.Join(
		unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}),
		// Non-dumpable also makes ptrace and /proc/<pid>/mem root-only.
		unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0),
	)
}
