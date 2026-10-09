//go:build unix && !linux

package harden

import "golang.org/x/sys/unix"

func apply() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
}
