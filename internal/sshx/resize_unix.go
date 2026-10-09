//go:build !windows

package sshx

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// watchResize forwards terminal size changes (SIGWINCH) to the remote PTY.
func watchResize(fd int, sess *ssh.Session) (stop func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-sig:
				if w, h, err := term.GetSize(fd); err == nil {
					sess.WindowChange(h, w)
				}
			}
		}
	}()
	return func() {
		signal.Stop(sig)
		close(done)
	}
}
