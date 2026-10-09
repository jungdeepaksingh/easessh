//go:build windows

package sshx

import (
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// watchResize polls the console size since Windows has no SIGWINCH.
func watchResize(fd int, sess *ssh.Session) (stop func()) {
	done := make(chan struct{})
	go func() {
		lw, lh, _ := term.GetSize(fd)
		tick := time.NewTicker(250 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				if w, h, err := term.GetSize(fd); err == nil && (w != lw || h != lh) {
					lw, lh = w, h
					sess.WindowChange(h, w)
				}
			}
		}
	}()
	return func() { close(done) }
}
