// Package sshx runs interactive SSH sessions with a native Go client.
package sshx

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"easessh/internal/config"
	"easessh/internal/prompt"
	"github.com/muesli/cancelreader"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const dialTimeout = 10 * time.Second

// Session adapts Run to bubbletea's tea.ExecCommand so the TUI can hand over the terminal.
type Session struct {
	Host config.Host
	in   io.Reader
	out  io.Writer
	err  io.Writer
}

func (s *Session) SetStdin(r io.Reader)  { s.in = r }
func (s *Session) SetStdout(w io.Writer) { s.out = w }
func (s *Session) SetStderr(w io.Writer) { s.err = w }
func (s *Session) Run() error {
	in, ok := s.in.(*os.File)
	if !ok {
		in = os.Stdin
	}
	out := s.out
	if out == nil {
		out = os.Stdout
	}
	return Run(s.Host, in, out)
}

// Run connects to h and attaches an interactive shell to the terminal.
// A remote shell exiting (with any status) is not an error.
func Run(h config.Host, in *os.File, out io.Writer) error {
	t := &tty{in: in, out: out}
	t.printf("Connecting to %s ...\n", h.Target())

	auth, closeAuth, err := authMethods(h, t)
	defer closeAuth()
	if err != nil {
		return t.cancelOr(err)
	}
	hostKeyCB, knownCB, err := hostKeyCallback(t)
	if err != nil {
		return err
	}

	addr := h.Addr()
	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return err
	}
	cfg := &ssh.ClientConfig{
		User:              h.LoginUser(),
		Auth:              auth,
		HostKeyCallback:   hostKeyCB,
		HostKeyAlgorithms: preferredHostKeyAlgos(knownCB, addr, conn.RemoteAddr()),
		Timeout:           dialTimeout,
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		// x/crypto doesn't always pass a prompt's error through the auth state machine.
		return t.cancelOr(err)
	}
	client := ssh.NewClient(c, chans, reqs)
	defer client.Close()

	done := make(chan struct{})
	defer close(done)
	go keepalive(client, done)

	return shell(client, in, out)
}

func shell(client *ssh.Client, in *os.File, out io.Writer) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	fd := int(in.Fd())
	if term.IsTerminal(fd) {
		w, h, err := term.GetSize(fd)
		if err != nil {
			w, h = 80, 24
		}
		termType := os.Getenv("TERM")
		if termType == "" {
			termType = "xterm-256color"
		}
		modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
		if err := sess.RequestPty(termType, h, w, modes); err != nil {
			return fmt.Errorf("request pty: %w", err)
		}
		old, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}
		defer term.Restore(fd, old)
		stopResize := watchResize(fd, sess)
		defer stopResize()
	}

	sess.Stdout = out
	sess.Stderr = out
	stdin, err := sess.StdinPipe()
	if err != nil {
		return err
	}
	// A cancelable reader ensures no goroutine keeps reading stdin after the session,
	// which would otherwise swallow the first keypress back in the TUI.
	cr, err := cancelreader.NewReader(in)
	if err != nil {
		return err
	}
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		io.Copy(stdin, cr)
		stdin.Close()
	}()
	// The copier must have exited before Close: otherwise its epoll fd number can be
	// reused by the TUI's reader and the stale goroutine steals keystrokes.
	defer func() {
		cr.Cancel()
		select {
		case <-copied:
			cr.Close()
		case <-time.After(time.Second):
		}
	}()

	if err := sess.Shell(); err != nil {
		return err
	}
	err = sess.Wait()

	var exitErr *ssh.ExitError
	if err == nil || errors.As(err, &exitErr) {
		return nil
	}
	var missing *ssh.ExitMissingError
	if errors.As(err, &missing) {
		return errors.New("connection lost")
	}
	return err
}

// Like OpenSSH's ServerAliveInterval=15 / ServerAliveCountMax=3.
var (
	keepaliveInterval = 15 * time.Second
	keepaliveTimeout  = 45 * time.Second
)

// keepalive closes the connection when the server stops answering, so a dropped
// network ends the session with "connection lost" instead of freezing the terminal.
func keepalive(client *ssh.Client, done <-chan struct{}) {
	tick := time.NewTicker(keepaliveInterval)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case <-tick.C:
		}
		reply := make(chan error, 1)
		go func() {
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			reply <- err
		}()
		select {
		case <-done:
			return
		case err := <-reply:
			if err != nil {
				client.Close()
				return
			}
		case <-time.After(keepaliveTimeout):
			client.Close()
			return
		}
	}
}

// tty does OpenSSH-style prompts on the (cooked) terminal before the session starts.
type tty struct {
	in        *os.File
	out       io.Writer
	cancelled bool // the user pressed Ctrl+C/Ctrl+D at a prompt
}

func (t *tty) cancelOr(err error) error {
	if t.cancelled {
		return prompt.ErrCancelled
	}
	return err
}

func (t *tty) printf(format string, a ...any) { fmt.Fprintf(t.out, format, a...) }

func (t *tty) readSecret(q string) (string, error) {
	b, err := prompt.Secret(t.in, t.out, q)
	t.cancelled = t.cancelled || errors.Is(err, prompt.ErrCancelled)
	return string(b), err
}

func (t *tty) readLine(q string) (string, error) {
	s, err := prompt.Line(t.in, t.out, q)
	t.cancelled = t.cancelled || errors.Is(err, prompt.ErrCancelled)
	return s, err
}
