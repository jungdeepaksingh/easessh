// easessh is a fast, minimal SSH host manager for the terminal.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"easessh/internal/config"
	"easessh/internal/harden"
	"easessh/internal/prompt"
	"easessh/internal/sshx"
	"easessh/internal/tui"
	tea "github.com/charmbracelet/bubbletea"
)

const minMasterLen = 8

// version is set at release time with -ldflags "-X main.version=..."
var version = "dev"

const usage = `easessh - fast SSH host manager

Usage:
  easessh            open the host manager
  easessh <name>     connect directly to a saved host (exact or unique partial match)
  easessh -l         list saved hosts
  easessh --passwd   change the master password
  easessh -v         print version

Hosts are encrypted with your master password (Argon2id + AES-256-GCM).
The manager locks itself after $EASESSH_AUTOLOCK minutes idle (default 10, 0 = off).

Config: %s (override with $EASESSH_CONFIG)
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "easessh:", err)
		os.Exit(1)
	}
}

func run() error {
	path, err := config.DefaultPath()
	if err != nil {
		return err
	}
	arg := ""
	if len(os.Args) > 1 {
		arg = os.Args[1]
	}
	switch arg {
	case "-h", "--help", "help":
		fmt.Printf(usage, path)
		return nil
	case "-v", "--version":
		fmt.Println("easessh", version)
		return nil
	}

	if err := harden.Apply(); err != nil && os.Getenv("EASESSH_DEBUG") != "" {
		fmt.Fprintln(os.Stderr, "easessh: hardening:", err)
	}
	autoLock, err := autoLockDuration()
	if err != nil {
		return err
	}

	store, err := unlock(path)
	if err != nil {
		return err
	}
	defer store.Lock()

	switch arg {
	case "":
		_, err = tea.NewProgram(tui.New(store, tui.Options{AutoLock: autoLock}), tea.WithAltScreen()).Run()
		return err
	case "-l", "--list", "ls":
		for _, h := range store.Sorted() {
			fmt.Printf("%-24s %-9s %s\n", h.Name, h.Auth, h.Target())
		}
		return nil
	case "--passwd", "passwd":
		pw, err := newMaster("New master password: ")
		if err != nil {
			return err
		}
		defer clear(pw)
		if err := store.ChangeMaster(pw); err != nil {
			return err
		}
		fmt.Println("Master password changed.")
		return nil
	default:
		h, err := findHost(store, arg)
		if err != nil {
			return err
		}
		if err := sshx.Run(h, os.Stdin, os.Stdout); err != nil {
			return fmt.Errorf("%s: %s", h.Name, sshx.Explain(h, err))
		}
		return store.Touch(h.Name)
	}
}

// autoLockDuration reads $EASESSH_AUTOLOCK in minutes (0 disables, default 10).
func autoLockDuration() (time.Duration, error) {
	v := os.Getenv("EASESSH_AUTOLOCK")
	if v == "" {
		return 10 * time.Minute, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("EASESSH_AUTOLOCK must be a number of minutes (0 = off), got %q", v)
	}
	return time.Duration(n) * time.Minute, nil
}

// unlock creates, migrates or decrypts the hosts file depending on its state.
func unlock(path string) (*config.Store, error) {
	state, err := config.Probe(path)
	if err != nil {
		return nil, err
	}
	switch state {
	case config.StateNew, config.StatePlain:
		if state == config.StateNew {
			fmt.Println("Welcome to easessh! Create a master password to encrypt your hosts.")
		} else {
			fmt.Printf("%s is not encrypted. Create a master password to encrypt it.\n", path)
		}
		fmt.Println("There is no way to recover it if forgotten.")
		pw, err := newMaster("Master password: ")
		if err != nil {
			return nil, err
		}
		defer clear(pw)
		store, err := config.Load(path, pw)
		if err != nil {
			return nil, err
		}
		if err := store.Save(); err != nil {
			return nil, err
		}
		return store, nil
	}

	for attempt := 1; ; attempt++ {
		pw, err := readSecret("🔒 Master password: ")
		if err != nil {
			return nil, err
		}
		store, err := config.Load(path, pw)
		clear(pw)
		if err == nil {
			return store, nil
		}
		if !errors.Is(err, config.ErrWrongPassword) || attempt == 3 {
			return nil, err
		}
		fmt.Println("Wrong password, try again.")
	}
}

func newMaster(prompt string) ([]byte, error) {
	for {
		pw, err := readSecret(prompt)
		if err != nil {
			return nil, err
		}
		if len(pw) < minMasterLen {
			fmt.Printf("Use at least %d characters.\n", minMasterLen)
			continue
		}
		again, err := readSecret("Confirm: ")
		if err != nil {
			return nil, err
		}
		match := bytes.Equal(pw, again)
		clear(again)
		if match {
			return pw, nil
		}
		clear(pw)
		fmt.Println("Passwords don't match, try again.")
	}
}

func readSecret(q string) ([]byte, error) {
	pw, err := prompt.Secret(os.Stdin, os.Stdout, q)
	if errors.Is(err, prompt.ErrCancelled) {
		return nil, errors.New("cancelled")
	}
	return pw, err
}

func findHost(s *config.Store, q string) (config.Host, error) {
	if h, ok := s.Get(q); ok {
		return h, nil
	}
	var matches []config.Host
	for _, h := range s.Sorted() {
		if strings.Contains(strings.ToLower(h.Name), strings.ToLower(q)) {
			matches = append(matches, h)
		}
	}
	switch len(matches) {
	case 0:
		return config.Host{}, fmt.Errorf("no saved host matches %q", q)
	case 1:
		return matches[0], nil
	}
	names := make([]string, len(matches))
	for i, h := range matches {
		names[i] = h.Name
	}
	return config.Host{}, fmt.Errorf("%q is ambiguous: %s", q, strings.Join(names, ", "))
}
