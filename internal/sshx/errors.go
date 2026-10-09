package sshx

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"easessh/internal/config"
	"easessh/internal/prompt"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Explain turns a connection error into a short message a user can act on.
func Explain(h config.Host, err error) string {
	if err == nil {
		return ""
	}
	addr := h.Addr()
	var (
		dnsErr     *net.DNSError
		changed    *HostKeyChangedError
		revoked    *knownhosts.RevokedError
		netErr     net.Error
		missingKey *os.PathError
	)
	msg := strings.TrimPrefix(err.Error(), "ssh: handshake failed: ")
	switch {
	case errors.Is(err, prompt.ErrCancelled):
		return "login cancelled"
	case errors.As(err, &changed):
		return changed.Error()
	case errors.As(err, &revoked):
		return fmt.Sprintf("the host key of %s is marked @revoked in %s:%d; refusing to connect",
			h.Host, revoked.Revoked.Filename, revoked.Revoked.Line)
	case errors.As(err, &dnsErr):
		return fmt.Sprintf("unknown host %q (DNS lookup failed)", h.Host)
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Sprintf("connection refused by %s; is SSH running on port %d?", h.Host, h.Port)
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return fmt.Sprintf("%s is unreachable; check your network or VPN", h.Host)
	case errors.As(err, &netErr) && netErr.Timeout():
		return fmt.Sprintf("timed out connecting to %s; check the address, port and firewall", addr)
	case strings.Contains(msg, "unable to authenticate"):
		switch h.Auth {
		case config.AuthPassword:
			return fmt.Sprintf("authentication failed for %s; wrong password, or the server doesn't allow password login", h.Target())
		case config.AuthKey:
			return fmt.Sprintf("authentication failed for %s; the server didn't accept the key (is its .pub in authorized_keys?)", h.Target())
		default:
			return fmt.Sprintf("authentication failed for %s; no agent or default key was accepted", h.Target())
		}
	case errors.Is(err, io.EOF):
		return fmt.Sprintf("%s closed the connection during login (not an SSH server, or blocked e.g. by fail2ban)", addr)
	case strings.Contains(msg, "host key verification failed"):
		return "host key not accepted; connection cancelled"
	case errors.As(err, &missingKey) && errors.Is(err, os.ErrNotExist):
		return fmt.Sprintf("key file not found: %s", missingKey.Path)
	}
	return msg
}
