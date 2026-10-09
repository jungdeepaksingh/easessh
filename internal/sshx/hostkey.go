package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// hostKeyCallback verifies against ~/.ssh/known_hosts, asking to trust unknown hosts
// and refusing changed keys, mirroring OpenSSH's StrictHostKeyChecking=ask.
// The raw known_hosts callback is also returned for preferredHostKeyAlgos.
func hostKeyCallback(t *tty) (ssh.HostKeyCallback, ssh.HostKeyCallback, error) {
	path := filepath.Join(sshDir(), "known_hosts")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return nil, nil, err
	}
	f.Close()
	db, err := knownhosts.New(path)
	if err != nil {
		return nil, nil, fmt.Errorf("load %s: %w", path, err)
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := db(hostname, remote, key)
		var ke *knownhosts.KeyError
		if !errors.As(err, &ke) {
			return err
		}
		if len(ke.Want) > 0 {
			return &HostKeyChangedError{Host: hostname, Fingerprint: ssh.FingerprintSHA256(key),
				File: ke.Want[0].Filename, Line: ke.Want[0].Line}
		}
		t.printf("The authenticity of host '%s' can't be established.\n%s key fingerprint is %s.\n",
			hostname, key.Type(), ssh.FingerprintSHA256(key))
		ans, err := t.readLine("Are you sure you want to continue connecting (yes/no)? ")
		if err != nil {
			return err
		}
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "yes" && a != "y" {
			return errors.New("host key verification failed")
		}
		af, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer af.Close()
		_, err = fmt.Fprintln(af, knownhosts.Line([]string{knownhosts.HashHostname(knownhosts.Normalize(hostname))}, key))
		if err == nil {
			t.printf("Permanently added '%s' to the list of known hosts.\n", hostname)
		}
		return err
	}, db, nil
}

// HostKeyChangedError means the server's key differs from the one in known_hosts.
type HostKeyChangedError struct {
	Host, Fingerprint, File string
	Line                    int
}

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf("host key for %s has CHANGED (now %s). This could be a man-in-the-middle attack. "+
		"If the server was reinstalled, remove line %d from %s", e.Host, e.Fingerprint, e.Line, e.File)
}

// preferredHostKeyAlgos puts the algorithms already recorded for this host first,
// so a server offering several key types doesn't trigger a false "key changed" error.
func preferredHostKeyAlgos(cb ssh.HostKeyCallback, hostname string, remote net.Addr) []string {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	probe, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil
	}
	var ke *knownhosts.KeyError
	if !errors.As(cb(hostname, remote, probe), &ke) || len(ke.Want) == 0 {
		return nil
	}
	var algos []string
	seen := map[string]bool{}
	add := func(a string) {
		if !seen[a] {
			seen[a] = true
			algos = append(algos, a)
		}
	}
	for _, w := range ke.Want {
		if w.Key.Type() == ssh.KeyAlgoRSA {
			add(ssh.KeyAlgoRSASHA512)
			add(ssh.KeyAlgoRSASHA256)
		}
		add(w.Key.Type())
	}
	for _, a := range ssh.SupportedAlgorithms().HostKeys {
		add(a)
	}
	return algos
}
