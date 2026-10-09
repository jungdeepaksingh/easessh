package sshx

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"easessh/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var defaultKeys = []string{"id_ed25519", "id_ecdsa", "id_rsa"}

// authMethods builds the auth chain for h. The returned closer releases the agent socket.
func authMethods(h config.Host, t *tty) ([]ssh.AuthMethod, func(), error) {
	var methods []ssh.AuthMethod
	closer := func() {}

	switch h.Auth {
	case config.AuthPassword:
		saved := h.Password
		prompt := fmt.Sprintf("%s's password: ", h.Target())
		// The saved password is tried once; later attempts prompt like OpenSSH does.
		next := func() (string, error) {
			if saved != "" {
				pw := saved
				saved = ""
				return pw, nil
			}
			return t.readSecret(prompt)
		}
		methods = append(methods,
			ssh.RetryableAuthMethod(ssh.PasswordCallback(next), 3),
			ssh.RetryableAuthMethod(ssh.KeyboardInteractive(
				func(_, instruction string, questions []string, echos []bool) ([]string, error) {
					if instruction != "" {
						t.printf("%s\n", instruction)
					}
					answers := make([]string, len(questions))
					for i, q := range questions {
						var err error
						if echos[i] {
							answers[i], err = t.readLine(q)
						} else if strings.Contains(strings.ToLower(q), "password") {
							answers[i], err = next()
						} else {
							answers[i], err = t.readSecret(q)
						}
						if err != nil {
							return nil, err
						}
					}
					return answers, nil
				}), 3),
		)

	case config.AuthKey:
		path := h.KeyPath
		if path == "" {
			path = firstDefaultKey()
		}
		signer, err := loadKey(config.ExpandPath(path), h.Passphrase, t)
		if err != nil {
			return nil, closer, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if h.Auth == config.AuthKey || h.Auth == config.AuthAgent {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			if conn, err := net.Dial("unix", sock); err == nil {
				methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
				closer = func() { conn.Close() }
			}
		}
	}
	if h.Auth == config.AuthAgent {
		// Unencrypted default keys only: never surprise the user with passphrase prompts.
		var signers []ssh.Signer
		for _, name := range defaultKeys {
			if data, err := os.ReadFile(filepath.Join(sshDir(), name)); err == nil {
				if s, err := ssh.ParsePrivateKey(data); err == nil {
					signers = append(signers, s)
				}
			}
		}
		if len(signers) > 0 {
			methods = append(methods, ssh.PublicKeys(signers...))
		}
		if len(methods) == 0 {
			return nil, closer, errors.New("no ssh-agent (SSH_AUTH_SOCK) and no unencrypted key in ~/.ssh; use key or password auth")
		}
	}
	return methods, closer, nil
}

func loadKey(path, passphrase string, t *tty) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		if err != nil {
			return nil, fmt.Errorf("parse key %s: %w", path, err)
		}
		return signer, nil
	}
	for attempt := 0; attempt < 3; attempt++ {
		pass := passphrase
		passphrase = ""
		if pass == "" {
			if pass, err = t.readSecret(fmt.Sprintf("Enter passphrase for key '%s': ", path)); err != nil {
				return nil, err
			}
		}
		signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(pass))
		if err == nil {
			return signer, nil
		}
		t.printf("Bad passphrase.\n")
	}
	return nil, fmt.Errorf("decrypt key %s: %w", path, err)
}

func sshDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh")
}

func firstDefaultKey() string {
	for _, name := range defaultKeys {
		p := filepath.Join(sshDir(), name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Join(sshDir(), defaultKeys[0])
}

// DefaultKeyPath is the key used when a key-auth host leaves the path blank.
func DefaultKeyPath() string { return firstDefaultKey() }
