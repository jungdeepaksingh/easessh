// Package config persists the saved SSH hosts.
package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

type AuthType string

const (
	AuthPassword AuthType = "password"
	AuthKey      AuthType = "key"
	AuthAgent    AuthType = "agent" // ssh-agent + default keys in ~/.ssh
)

var AuthTypes = []AuthType{AuthPassword, AuthKey, AuthAgent}

type Host struct {
	Name       string    `json:"name"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	User       string    `json:"user"`
	Auth       AuthType  `json:"auth"`
	Password   string    `json:"password,omitempty"`
	KeyPath    string    `json:"key_path,omitempty"`
	Passphrase string    `json:"passphrase,omitempty"`
	LastUsed   time.Time `json:"last_used,omitzero"`
	Uses       int       `json:"uses,omitempty"`
}

func (h Host) Addr() string { return net.JoinHostPort(h.Host, strconv.Itoa(h.Port)) }

// LoginUser returns the configured user, falling back to the local user.
func (h Host) LoginUser() string {
	if h.User != "" {
		return h.User
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return os.Getenv("USERNAME")
}

// Target renders user@host[:port] the way people type it.
func (h Host) Target() string {
	s := h.LoginUser() + "@" + h.Host
	if h.Port != 22 {
		s += ":" + strconv.Itoa(h.Port)
	}
	return s
}

var (
	ErrLocked        = errors.New("easessh is locked")
	ErrMasterChanged = errors.New("the master password was changed in another easessh window; restart easessh")
	ErrTampered      = errors.New("hosts file failed its integrity check (corrupted or modified outside easessh)")
)

const lockTimeout = 5 * time.Second

// Store holds the decrypted host list and the key used to re-encrypt it.
// Hosts is a read-only snapshot; all changes go through the mutating methods,
// which re-read the file under a lock so concurrent instances never lose edits.
type Store struct {
	path  string
	kdf   kdfParams
	key   []byte
	Hosts []Host `json:"hosts"`
}

type payload struct {
	Hosts []Host `json:"hosts"`
}

// DefaultPath honours $EASESSH_CONFIG, else <user config dir>/easessh/hosts.json.
func DefaultPath() (string, error) {
	if p := os.Getenv("EASESSH_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "easessh", "hosts.json"), nil
}

type State int

const (
	StateNew       State = iota // no file yet
	StatePlain                  // legacy unencrypted file, needs migrating
	StateEncrypted              // needs the master password
)

// Probe reports what kind of hosts file exists at path, so the caller knows
// whether to create, migrate or ask for the master password.
func Probe(path string) (State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return StateNew, nil
	}
	if err != nil {
		return 0, err
	}
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	if e.Data != nil {
		return StateEncrypted, nil
	}
	return StatePlain, nil
}

// Load opens the hosts file with the master password. A missing file yields an
// empty store and a legacy plain file is read as-is; call Save to encrypt them.
func Load(path string, master []byte) (*Store, error) {
	s := &Store{path: path}
	if err := s.Unlock(master); err != nil {
		return nil, err
	}
	return s, nil
}

// Unlock (re)reads the hosts file with master, e.g. after an idle Lock.
func (s *Store) Unlock(master []byte) error {
	data, err := os.ReadFile(s.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var e envelope
	if data != nil {
		if err := json.Unmarshal(data, &e); err != nil {
			return fmt.Errorf("parse %s: %w", s.path, err)
		}
	}
	if e.Data == nil {
		var p payload
		if data != nil {
			if err := json.Unmarshal(data, &p); err != nil {
				return fmt.Errorf("parse %s: %w", s.path, err)
			}
		}
		kdf, key, err := newKey(master)
		if err != nil {
			return err
		}
		s.Hosts, s.kdf, s.key = p.Hosts, kdf, key
		return nil
	}

	if e.Version != 1 {
		return fmt.Errorf("unsupported hosts file version %d", e.Version)
	}
	key, err := e.kdfParams.deriveKey(master)
	if err != nil {
		return err
	}
	hosts, err := decode(key, e)
	if err != nil {
		clear(key)
		return err
	}
	s.Hosts, s.kdf, s.key = hosts, e.kdfParams, key
	return nil
}

// Lock wipes the key and drops the decrypted hosts until Unlock is called.
func (s *Store) Lock() {
	clear(s.key)
	s.key, s.Hosts = nil, nil
}

func (s *Store) Locked() bool { return s.key == nil }

func (s *Store) Path() string { return s.path }

// Save writes the in-memory hosts as-is; used to create or migrate the file.
func (s *Store) Save() error {
	if s.key == nil {
		return ErrLocked
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	return s.write(s.Hosts, s.kdf, s.key)
}

// Upsert adds h, or replaces the host currently named orig ("" means add).
func (s *Store) Upsert(orig string, h Host) error {
	return s.update(func(hosts []Host) ([]Host, error) {
		if i := index(hosts, h.Name); i >= 0 && h.Name != orig {
			return nil, fmt.Errorf("a host named %q already exists", h.Name)
		}
		if i := index(hosts, orig); orig != "" && i >= 0 {
			h.LastUsed, h.Uses = hosts[i].LastUsed, hosts[i].Uses
			hosts[i] = h
			return hosts, nil
		}
		return append(hosts, h), nil
	})
}

func (s *Store) Delete(name string) error {
	return s.update(func(hosts []Host) ([]Host, error) {
		if i := index(hosts, name); i >= 0 {
			hosts = append(hosts[:i], hosts[i+1:]...)
		}
		return hosts, nil
	})
}

// Touch records a successful connection.
func (s *Store) Touch(name string) error {
	return s.update(func(hosts []Host) ([]Host, error) {
		if i := index(hosts, name); i >= 0 {
			hosts[i].LastUsed = time.Now()
			hosts[i].Uses++
		}
		return hosts, nil
	})
}

// AddMissing adds the hosts whose names aren't taken yet and reports how many were added.
func (s *Store) AddMissing(add []Host) (int, error) {
	n := 0
	err := s.update(func(hosts []Host) ([]Host, error) {
		n = 0
		for _, h := range add {
			if index(hosts, h.Name) < 0 {
				hosts = append(hosts, h)
				n++
			}
		}
		return hosts, nil
	})
	return n, err
}

// ChangeMaster re-encrypts the file under a new master password (fresh salt).
func (s *Store) ChangeMaster(master []byte) error {
	if s.key == nil {
		return ErrLocked
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	hosts, err := s.readLatest()
	if err != nil {
		return err
	}
	kdf, key, err := newKey(master)
	if err != nil {
		return err
	}
	if err := s.write(hosts, kdf, key); err != nil {
		clear(key)
		return err
	}
	clear(s.key)
	s.Hosts, s.kdf, s.key = hosts, kdf, key
	return nil
}

func (s *Store) Index(name string) int { return index(s.Hosts, name) }

func (s *Store) Get(name string) (Host, bool) {
	if i := s.Index(name); i >= 0 {
		return s.Hosts[i], true
	}
	return Host{}, false
}

func index(hosts []Host, name string) int {
	for i, h := range hosts {
		if h.Name == name {
			return i
		}
	}
	return -1
}

// update applies fn to the latest on-disk hosts under an exclusive file lock.
func (s *Store) update(fn func([]Host) ([]Host, error)) error {
	if s.key == nil {
		return ErrLocked
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	hosts, err := s.readLatest()
	if err != nil {
		return err
	}
	if hosts, err = fn(hosts); err != nil {
		return err
	}
	if err := s.write(hosts, s.kdf, s.key); err != nil {
		return err
	}
	s.Hosts = hosts
	return nil
}

// readLatest decrypts the current file with the in-memory key.
func (s *Store) readLatest() ([]Host, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return append([]Host(nil), s.Hosts...), nil
	}
	if err != nil {
		return nil, err
	}
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil || e.Data == nil {
		return nil, ErrTampered
	}
	if !bytes.Equal(e.Salt, s.kdf.Salt) {
		return nil, ErrMasterChanged
	}
	hosts, err := decode(s.key, e)
	if errors.Is(err, ErrWrongPassword) {
		return nil, ErrTampered
	}
	return hosts, err
}

func decode(key []byte, e envelope) ([]Host, error) {
	plain, err := unseal(key, e.Nonce, e.Data)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var p payload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, ErrTampered
	}
	return p.Hosts, nil
}

func (s *Store) lockFile() (unlock func(), err error) {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return nil, err
	}
	fl := flock.New(s.path+".lock", flock.SetPermissions(0o600))
	ctx, cancel := context.WithTimeout(context.Background(), lockTimeout)
	defer cancel()
	ok, err := fl.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil || !ok {
		return nil, fmt.Errorf("hosts file is busy in another easessh window, try again: %v", err)
	}
	return func() { fl.Unlock() }, nil
}

// write encrypts hosts and replaces the file atomically with 0600 permissions.
func (s *Store) write(hosts []Host, kdf kdfParams, key []byte) error {
	plain, err := json.Marshal(payload{hosts})
	if err != nil {
		return err
	}
	nonce, ct, err := seal(key, plain)
	clear(plain)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(envelope{Version: 1, kdfParams: kdf, Nonce: nonce, Data: ct}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".hosts-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}

// Sorted returns hosts most-recently-used first, then alphabetically.
func (s *Store) Sorted() []Host {
	out := append([]Host(nil), s.Hosts...)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].LastUsed.Equal(out[j].LastUsed) {
			return out[i].LastUsed.After(out[j].LastUsed)
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

// ExpandPath expands a leading ~ to the home directory.
func ExpandPath(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}
