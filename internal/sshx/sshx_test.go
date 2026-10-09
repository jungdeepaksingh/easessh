package sshx

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"easessh/internal/config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const banner = "hello from test server"

type testServer struct {
	addr    *net.TCPAddr
	hostKey ssh.Signer
}

// startServer runs an in-process SSH server accepting tester/pw123 and the given key.
// Its shell prints a banner and exits with status 3 (a non-zero exit must not be an error).
func startServer(t *testing.T, authorized ssh.PublicKey) *testServer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.User() == "tester" && string(pw) == "pw123" {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if authorized != nil && bytes.Equal(k.Marshal(), authorized.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(hostKey)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn, cfg)
		}
	}()
	return &testServer{addr: ln.Addr().(*net.TCPAddr), hostKey: hostKey}
}

func serve(conn net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for req := range creqs {
				req.Reply(true, nil)
				if req.Type == "shell" {
					ch.Write([]byte(banner + "\n"))
					ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{3}))
					ch.Close()
					return
				}
			}
		}()
	}
}

func (s *testServer) host(auth config.AuthType) config.Host {
	return config.Host{Name: "t", Host: "127.0.0.1", Port: s.addr.Port, User: "tester", Auth: auth}
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// run connects with typed answers on stdin and returns the error and terminal output.
func run(t *testing.T, h config.Host, input string) (error, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w.WriteString(input)
	w.Close()
	out := &syncBuf{}
	err = Run(h, r, out)
	return err, out.String()
}

func isolateHome(t *testing.T) string {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	return home
}

func TestPasswordLoginTrustsNewHostOnce(t *testing.T) {
	home := isolateHome(t)
	srv := startServer(t, nil)
	h := srv.host(config.AuthPassword)
	h.Password = "pw123"

	err, out := run(t, h, "yes\n")
	if err != nil || !strings.Contains(out, banner) || !strings.Contains(out, "authenticity") {
		t.Fatalf("first login: err=%v out=%q", err, out)
	}
	kh, _ := os.ReadFile(filepath.Join(home, ".ssh", "known_hosts"))
	if !strings.HasPrefix(string(kh), "|1|") || strings.Contains(string(kh), "127.0.0.1") {
		t.Errorf("known_hosts entry not hashed: %q", kh)
	}

	err, out = run(t, h, "")
	if err != nil || strings.Contains(out, "authenticity") || !strings.Contains(out, banner) {
		t.Fatalf("second login should not prompt: err=%v out=%q", err, out)
	}
}

func TestPasswordPromptRetries(t *testing.T) {
	isolateHome(t)
	srv := startServer(t, nil)
	err, out := run(t, srv.host(config.AuthPassword), "yes\nwrong\npw123\n")
	if err != nil || strings.Count(out, "password:") != 2 || !strings.Contains(out, banner) {
		t.Fatalf("err=%v out=%q", err, out)
	}
}

func TestWrongPasswordExplained(t *testing.T) {
	isolateHome(t)
	srv := startServer(t, nil)
	h := srv.host(config.AuthPassword)
	h.Password = "nope"
	err, _ := run(t, h, "yes\nx\nx\nx\nx\nx\n")
	if err == nil || !strings.Contains(Explain(h, err), "authentication failed") {
		t.Fatalf("err=%v explained=%q", err, Explain(h, err))
	}

	err, _ = run(t, srv.host(config.AuthPassword), "") // EOF at the host key prompt
	if err == nil || !strings.Contains(Explain(h, err), "cancelled") {
		t.Errorf("EOF: %q", Explain(h, err))
	}
}

func TestEncryptedKeyLogin(t *testing.T) {
	home := isolateHome(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("secretpp"))
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, "id_test")
	os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600)
	sshPub, _ := ssh.NewPublicKey(pub)
	srv := startServer(t, sshPub)

	h := srv.host(config.AuthKey)
	h.KeyPath = keyPath
	h.Passphrase = "secretpp"
	if err, out := run(t, h, "yes\n"); err != nil || !strings.Contains(out, banner) {
		t.Fatalf("saved passphrase: err=%v out=%q", err, out)
	}

	h.Passphrase = ""
	if err, out := run(t, h, "bad\nsecretpp\n"); err != nil || !strings.Contains(out, "Bad passphrase") {
		t.Fatalf("prompted passphrase: err=%v out=%q", err, out)
	}

	h.KeyPath = filepath.Join(home, "missing")
	if err, _ := run(t, h, ""); err == nil || !strings.Contains(Explain(h, err), "key file not found") {
		t.Errorf("missing key: %v", err)
	}
}

func TestChangedHostKeyRefused(t *testing.T) {
	home := isolateHome(t)
	srv := startServer(t, nil)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherSigner, _ := ssh.NewSignerFromKey(other)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(srv.addr.Port))
	os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
	line := knownhosts.Line([]string{knownhosts.Normalize(addr)}, otherSigner.PublicKey())
	os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(line+"\n"), 0o600)

	h := srv.host(config.AuthPassword)
	h.Password = "pw123"
	err, out := run(t, h, "yes\n")
	var changed *HostKeyChangedError
	if !errors.As(err, &changed) || strings.Contains(out, banner) {
		t.Fatalf("connected despite changed key: err=%v out=%q", err, out)
	}
	if !strings.Contains(Explain(h, err), "CHANGED") {
		t.Errorf("explain: %q", Explain(h, err))
	}
}

func TestConnectionRefusedExplained(t *testing.T) {
	isolateHome(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	h := config.Host{Name: "t", Host: "127.0.0.1", Port: port, User: "x", Auth: config.AuthPassword, Password: "x"}
	err, _ := run(t, h, "")
	if !strings.Contains(Explain(h, err), "connection refused") {
		t.Errorf("explain: %q", Explain(h, err))
	}
}

// blackholeProxy forwards TCP traffic until frozen, then silently drops it,
// like a network that went away without closing the connection.
func blackholeProxy(t *testing.T, target string) (addr string, freeze func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var frozen atomic.Bool
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if !frozen.Load() {
				dst.Write(buf[:n])
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				return
			}
			t.Cleanup(func() { c.Close(); up.Close() })
			go pipe(up, c)
			go pipe(c, up)
		}
	}()
	return ln.Addr().String(), func() { frozen.Store(true) }
}

func TestKeepaliveDropsDeadConnection(t *testing.T) {
	isolateHome(t)
	oldI, oldT := keepaliveInterval, keepaliveTimeout
	keepaliveInterval, keepaliveTimeout = 50*time.Millisecond, 300*time.Millisecond
	t.Cleanup(func() { keepaliveInterval, keepaliveTimeout = oldI, oldT })

	srv := startServer(t, nil)
	addr, freeze := blackholeProxy(t, srv.addr.String())
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "tester",
		Auth:            []ssh.AuthMethod{ssh.Password("pw123")},
		HostKeyCallback: ssh.FixedHostKey(srv.hostKey.PublicKey()),
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	defer close(done)
	go keepalive(client, done)

	closed := make(chan struct{})
	go func() { client.Wait(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("healthy connection was closed")
	case <-time.After(400 * time.Millisecond):
	}

	freeze()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("dead connection was not closed by keepalive")
	}
}
