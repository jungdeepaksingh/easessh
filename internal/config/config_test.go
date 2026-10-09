package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestImportSSHConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	os.WriteFile(p, []byte(`Host *
  User ignored
Host web1 web2
  HostName 10.1.1.1
  User deploy
  Port 2200
  IdentityFile "~/.ssh/k"
Match host x
  User nope
Host bastion
  HostName=bastion.example.com
`), 0o600)
	hosts, err := ImportSSHConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 3 {
		t.Fatalf("got %d hosts: %+v", len(hosts), hosts)
	}
	w := hosts[1]
	if w.Name != "web2" || w.Host != "10.1.1.1" || w.User != "deploy" || w.Port != 2200 || w.Auth != AuthKey || w.KeyPath != "~/.ssh/k" {
		t.Errorf("web2 = %+v", w)
	}
	if b := hosts[2]; b.Host != "bastion.example.com" || b.Auth != AuthAgent || b.Port != 22 {
		t.Errorf("bastion = %+v", b)
	}
}

func TestImportSSHConfigMergesAndExpands(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	os.WriteFile(p, []byte(`Host db
  Port 2201
Host db app
  HostName %h.corp.example
  Port 9999
  IdentityFile %d/.ssh/id_%h
Host db
  User late
  HostName ignored
`), 0o600)
	hosts, err := ImportSSHConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("got %d hosts: %+v", len(hosts), hosts)
	}
	db, app := hosts[0], hosts[1]
	if db.Host != "db.corp.example" || db.Port != 2201 || db.User != "late" || db.KeyPath != "~/.ssh/id_db" {
		t.Errorf("db = %+v", db)
	}
	if app.Host != "app.corp.example" || app.Port != 9999 {
		t.Errorf("app = %+v", app)
	}
}

func newStore(t *testing.T, master string) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sub", "hosts.json")
	s, err := Load(p, []byte(master))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestStoreEncryptedRoundTrip(t *testing.T) {
	master := []byte("correct horse")
	s, p := newStore(t, string(master))
	if err := s.Upsert("", Host{Name: "a", Host: "secret-host.internal", Port: 22, Auth: AuthPassword, Password: "hunter2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Upsert("", Host{Name: "a"}); err == nil {
		t.Error("duplicate name accepted")
	}
	if err := s.Touch("a"); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(p)
	for _, leak := range []string{"hunter2", "secret-host", `"a"`} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Errorf("file leaks %q", leak)
		}
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("perm = %v", fi.Mode().Perm())
	}
	if st, _ := Probe(p); st != StateEncrypted {
		t.Errorf("probe = %v", st)
	}
	if _, err := Load(p, []byte("wrong password")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password: err = %v", err)
	}

	s2, err := Load(p, master)
	if err != nil || len(s2.Hosts) != 1 || s2.Hosts[0].Password != "hunter2" || s2.Hosts[0].Uses != 1 {
		t.Fatalf("reload = %+v, %v", s2, err)
	}
	if err := s2.Upsert("a", Host{Name: "b", Host: "h2", Port: 22}); err != nil || s2.Hosts[0].Uses != 1 {
		t.Errorf("rename lost usage stats: %+v %v", s2.Hosts, err)
	}

	if err := s2.ChangeMaster([]byte("new master pw")); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p, master); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("old password still works: %v", err)
	}
	if s3, err := Load(p, []byte("new master pw")); err != nil || s3.Hosts[0].Name != "b" {
		t.Errorf("new password: %+v %v", s3, err)
	}
}

func TestConcurrentInstancesKeepEachOthersEdits(t *testing.T) {
	a, p := newStore(t, "master-pw")
	b, err := Load(p, []byte("master-pw"))
	if err != nil {
		t.Fatal(err)
	}
	// Both windows start from the same (empty) snapshot.
	if err := a.Upsert("", Host{Name: "from-a", Host: "a", Port: 22}); err != nil {
		t.Fatal(err)
	}
	if err := b.Upsert("", Host{Name: "from-b", Host: "b", Port: 22}); err != nil {
		t.Fatal(err)
	}
	if err := a.Touch("from-b"); err != nil {
		t.Fatal(err)
	}
	final, _ := Load(p, []byte("master-pw"))
	if len(final.Hosts) != 2 || final.Hosts[1].Uses != 1 {
		t.Errorf("lost an edit: %+v", final.Hosts)
	}

	if err := a.ChangeMaster([]byte("changed-pw")); err != nil {
		t.Fatal(err)
	}
	if err := b.Delete("from-a"); !errors.Is(err, ErrMasterChanged) {
		t.Errorf("stale instance wrote after password change: %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	s, p := newStore(t, "master-pw")
	s.Upsert("", Host{Name: "x", Host: "x", Port: 22})
	raw, _ := os.ReadFile(p)
	var e envelope
	json.Unmarshal(raw, &e)
	e.Data[0] ^= 1
	raw, _ = json.Marshal(e)
	os.WriteFile(p, raw, 0o600)
	if err := s.Touch("x"); !errors.Is(err, ErrTampered) {
		t.Errorf("tampering not detected: %v", err)
	}
}

func TestLockUnlock(t *testing.T) {
	s, _ := newStore(t, "master-pw")
	s.Upsert("", Host{Name: "x", Host: "x", Port: 22})
	s.Lock()
	if !s.Locked() || s.Hosts != nil {
		t.Fatal("lock kept data")
	}
	if err := s.Touch("x"); !errors.Is(err, ErrLocked) {
		t.Errorf("write while locked: %v", err)
	}
	if err := s.Unlock([]byte("nope")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("unlock wrong: %v", err)
	}
	if err := s.Unlock([]byte("master-pw")); err != nil || len(s.Hosts) != 1 {
		t.Errorf("unlock: %v %+v", err, s.Hosts)
	}
}

func TestMigratePlain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hosts.json")
	os.WriteFile(p, []byte(`{"hosts":[{"name":"old","host":"h","port":22,"auth":"password","password":"pw"}]}`), 0o600)
	if st, _ := Probe(p); st != StatePlain {
		t.Fatalf("probe = %v", st)
	}
	s, err := Load(p, []byte("migrate-me"))
	if err != nil || len(s.Hosts) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if st, _ := Probe(p); st != StateEncrypted {
		t.Errorf("not encrypted after save: %v", st)
	}
	if s2, err := Load(p, []byte("migrate-me")); err != nil || s2.Hosts[0].Password != "pw" {
		t.Errorf("%+v %v", s2, err)
	}
}
