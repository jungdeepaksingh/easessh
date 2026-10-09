package tui

import (
	"testing"

	"easessh/internal/config"
)

func TestFormHostShortcut(t *testing.T) {
	f := newForm(nil)
	f.auth = 2 // agent: no key file check
	f.inputs[fHost].SetValue("root@10.0.0.9:2022")
	h, err := f.host()
	if err != nil {
		t.Fatal(err)
	}
	if h.Name != "10.0.0.9" || h.Host != "10.0.0.9" || h.User != "root" || h.Port != 2022 {
		t.Errorf("got %+v", h)
	}

	f.inputs[fHost].SetValue("[::1]")
	if h, _ := f.host(); h.Host != "::1" || h.Port != 22 {
		t.Errorf("ipv6: %+v", h)
	}
	f.inputs[fHost].SetValue("[fe80::1]:2200")
	if h, _ := f.host(); h.Host != "fe80::1" || h.Port != 2200 {
		t.Errorf("ipv6 with port: %+v", h)
	}
	f.inputs[fHost].SetValue("fe80::1")
	if h, _ := f.host(); h.Host != "fe80::1" || h.Port != 22 {
		t.Errorf("bare ipv6: %+v", h)
	}
	f.inputs[fHost].SetValue("h")
	f.inputs[fPort].SetValue("99999")
	if _, err := f.host(); err == nil {
		t.Error("bad port accepted")
	}
}

func TestFormEditHostPortOverridesPortField(t *testing.T) {
	h := config.Host{Name: "x", Host: "old", Port: 22, Auth: config.AuthAgent}
	f := newForm(&h)
	f.inputs[fHost].SetValue("new:2222")
	got, err := f.host()
	if err != nil || got.Host != "new" || got.Port != 2222 {
		t.Errorf("got %+v %v", got, err)
	}
}

func TestFuzzy(t *testing.T) {
	for _, c := range []struct {
		s, q string
		want bool
	}{{"prod-web ubuntu@10.0.0.1", "pw", true}, {"prod-web ubuntu@10.0.0.1", "web 10.0", true}, {"db root@db", "web", false}} {
		if got := fuzzy(c.s, c.q); got != c.want {
			t.Errorf("fuzzy(%q,%q)=%v", c.s, c.q, got)
		}
	}
}
