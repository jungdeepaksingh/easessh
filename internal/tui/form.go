package tui

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"easessh/internal/config"
	"easessh/internal/sshx"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type field int

const (
	fName field = iota
	fHost
	fPort
	fUser
	fAuth
	fPassword
	fKey
	fPassphrase
	fieldCount
)

var fieldLabels = [fieldCount]string{"Name", "Host", "Port", "User", "Auth", "Password", "Key file", "Passphrase"}

type form struct {
	orig   string // name being edited; "" when adding
	inputs [fieldCount]textinput.Model
	auth   int // index into config.AuthTypes
	focus  int // index into visible()
	err    string
}

func newForm(h *config.Host) *form {
	f := &form{}
	placeholders := [fieldCount]string{
		"prod-web (defaults to host)", "10.0.0.5 or user@host:port", "22", os.Getenv("USER"), "",
		"blank = ask on connect", sshx.DefaultKeyPath(), "blank = ask if needed",
	}
	for i := range f.inputs {
		ti := textinput.New()
		ti.Prompt = ""
		ti.Placeholder = placeholders[i]
		ti.CharLimit = 512
		ti.Width = 48
		if field(i) == fPassword || field(i) == fPassphrase {
			ti.EchoMode = textinput.EchoPassword
			ti.EchoCharacter = '•'
		}
		f.inputs[i] = ti
	}
	if h != nil {
		f.orig = h.Name
		f.inputs[fName].SetValue(h.Name)
		f.inputs[fHost].SetValue(h.Host)
		f.inputs[fPort].SetValue(strconv.Itoa(h.Port))
		f.inputs[fUser].SetValue(h.User)
		f.inputs[fPassword].SetValue(h.Password)
		f.inputs[fKey].SetValue(h.KeyPath)
		f.inputs[fPassphrase].SetValue(h.Passphrase)
		for i, a := range config.AuthTypes {
			if a == h.Auth {
				f.auth = i
			}
		}
	}
	f.setFocus(0)
	return f
}

func (f *form) visible() []field {
	fs := []field{fName, fHost, fPort, fUser, fAuth}
	switch config.AuthTypes[f.auth] {
	case config.AuthPassword:
		fs = append(fs, fPassword)
	case config.AuthKey:
		fs = append(fs, fKey, fPassphrase)
	}
	return fs
}

func (f *form) current() field { return f.visible()[f.focus] }

func (f *form) setFocus(i int) tea.Cmd {
	vis := f.visible()
	f.focus = (i + len(vis)) % len(vis)
	for j := range f.inputs {
		f.inputs[j].Blur()
	}
	if c := f.current(); c != fAuth {
		return f.inputs[c].Focus()
	}
	return nil
}

// update returns submit=true when the user asks to save.
func (f *form) update(msg tea.KeyMsg) (cmd tea.Cmd, submit bool) {
	switch msg.String() {
	case "ctrl+s":
		return nil, true
	case "tab", "down":
		return f.setFocus(f.focus + 1), false
	case "shift+tab", "up":
		return f.setFocus(f.focus - 1), false
	case "enter":
		if f.focus == len(f.visible())-1 {
			return nil, true
		}
		return f.setFocus(f.focus + 1), false
	}
	if f.current() == fAuth {
		n := len(config.AuthTypes)
		switch msg.String() {
		case "left", "h":
			f.auth = (f.auth - 1 + n) % n
		case "right", "l", " ":
			f.auth = (f.auth + 1) % n
		case "p":
			f.auth = 0
		case "k":
			f.auth = 1
		case "a":
			f.auth = 2
		}
		return nil, false
	}
	var c tea.Cmd
	f.inputs[f.current()], c = f.inputs[f.current()].Update(msg)
	return c, false
}

func (f *form) value(fl field) string { return strings.TrimSpace(f.inputs[fl].Value()) }

// host validates the form. It accepts "user@host:port" in the host field as a shortcut.
func (f *form) host() (config.Host, error) {
	h := config.Host{
		Name:    f.value(fName),
		Host:    f.value(fHost),
		User:    f.value(fUser),
		Auth:    config.AuthTypes[f.auth],
		Port:    22,
		KeyPath: f.value(fKey),
	}
	if at := strings.LastIndex(h.Host, "@"); at >= 0 {
		if h.User == "" {
			h.User = h.Host[:at]
		}
		h.Host = h.Host[at+1:]
	}
	portStr := f.value(fPort)
	// host:port and [ipv6]:port; a bare IPv6 address has several colons and no brackets.
	// A port typed into the host field wins over the (possibly pre-filled) port field.
	if strings.HasPrefix(h.Host, "[") || strings.Count(h.Host, ":") == 1 {
		if host, port, err := net.SplitHostPort(h.Host); err == nil {
			h.Host, portStr = host, port
		}
	}
	h.Host = strings.Trim(h.Host, "[]")
	if h.Host == "" {
		return h, errors.New("host is required")
	}
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return h, fmt.Errorf("invalid port %q", portStr)
		}
		h.Port = p
	}
	if h.Name == "" {
		h.Name = h.Host
	}
	switch h.Auth {
	case config.AuthPassword:
		h.Password = f.inputs[fPassword].Value()
		h.KeyPath = ""
	case config.AuthKey:
		h.Passphrase = f.inputs[fPassphrase].Value()
		path := h.KeyPath
		if path == "" {
			path = sshx.DefaultKeyPath()
		}
		if _, err := os.Stat(config.ExpandPath(path)); err != nil {
			return h, fmt.Errorf("key file not found: %s", path)
		}
	default:
		h.KeyPath = ""
	}
	return h, nil
}

func (f *form) view(width int) string {
	var b strings.Builder
	title := "Add host"
	if f.orig != "" {
		title = "Edit " + f.orig
	}
	b.WriteString(titleStyle.Render(title) + "\n\n")
	for i, fl := range f.visible() {
		label := labelStyle
		if i == f.focus {
			label = focusLabel
		}
		b.WriteString(label.Render(fieldLabels[fl]))
		if fl == fAuth {
			var opts []string
			for j, a := range config.AuthTypes {
				s := " " + string(a) + " "
				if j == f.auth {
					if i == f.focus {
						s = titleStyle.Render(string(a))
					} else {
						s = selectedStyle.Render(s)
					}
				} else {
					s = dimStyle.Render(s)
				}
				opts = append(opts, s)
			}
			b.WriteString(strings.Join(opts, " "))
			if i == f.focus {
				b.WriteString(dimStyle.Render("  ←/→"))
			}
		} else {
			b.WriteString(f.inputs[fl].View())
		}
		b.WriteString("\n")
	}
	if config.AuthTypes[f.auth] == config.AuthAgent {
		b.WriteString(dimStyle.Render("\n            Uses ssh-agent and unencrypted ~/.ssh/id_* keys.") + "\n")
	}
	if f.err != "" {
		b.WriteString("\n" + errStyle.Render("✗ "+f.err) + "\n")
	}
	b.WriteString("\n" + help("tab", "next", "shift+tab", "prev", "enter", "next/save", "ctrl+s", "save", "esc", "cancel"))
	return b.String()
}
