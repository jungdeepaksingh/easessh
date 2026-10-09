// Package tui is the host manager interface.
package tui

import (
	"fmt"
	"strings"
	"time"

	"easessh/internal/config"
	"easessh/internal/sshx"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type mode int

const (
	modeList mode = iota
	modeFilter
	modeForm
	modeConfirmDelete
	modeLocked
)

type sessionDoneMsg struct {
	host config.Host
	err  error
}

type tickMsg time.Time

// Options tune the manager's behaviour.
type Options struct {
	AutoLock time.Duration // lock after this much inactivity; 0 disables
}

type Model struct {
	store      *config.Store
	opts       Options
	lastActive time.Time
	inSession  bool
	lockInput  textinput.Model
	lockErr    string
	mode       mode
	hosts      []config.Host // filtered, sorted view
	cursor     int
	offset     int
	filter     textinput.Model
	form       *form
	status     string
	isErr      bool
	width      int
	height     int
}

func New(store *config.Store, opts Options) Model {
	fi := textinput.New()
	fi.Prompt = "/ "
	fi.Placeholder = "filter by name, user or host"
	li := textinput.New()
	li.Prompt = "🔒 Master password: "
	li.EchoMode = textinput.EchoPassword
	li.EchoCharacter = '•'
	m := Model{store: store, opts: opts, filter: fi, lockInput: li, width: 80, height: 24, lastActive: time.Now()}
	m.refresh()
	return m
}

func (m Model) Init() tea.Cmd { return m.tick() }

func (m Model) tick() tea.Cmd {
	if m.opts.AutoLock <= 0 {
		return nil
	}
	every := min(15*time.Second, m.opts.AutoLock)
	return tea.Tick(every, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// lock wipes decrypted data from memory and shows the lock screen.
func (m *Model) lock() tea.Cmd {
	m.store.Lock()
	m.hosts, m.form = nil, nil
	m.filter.SetValue("")
	m.filter.Blur()
	m.cursor, m.offset = 0, 0
	m.status, m.lockErr = "", ""
	m.mode = modeLocked
	m.lockInput.SetValue("")
	return m.lockInput.Focus()
}

func (m Model) updateLocked(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() != "enter" {
		var cmd tea.Cmd
		m.lockInput, cmd = m.lockInput.Update(msg)
		return m, cmd
	}
	pw := []byte(m.lockInput.Value())
	m.lockInput.SetValue("")
	err := m.store.Unlock(pw)
	clear(pw)
	if err != nil {
		m.lockErr = err.Error()
		return m, nil
	}
	m.lockInput.Blur()
	m.mode, m.lockErr = modeList, ""
	m.refresh()
	return m, nil
}

func (m *Model) refresh() {
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	m.hosts = m.hosts[:0]
	for _, h := range m.store.Sorted() {
		if q == "" || fuzzy(strings.ToLower(h.Name+" "+h.User+"@"+h.Host), q) {
			m.hosts = append(m.hosts, h)
		}
	}
	if m.cursor >= len(m.hosts) {
		m.cursor = max(0, len(m.hosts)-1)
	}
}

// fuzzy reports whether every whitespace-separated term is a subsequence of s.
func fuzzy(s, q string) bool {
	for _, t := range strings.Fields(q) {
		term := []rune(t)
		i := 0
		for _, r := range s {
			if i < len(term) && r == term[i] {
				i++
			}
		}
		if i < len(term) {
			return false
		}
	}
	return true
}

func (m *Model) setStatus(err bool, format string, a ...any) {
	m.status, m.isErr = fmt.Sprintf(format, a...), err
}

func (m *Model) selected() (config.Host, bool) {
	if m.cursor < len(m.hosts) {
		return m.hosts[m.cursor], true
	}
	return config.Host{}, false
}

func (m *Model) connect(h config.Host) tea.Cmd {
	m.setStatus(false, "connecting to %s…", h.Name)
	m.inSession = true
	return tea.Exec(&sshx.Session{Host: h}, func(err error) tea.Msg {
		return sessionDoneMsg{host: h, err: err}
	})
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := m.update(msg)
	nm := next.(Model)
	nm.scroll()
	return nm, cmd
}

// scroll keeps the cursor inside the visible window.
func (m *Model) scroll() {
	rows := m.listHeight()
	if m.cursor < m.offset {
		m.offset = m.cursor
	} else if m.cursor >= m.offset+rows {
		m.offset = m.cursor - rows + 1
	}
	m.offset = max(0, min(m.offset, len(m.hosts)-1))
}

func (m Model) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tickMsg:
		if m.mode != modeLocked && !m.inSession && time.Since(m.lastActive) >= m.opts.AutoLock {
			return m, tea.Batch(m.lock(), m.tick())
		}
		return m, m.tick()
	case sessionDoneMsg:
		m.inSession, m.lastActive = false, time.Now()
		if msg.err != nil {
			m.setStatus(true, "%s: %s", msg.host.Name, sshx.Explain(msg.host, msg.err))
		} else if err := m.store.Touch(msg.host.Name); err != nil {
			m.setStatus(true, "%v", err)
		} else {
			m.setStatus(false, "Connection to %s closed.", msg.host.Name)
			m.cursor, m.offset = 0, 0
		}
		m.refresh()
		return m, nil
	case tea.KeyMsg:
		m.lastActive = time.Now()
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "ctrl+l":
			if m.mode != modeLocked {
				return m, m.lock()
			}
		}
		switch m.mode {
		case modeLocked:
			return m.updateLocked(msg)
		case modeForm:
			return m.updateForm(msg)
		case modeConfirmDelete:
			return m.updateConfirm(msg)
		case modeFilter:
			return m.updateFilter(msg)
		default:
			return m.updateList(msg)
		}
	}
	return m, nil
}

func (m *Model) move(delta int) {
	if len(m.hosts) == 0 {
		return
	}
	m.cursor = min(max(m.cursor+delta, 0), len(m.hosts)-1)
}

func (m Model) updateList(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	// Fast typing or paste can deliver "/query" as one event.
	if msg.Type == tea.KeyRunes && len(msg.Runes) > 1 && msg.Runes[0] == '/' {
		m.mode = modeFilter
		m.filter.SetValue(string(msg.Runes[1:]))
		m.filter.CursorEnd()
		m.cursor = 0
		m.refresh()
		return m, m.filter.Focus()
	}
	switch key {
	case "q":
		return m, tea.Quit
	case "esc":
		m.filter.SetValue("")
		m.refresh()
	case "up", "k":
		m.move(-1)
	case "down", "j":
		m.move(1)
	case "pgup":
		m.move(-m.listHeight())
	case "pgdown":
		m.move(m.listHeight())
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.move(len(m.hosts))
	case "/":
		m.mode = modeFilter
		return m, m.filter.Focus()
	case "enter", "right", "l":
		if h, ok := m.selected(); ok {
			return m, m.connect(h)
		}
	case "a", "n":
		m.form = newForm(nil)
		m.mode = modeForm
		return m, textinput.Blink
	case "e":
		if h, ok := m.selected(); ok {
			m.form = newForm(&h)
			m.mode = modeForm
			return m, textinput.Blink
		}
	case "c":
		if h, ok := m.selected(); ok {
			h.Name += "-copy"
			m.form = newForm(&h)
			m.form.orig = ""
			m.mode = modeForm
			return m, textinput.Blink
		}
	case "d", "delete", "x":
		if _, ok := m.selected(); ok {
			m.mode = modeConfirmDelete
		}
	case "i":
		m.importSSHConfig()
	default:
		// 1-9: instant connect to the Nth visible host.
		if len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
			if i := m.offset + int(key[0]-'1'); i < len(m.hosts) {
				m.cursor = i
				return m, m.connect(m.hosts[i])
			}
		}
	}
	return m, nil
}

func (m Model) updateFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		// Keep the filter so the matches can be edited/deleted; esc again clears it.
		m.filter.Blur()
		m.mode = modeList
		return m, nil
	case "enter":
		m.filter.Blur()
		m.mode = modeList
		if h, ok := m.selected(); ok {
			return m, m.connect(h)
		}
		return m, nil
	case "up", "ctrl+p", "ctrl+k":
		m.move(-1)
		return m, nil
	case "down", "ctrl+n", "ctrl+j", "tab":
		m.move(1)
		return m, nil
	}
	var cmd tea.Cmd
	m.filter, cmd = m.filter.Update(msg)
	m.cursor, m.offset = 0, 0
	m.refresh()
	return m, cmd
}

func (m Model) updateForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		m.mode, m.form = modeList, nil
		return m, nil
	}
	cmd, submit := m.form.update(msg)
	if !submit {
		return m, cmd
	}
	h, err := m.form.host()
	if err == nil {
		err = m.store.Upsert(m.form.orig, h)
	}
	if err != nil {
		m.form.err = err.Error()
		return m, nil
	}
	m.setStatus(false, "Saved %s.", h.Name)
	m.mode, m.form = modeList, nil
	m.refresh()
	for i, x := range m.hosts {
		if x.Name == h.Name {
			m.cursor = i
		}
	}
	return m, nil
}

func (m Model) updateConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if h, ok := m.selected(); ok && (msg.String() == "y" || msg.String() == "Y") {
		if err := m.store.Delete(h.Name); err != nil {
			m.setStatus(true, "%v", err)
		} else {
			m.setStatus(false, "Deleted %s.", h.Name)
		}
		m.refresh()
	}
	m.mode = modeList
	return m, nil
}

func (m *Model) importSSHConfig() {
	found, err := config.ImportSSHConfig("~/.ssh/config")
	if err != nil {
		m.setStatus(true, "import: %v", err)
		return
	}
	added, err := m.store.AddMissing(found)
	if err != nil {
		m.setStatus(true, "import: %v", err)
	} else {
		m.setStatus(false, "Imported %d new host(s) from ~/.ssh/config (%d found).", added, len(found))
	}
	m.refresh()
}

// listHeight is the number of host rows that fit on screen.
func (m Model) listHeight() int {
	used := 6 // title, blank, filter, blank, status, help
	return max(1, m.height-used)
}

func (m Model) View() string {
	if m.mode == modeLocked {
		var b strings.Builder
		b.WriteString(titleStyle.Render("⚡ easessh") + "  " + dimStyle.Render("locked") + "\n\n")
		b.WriteString(m.lockInput.View() + "\n")
		if m.lockErr != "" {
			b.WriteString("\n" + errStyle.Render("✗ "+m.lockErr) + "\n")
		}
		b.WriteString("\n" + help("enter", "unlock", "ctrl+c", "quit"))
		return lipgloss.NewStyle().Padding(1, 2).Render(b.String())
	}
	if m.mode == modeForm {
		return lipgloss.NewStyle().Padding(1, 2).Render(m.form.view(m.width))
	}

	var b strings.Builder
	title := titleStyle.Render("⚡ easessh")
	count := dimStyle.Render(fmt.Sprintf("%d/%d hosts", len(m.hosts), len(m.store.Hosts)))
	gap := max(1, m.width-lipgloss.Width(title)-lipgloss.Width(count)-4)
	b.WriteString(title + strings.Repeat(" ", gap) + count + "\n\n")

	if m.mode == modeFilter || m.filter.Value() != "" {
		b.WriteString(m.filter.View() + "\n")
	} else {
		b.WriteString(dimStyle.Render("/ to filter") + "\n")
	}
	b.WriteString("\n")

	rows := m.listHeight()
	if len(m.store.Hosts) == 0 {
		b.WriteString(dimStyle.Render("No hosts yet. Press ") + keyStyle.Render("a") +
			dimStyle.Render(" to add one, or ") + keyStyle.Render("i") + dimStyle.Render(" to import ~/.ssh/config.") + "\n")
		rows--
	} else if len(m.hosts) == 0 {
		b.WriteString(dimStyle.Render("No matches.") + "\n")
		rows--
	}

	nameW := 4
	for _, h := range m.hosts {
		nameW = max(nameW, lipgloss.Width(h.Name))
	}
	nameW = min(nameW, 28)
	end := min(len(m.hosts), m.offset+rows)
	for i := m.offset; i < end; i++ {
		h := m.hosts[i]
		num := "  "
		if n := i - m.offset + 1; n <= 9 {
			num = fmt.Sprintf("%d ", n)
		}
		name := lipgloss.NewStyle().Width(nameW + 2).Render(truncate(h.Name, nameW))
		line := badgeStyle.Render(string(h.Auth)) + h.Target()
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("▸ "+num) + selectedStyle.Render(name) + line + "\n")
		} else {
			b.WriteString("  " + dimStyle.Render(num) + nameStyle.Render(name) + dimStyle.Render(line) + "\n")
		}
		rows--
	}
	b.WriteString(strings.Repeat("\n", max(0, rows)))

	switch {
	case m.mode == modeConfirmDelete:
		h, _ := m.selected()
		b.WriteString(errStyle.Render(fmt.Sprintf("Delete %s? ", h.Name)) + keyStyle.Render("y") + dimStyle.Render("/n") + "\n")
	case m.status != "" && m.isErr:
		b.WriteString(errStyle.Render("✗ "+truncate(m.status, max(10, m.width-6))) + "\n")
	case m.status != "":
		b.WriteString(okStyle.Render("✓ "+m.status) + "\n")
	default:
		b.WriteString("\n")
	}

	if m.mode == modeFilter {
		b.WriteString(help("↑/↓", "move", "enter", "connect", "esc", "done"))
	} else {
		b.WriteString(help("enter/1-9", "connect", "a", "add", "e", "edit", "c", "copy", "d", "delete", "i", "import", "ctrl+l", "lock", "q", "quit"))
	}
	return lipgloss.NewStyle().Padding(0, 1).Render(b.String())
}

func help(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, keyStyle.Render(pairs[i])+" "+dimStyle.Render(pairs[i+1]))
	}
	return strings.Join(parts, dimStyle.Render(" • "))
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:max(0, n-1)]) + "…"
}
