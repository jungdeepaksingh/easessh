package tui

import "github.com/charmbracelet/lipgloss"

var (
	accent = lipgloss.AdaptiveColor{Light: "#5A3FD9", Dark: "#9D8CFF"}
	subtle = lipgloss.AdaptiveColor{Light: "#8A8A8A", Dark: "#6C6C6C"}
	good   = lipgloss.AdaptiveColor{Light: "#1A7F37", Dark: "#56D364"}
	bad    = lipgloss.AdaptiveColor{Light: "#CF222E", Dark: "#FF7B72"}

	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(accent).Padding(0, 1)
	dimStyle      = lipgloss.NewStyle().Foreground(subtle)
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(accent)
	nameStyle     = lipgloss.NewStyle().Bold(true)
	okStyle       = lipgloss.NewStyle().Foreground(good)
	errStyle      = lipgloss.NewStyle().Foreground(bad)
	labelStyle    = lipgloss.NewStyle().Width(12).Foreground(subtle)
	focusLabel    = labelStyle.Foreground(accent).Bold(true)
	badgeStyle    = lipgloss.NewStyle().Foreground(subtle).Width(9)
	keyStyle      = lipgloss.NewStyle().Foreground(accent).Bold(true)
)
