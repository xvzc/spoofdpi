package main

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// UI styling
var (
	logoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("2")).
		// Bold(false).
		MarginBottom(0)

	connsStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("255")).
			Bold(true).
			MarginLeft(26)

	spinnerFrames = []string{
		"⢀⠀", "⡀⠀", "⠄⠀", "⢂⠀", "⡂⠀", "⠅⠀", "⢃⠀", "⡃⠀", "⠍⠀", "⢋⠀", "⡋⠀", "⠍⠁", "⢋⠁", "⡋⠁",
		"⠍⠉", "⠋⠉", "⠋⠉", "⠉⠙", "⠉⠙", "⠉⠩", "⠈⢙", "⠈⡙", "⢈⠩", "⡀⢙", "⠄⡙", "⢂⠩", "⡂⢘", "⠅⡘",
		"⢃⠨", "⡃⢐", "⠍⡐", "⢋⠠", "⡋⢀", "⠍⡁", "⢋⠁", "⡋⠁", "⠍⠉", "⠋⠉", "⠋⠉", "⠉⠙", "⠉⠙", "⠉⠩",
		"⠈⢙", "⠈⡙", "⠈⠩", "⠀⢙", "⠀⡙", "⠀⠩", "⠀⢘", "⠀⡘", "⠀⠨", "⠀⢐", "⠀⡐", "⠀⠠", "⠀⢀", "⠀⡀",
	}
)

//go:embed logo.txt
var logo string

type (
	tickMsg time.Time
	logMsg  string
	// activeConnsMsg gives the model the count of the connections the
	// server is handling.
	activeConnsMsg func() int64
)

type model struct {
	viewport     viewport.Model
	spinner      spinner.Model
	logs         []string
	filteredLogs []string
	conns        string
	activeConns  func() int64
	ready        bool
	filterInput  string
	activeFilter string
	inputMode    bool

	readyChan chan struct{}
}

func formatConns(n int64) string {
	return fmt.Sprintf("active connections: %d", n)
}

func filterLogs(logs []string, filter string) []string {
	if filter == "" {
		return logs
	}
	var result []string
	for _, log := range logs {
		if strings.Contains(log, filter) {
			result = append(result, log)
		}
	}
	return result
}

func initialModel(readyChan chan struct{}) model {
	s := spinner.New()
	s.Spinner = spinner.Spinner{
		Frames: spinnerFrames,
		FPS:    time.Second / 25,
	}

	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("255"))

	return model{
		spinner:   s,
		logs:      []string{},
		conns:     formatConns(0),
		readyChan: readyChan,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		tickCmd(),
		m.spinner.Tick,
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		cmd  tea.Cmd
		cmds []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		key := msg.String()
		if msg.Type == tea.KeyCtrlC {
			return m, tea.Quit
		}

		switch key {
		case "enter":
			if m.inputMode {
				m.activeFilter = m.filterInput
				m.filteredLogs = filterLogs(m.logs, m.activeFilter)
				m.inputMode = false
				m.updateViewport()
			}
		case "esc":
			if m.inputMode {
				m.inputMode = false
				m.filterInput = ""
			} else if m.activeFilter != "" {
				m.activeFilter = ""
				m.filteredLogs = m.logs
				m.updateViewport()
			}
		case "backspace":
			if m.inputMode && len(m.filterInput) > 0 {
				m.filterInput = m.filterInput[:len(m.filterInput)-1]
			}
		case "R":
			if !m.inputMode {
				m.logs = []string{}
				m.filteredLogs = filterLogs(m.logs, m.activeFilter)
				m.updateViewport()
			} else {
				m.filterInput += msg.String()
			}
		case "f":
			if !m.inputMode {
				m.inputMode = true
				m.filterInput = ""
			} else {
				m.filterInput += msg.String()
			}
		default:
			if m.inputMode {
				m.filterInput += msg.String()
			}
		}

	case tea.WindowSizeMsg:
		headerHeight := lipgloss.Height(m.headerView())
		footerHeight := 1
		verticalMarginHeight := headerHeight + footerHeight

		if !m.ready {
			m.viewport = viewport.New(msg.Width, msg.Height-verticalMarginHeight)
			m.viewport.YPosition = headerHeight
			m.viewport.SetContent(strings.Join(m.logs, "\n"))
			m.ready = true
			if m.readyChan != nil {
				close(m.readyChan)
				m.readyChan = nil
			}
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = msg.Height - verticalMarginHeight
			m.updateViewport()
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)

	case activeConnsMsg:
		m.activeConns = msg
		m.conns = formatConns(m.activeConns())

	case tickMsg:
		if m.activeConns != nil {
			m.conns = formatConns(m.activeConns())
		}
		cmds = append(cmds, tickCmd())

	case logMsg:
		m.logs = append(m.logs, string(msg))

		if m.activeFilter == "" || strings.Contains(string(msg), m.activeFilter) {
			m.filteredLogs = append(m.filteredLogs, string(msg))
		}

		const maxLogs = 5000
		if len(m.logs) > maxLogs {
			m.logs = m.logs[len(m.logs)-maxLogs:]
		}
		if len(m.filteredLogs) > maxLogs {
			m.filteredLogs = m.filteredLogs[len(m.filteredLogs)-maxLogs:]
		}

		m.updateViewport()
	}

	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m *model) updateViewport() {
	if !m.ready {
		return
	}
	isAtBottom := m.viewport.AtBottom()
	// bubbles/viewport horizontally cuts lines wider than its width instead
	// of wrapping. Pre-wrap so each logical line fits and nothing gets
	// chopped off the right edge.
	width := m.viewport.Width
	if width <= 0 {
		width = 80
	}
	wrapped := make([]string, len(m.filteredLogs))
	for i, line := range m.filteredLogs {
		wrapped[i] = ansi.Hardwrap(line, width, false)
	}
	m.viewport.SetContent(strings.Join(wrapped, "\n"))
	if isAtBottom {
		m.viewport.GotoBottom()
	}
}

func (m model) headerView() string {
	logoView := logoStyle.Render(strings.TrimPrefix(logo, "\n"))

	connsText := fmt.Sprintf("%s %s", m.conns, m.spinner.View())
	connsView := connsStyle.Render(connsText)

	width := m.viewport.Width
	if width == 0 {
		width = 80 // fallback width before WindowSizeMsg
	}
	divider := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Render(strings.Repeat("─", width))

	return lipgloss.JoinVertical(lipgloss.Left, logoView, connsView, divider)
}

func (m model) footerView() string {
	if !m.ready {
		return ""
	}

	var left, right string
	var leftStyle, rightStyle lipgloss.Style

	keyStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("226")).
		Bold(true)

	descStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("249"))

	if m.inputMode {
		left = "filter: " + m.filterInput
		leftStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
		right = keyStyle.Render("enter") + " " + descStyle.Render("apply") + "  " +
			keyStyle.Render("esc") + " " + descStyle.Render("cancel")
		rightStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("82"))
	} else if m.activeFilter != "" {
		left = "filter: " + m.activeFilter
		leftStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
		right = keyStyle.Render("esc") + " unfilter  " +
			keyStyle.Render("f") + " filter  " +
			keyStyle.Render("R") + " clear  " +
			keyStyle.Render("^C") + " quit"
		rightStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("75"))
	} else {
		right = keyStyle.Render("f") + " filter  " +
			keyStyle.Render("R") + " clear  " +
			keyStyle.Render("^C") + " quit"
		rightStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("249"))
	}

	leftStr := leftStyle.Render(left)
	rightStr := rightStyle.Width(m.viewport.Width - lipgloss.Width(leftStr)).
		Align(lipgloss.Right).
		Render(right)

	return leftStr + rightStr
}

func (m model) View() string {
	if !m.ready {
		return "\n  Initializing..."
	}

	return fmt.Sprintf(
		"%s\n%s\n%s",
		m.headerView(),
		m.viewport.View(),
		m.footerView(),
	)
}

var p *tea.Program

type TUIWriter struct{}

func (TUIWriter) Write(b []byte) (n int, err error) {
	if p != nil {
		go p.Send(logMsg(strings.TrimSpace(string(b))))
	}
	return len(b), nil
}

// showActiveConns makes the TUI show the count that activeConns returns,
// updated every second. It does nothing without the TUI.
func showActiveConns(activeConns func() int64) {
	if p != nil {
		p.Send(activeConnsMsg(activeConns))
	}
}

func startTUI(cancel context.CancelFunc) error {
	readyChan := make(chan struct{})
	p = tea.NewProgram(initialModel(readyChan), tea.WithAltScreen())

	errChan := make(chan error, 1)

	go func() {
		defer cancel()
		_, err := p.Run()
		if err != nil {
			errChan <- err
		}
	}()

	select {
	case <-readyChan:
		return nil
	case err := <-errChan:
		return err
	}
}
