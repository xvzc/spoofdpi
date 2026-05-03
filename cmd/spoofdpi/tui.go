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
	"github.com/xvzc/spoofdpi/internal/netutil"
)

// UI styling
var (
	logoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00ff00")).
			Bold(true).
			MarginBottom(0)

	speedStyle = lipgloss.NewStyle().
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
)

type model struct {
	viewport     viewport.Model
	spinner      spinner.Model
	logs         []string
	filteredLogs []string
	speed        string
	lastTxBytes  uint64
	lastRxBytes  uint64
	lastTickTime time.Time
	avgUpSpeed   float64
	avgDownSpeed float64
	ready        bool
	filterInput  string
	activeFilter string
	inputMode    bool

	readyChan chan struct{}
}

func formatSpeed(up, down float64) string {
	return fmt.Sprintf("↑ %8.1f KB/s ┆ ↓ %8.1f KB/s", up, down)
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

	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("119"))

	return model{
		spinner:      s,
		logs:         []string{},
		speed:        formatSpeed(0, 0),
		lastTickTime: time.Now(),
		readyChan:    readyChan,
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
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
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

	case tickMsg:
		now := time.Time(msg)
		elapsed := now.Sub(m.lastTickTime).Seconds()
		if elapsed <= 0.0 {
			elapsed = 1.0
		}

		currentRx := netutil.GetRxBytes()
		currentTx := netutil.GetTxBytes()

		rawUpSpeed := (float64(currentTx-m.lastTxBytes) / 1024.0) / elapsed
		rawDownSpeed := (float64(currentRx-m.lastRxBytes) / 1024.0) / elapsed

		m.lastRxBytes = currentRx
		m.lastTxBytes = currentTx
		m.lastTickTime = now

		alpha := 0.3
		m.avgUpSpeed = (rawUpSpeed * alpha) + (m.avgUpSpeed * (1 - alpha))
		m.avgDownSpeed = (rawDownSpeed * alpha) + (m.avgDownSpeed * (1 - alpha))

		m.speed = formatSpeed(m.avgUpSpeed, m.avgDownSpeed)
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

	speedText := fmt.Sprintf("%s %s", m.speed, m.spinner.View())
	speedView := speedStyle.Render(speedText)

	width := m.viewport.Width
	if width == 0 {
		width = 80 // fallback width before WindowSizeMsg
	}
	divider := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Render(strings.Repeat("─", width))

	return lipgloss.JoinVertical(lipgloss.Left, logoView, speedView, divider)
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
