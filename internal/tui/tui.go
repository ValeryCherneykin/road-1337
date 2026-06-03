// Package tui implements the road-1337 terminal user interface using the
// Bubble Tea framework (The Elm Architecture). It utilizes lipgloss for
// advanced terminal layout orchestration and components from the bubbles universe.
package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Message encapsulates an immutable entry within the conversation history buffer.
type Message struct {
	Content   string
	IsMine    bool
	Timestamp time.Time
}

// Model coordinates the internal state, sub-component states, and execution
// context for the terminal user interface event loop.
type Model struct {
	viewport   viewport.Model
	textarea   textarea.Model
	messages   []Message
	peerPubKey string
	width      int
	height     int
	ready      bool
}

// Global UI style definitions using the Lipgloss functional styling layout engine.
// Color schemas follow a high-contrast cyberpunk / Dracula architectural theme.
var (
	primary = lipgloss.Color("#A855F7") // Neon Purple theme anchor

	sentStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E0E7FF")).
			Background(lipgloss.Color("#6D28D9")).
			Padding(0, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primary)

	receivedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E0E7FF")).
			Background(lipgloss.Color("#334155")).
			Padding(0, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#64748B"))

	tsStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#94A3B8")).
		Italic(true)
)

// New provisions a zero-state Model initialized with default viewport settings,
// custom text input behaviors, and safe placeholder histories.
func New(peerPubKey string) Model {
	ta := textarea.New()
	ta.Placeholder = "Напиши сообщение... (/file /exit)"
	ta.Focus()
	ta.ShowLineNumbers = false
	ta.KeyMap.InsertNewline.SetEnabled(false) // Intercept Enter key to trigger dispatch instead of line insertion
	ta.SetHeight(3)

	// TODO Sprint 3: Replace initialDemoChat seed with persistent structural local storage logs
	initialMessages := []Message{
		{Content: "Hi!", IsMine: false, Timestamp: time.Now().Add(-5 * time.Minute)},
		{Content: "How are you?", IsMine: true, Timestamp: time.Now().Add(-3 * time.Minute)},
		{Content: "I'm hacker", IsMine: false, Timestamp: time.Now().Add(-1 * time.Minute)},
	}

	m := Model{
		textarea:   ta,
		messages:   initialMessages,
		peerPubKey: peerPubKey,
	}

	return m
}

// Init acts as the formal structural constructor for structural initialization routines.
// Returns an initial asynchronous command to start the text cursor blinking cycle.
func (m Model) Init() tea.Cmd {
	return textarea.Blink
}

// Update acts as the pure state-transition function, receiving messages (events)
// and modifying the internal Model state accordingly.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		tiCmd tea.Cmd
		vpCmd tea.Cmd
		cmds  []tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		// Establish structural defensive boundaries against terminal extreme down-sizing
		vpWidth := msg.Width - 4
		if vpWidth < 20 {
			vpWidth = 20
		}
		vpHeight := msg.Height - 7
		if vpHeight < 3 {
			vpHeight = 3
		}

		// Lazy initialization pattern ensuring component generation only when window dimensions are available
		if !m.ready {
			m.viewport = viewport.New(vpWidth, vpHeight)
			m.ready = true
		} else {
			m.viewport.Width = vpWidth
			m.viewport.Height = vpHeight
		}

		m.textarea.SetWidth(vpWidth)
		m.viewport.SetContent(m.renderMessages())
		m.viewport.GotoBottom()

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit

		case "enter":
			text := strings.TrimSpace(m.textarea.Value())
			if text == "" {
				break
			}

			// Intercept interceptable system-level CLI commands
			if strings.HasPrefix(text, "/exit") {
				return m, tea.Quit // Soft teardown: Bubble Tea automatically restores terminal state and exits the AltScreen
			}

			// TODO Sprint 3: Dispatch raw 'text' to the background crypt-network pipeline outChan prior to local rendering
			m.messages = append(m.messages, Message{
				Content:   text,
				IsMine:    true,
				Timestamp: time.Now(),
			})

			m.viewport.SetContent(m.renderMessages())
			m.textarea.Reset()
			m.viewport.GotoBottom() // Enforce structural auto-scroll anchoring to track conversation velocity
		}
	}

	// Propagate updates to encapsulated state components to preserve cursor animations, text entries, and touch motions
	m.textarea, tiCmd = m.textarea.Update(msg)
	cmds = append(cmds, tiCmd)

	m.viewport, vpCmd = m.viewport.Update(msg)
	cmds = append(cmds, vpCmd)

	return m, tea.Batch(cmds...)
}

// renderMessages flattens the structural message log slice into a single string.
// Note: This allocation pattern is optimized for transient development cycles.
// TODO Optimization: Transition to block-based index tracking to avoid O(N) allocation loops on large histories.
func (m Model) renderMessages() string {
	var sb strings.Builder
	for _, msg := range m.messages {
		ts := msg.Timestamp.Format("15:04")
		timeRendered := tsStyle.Render(ts)

		if msg.IsMine {
			bubble := sentStyle.Render(msg.Content)
			content := lipgloss.JoinVertical(lipgloss.Right, bubble, timeRendered)
			// Pad structural rows dynamically to fit the target viewport to enforce strict right alignment behaviors
			row := lipgloss.NewStyle().Width(m.viewport.Width).Align(lipgloss.Right).Render(content)
			sb.WriteString(row + "\n\n")
		} else {
			bubble := receivedStyle.Render(msg.Content)
			content := lipgloss.JoinVertical(lipgloss.Left, bubble, timeRendered)
			row := lipgloss.NewStyle().Width(m.viewport.Width).Align(lipgloss.Left).Render(content)
			sb.WriteString(row + "\n\n")
		}
	}
	return sb.String()
}

// View serializes the state vectors into the final text-based UI canvas string layer.
func (m Model) View() string {
	if !m.ready {
		return "Загрузка красивого интерфейса..."
	}

	shortKey := safePrefix(m.peerPubKey, 16)

	// Top banner component layout
	header := lipgloss.NewStyle().
		Background(primary).
		Foreground(lipgloss.Color("#FFFFFF")).
		Bold(true).
		Width(m.width).
		Padding(0, 1).
		Render(fmt.Sprintf(" road-1337  •  peer: %s...", shortKey))

	// Central conversation log structural padding wrapper
	chatContainer := lipgloss.NewStyle().Padding(0, 2).Render(m.viewport.View())

	// Bottom persistent input console zone
	inputContainer := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(primary).
		Margin(0, 2).
		Render(m.textarea.View())

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		chatContainer,
		inputContainer,
	)
}

// safePrefix returns the first n bytes of string s safely without out-of-bounds slicing threats.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
