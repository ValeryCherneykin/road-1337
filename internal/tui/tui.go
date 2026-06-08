// Package tui implements the road-1337 terminal user interface.
//
// Built on Bubble Tea (The Elm Architecture) + Lipgloss for layout.
// Visual design: Telegram-style chat bubbles, cyberpunk purple palette.
//
// Architecture:
//
// Network goroutines → incoming chan (buffered 64) → waitForNetwork() Cmd → Update()
// Update() (Enter) → outgoing chan (buffered 32) → sendLoop goroutine
//
// Shutdown contract:
//
// PeerDisconnectedMsg received → Update returns tea.Quit immediately.
// User types /exit or Ctrl+C → /exit sent to sendLoop → sendLoop calls
// Zeroize() then tea.Quit is returned.
//
// Performance notes:
// - renderHistory() is called only when history changes, not on every frame.
// - All Lipgloss styles are pre-allocated package-level vars (zero alloc at render time).
// - viewport.SetContent is the only expensive call; guarded by dirty flag pattern.
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

// ── Constants ─────────────────────────────────────────────────────────────────

const maxMessageHistory = 100 // Prevents UI lag and memory leaks during long sessions

// ── Network event types ───────────────────────────────────────────────────────
// These are written by client goroutines and read by Update() via waitForNetwork().

// IncomingTextMsg carries a decrypted text message from the peer.
type IncomingTextMsg struct{ Text string }

// IncomingFileMsg signals a file transfer event (started, progress, or completed).
type IncomingFileMsg struct {
	Text string // filename
	Meta string // e.g. "N KB received ✓", "Sending..."
}

// FileProgressMsg updates the live transfer progress bar.
// An empty Status clears the bar.
type FileProgressMsg struct{ Status string }

// PeerDisconnectedMsg signals the peer has disconnected (gracefully or by error).
// Receiving this causes Update() to return tea.Quit.
type PeerDisconnectedMsg struct{}

// StatusMsg updates the status indicator in the header bar.
type StatusMsg struct{ Text string }

// ── Palette ───────────────────────────────────────────────────────────────────
// All colors are 24-bit hex for true-color terminals.
// Derived from a neon purple base (#A855F7) with dark slate backgrounds.
var (
	colorPurple      = lipgloss.Color("#A855F7") // primary accent — neon purple
	colorPurpleDark  = lipgloss.Color("#6D28D9") // sent bubble background
	colorPurpleDeep  = lipgloss.Color("#3B0764") // status bar background
	colorSlateDark   = lipgloss.Color("#334155") // received bubble background
	colorSlateMid    = lipgloss.Color("#4B4880") // divider, secondary borders
	colorTextPrimary = lipgloss.Color("#F1F0FF") // near-white with purple tint
	colorTextMuted   = lipgloss.Color("#94A3B8") // timestamps, secondary text
	colorTextAccent  = lipgloss.Color("#C4B5FD") // peer label, highlights
	colorGreen       = lipgloss.Color("#4ADE80") // connected indicator dot
	colorRed         = lipgloss.Color("#F87171") // disconnected / error
	colorYellow      = lipgloss.Color("#FCD34D") // file events, warnings
)

// ── Pre-allocated styles ──────────────────────────────────────────────────────
// Declared at package level so Lipgloss does not allocate style objects on every
// render call. Render time per frame stays O(1) in style construction.
var (
	statusBarStyle = lipgloss.NewStyle().
			Background(colorPurpleDeep).
			Foreground(colorTextPrimary).
			Bold(true).
			Padding(0, 2)
	disconnectedBarStyle = lipgloss.NewStyle().
				Background(colorRed).
				Foreground(colorTextPrimary).
				Bold(true).
				Padding(0, 2)
	dividerStyle    = lipgloss.NewStyle().Foreground(colorSlateMid)
	sentBubbleStyle = lipgloss.NewStyle().
			Background(colorPurpleDark).
			Foreground(colorTextPrimary).
			Padding(0, 2).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorPurple)
	receivedBubbleStyle = lipgloss.NewStyle().
				Background(colorSlateDark).
				Foreground(colorTextPrimary).
				Padding(0, 2).
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorSlateMid)
	systemMsgStyle = lipgloss.NewStyle().
			Foreground(colorYellow).
			Italic(true)
	timestampStyle = lipgloss.NewStyle().
			Foreground(colorTextMuted).
			Italic(true)
	peerLabelStyle = lipgloss.NewStyle().
			Foreground(colorTextAccent).
			Bold(true)
	progressStyle = lipgloss.NewStyle().
			Foreground(colorPurple).
			PaddingLeft(3)
	inputBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorPurple).
				Padding(0, 1)
	inputDisconnectedStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(colorRed).
				Padding(0, 1)
)

// ── Message types ─────────────────────────────────────────────────────────────

type msgKind uint8

const (
	kindSent     msgKind = iota // user's own outbound message
	kindReceived                // inbound message from peer
	kindSystem                  // local event notification
	kindFile                    // file transfer event
)

type chatMessage struct {
	kind      msgKind
	text      string
	meta      string // file: size / path info
	timestamp time.Time
}

// ── Model ─────────────────────────────────────────────────────────────────────

// Model is the complete TUI state. Bubble Tea owns the event loop;
// all mutations happen by returning new (Model, Cmd) pairs from Update().
type Model struct {
	viewport     viewport.Model
	textarea     textarea.Model
	history      []chatMessage
	peerKey      string // display key for status bar
	connected    bool
	disconnected bool
	status       string         // secondary status text
	fileStatus   string         // live file progress line; "" = hidden
	outgoing     chan<- string  // user commands → sendLoop
	incoming     <-chan tea.Msg // network events → Update
	width        int
	height       int
	ready        bool
}

// New creates a Model wired to the provided channels.
// Pass nil channels for demo/test mode (road-1337 tui).
func New(peerKey string, outgoing chan<- string, incoming <-chan tea.Msg, isFirstRun ...bool) Model {
	ta := textarea.New()
	ta.Placeholder = "Type a message... (/file <path> | /clear | /exit)"
	ta.Focus()
	ta.ShowLineNumbers = false
	ta.KeyMap.InsertNewline.SetEnabled(false) // Enter sends; Shift+Enter not needed
	ta.SetHeight(3)

	// Style the textarea to match the dark purple palette.
	ta.FocusedStyle.Base = lipgloss.NewStyle().
		Foreground(colorTextPrimary)
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()
	ta.BlurredStyle.Base = lipgloss.NewStyle().
		Foreground(colorTextMuted)

	history := []chatMessage{
		{
			kind:      kindSystem,
			text:      "Welcome to road-1337 · E2EE session · all traffic is encrypted noise",
			timestamp: time.Now(),
		},
		{
			kind:      kindSystem,
			text:      "Commands: /file <path> | /clear | /exit | PgUp/PgDn to scroll",
			timestamp: time.Now(),
		},
	}

	firstRun := len(isFirstRun) > 0 && isFirstRun[0]
	_ = firstRun // handled by onboard package before TUI starts

	return Model{
		textarea:  ta,
		history:   history,
		peerKey:   peerKey,
		connected: true,
		status:    "Connecting...",
		outgoing:  outgoing,
		incoming:  incoming,
	}
}

// Init starts cursor blinking and the network event listener.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{textarea.Blink}
	if m.incoming != nil {
		cmds = append(cmds, m.waitForNetwork())
	}
	return tea.Batch(cmds...)
}

// pushMessage safely appends a message to history and reallocates if it exceeds maxMessageHistory
// to prevent memory leaks in the underlying slice array during long sessions.
func pushMessage(history []chatMessage, msg chatMessage) []chatMessage {
	history = append(history, msg)
	if len(history) > maxMessageHistory {
		newHistory := make([]chatMessage, maxMessageHistory)
		copy(newHistory, history[1:])
		return newHistory
	}
	return history
}

// Update is the pure state-transition function.
// It handles terminal resize, keyboard input, and all network events.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		taCmd  tea.Cmd
		vpCmd  tea.Cmd
		extras []tea.Cmd
	)

	switch msg := msg.(type) {
	// ── Terminal resize ────────────────────────────────────────────────────
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		vpW := msg.Width - 4
		if vpW < 20 {
			vpW = 20
		}
		// Layout rows: 1 status + 1 divider + 1 progress + 5 input border = 8
		vpH := msg.Height - 8
		if vpH < 3 {
			vpH = 3
		}
		if !m.ready {
			m.viewport = viewport.New(vpW, vpH)
			m.ready = true
		} else {
			m.viewport.Width = vpW
			m.viewport.Height = vpH
		}
		m.textarea.SetWidth(vpW - 2)
		m.viewport.SetContent(m.renderHistory())
		m.viewport.GotoBottom()

	// ── Keyboard ───────────────────────────────────────────────────────────
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			// Ctrl+C: send graceful disconnect then quit.
			if m.outgoing != nil && !m.disconnected {
				select {
				case m.outgoing <- "/exit":
				default:
				}
			}
			return m, tea.Quit

		case "enter":
			if m.disconnected {
				break // input locked after disconnect
			}
			text := strings.TrimSpace(m.textarea.Value())
			if text == "" {
				break
			}
			m.textarea.Reset()

			if text == "/exit" {
				if m.outgoing != nil {
					m.outgoing <- "/exit"
				}
				return m, tea.Quit
			}

			if text == "/clear" {
				m.history = nil // GC will clean the old array
				m.viewport.SetContent("")
				return m, nil
			}

			// Relay to network layer.
			if m.outgoing != nil {
				select {
				case m.outgoing <- text:
				default:
					// Channel full — surface as error; don't block the TUI.
					m.history = pushMessage(m.history, chatMessage{
						kind:      kindSystem,
						text:      "⚠ send queue full — try again",
						timestamp: time.Now(),
					})
				}
			}

			if strings.HasPrefix(text, "/file ") {
				m.history = pushMessage(m.history, chatMessage{
					kind:      kindFile,
					text:      strings.TrimPrefix(text, "/file "),
					meta:      "Sending...",
					timestamp: time.Now(),
				})
			} else {
				m.history = pushMessage(m.history, chatMessage{
					kind:      kindSent,
					text:      text,
					timestamp: time.Now(),
				})
			}

			m.viewport.SetContent(m.renderHistory())
			m.viewport.GotoBottom()

		case "pgup", "ctrl+u":
			m.viewport.HalfViewUp()
		case "pgdown", "ctrl+d":
			m.viewport.HalfViewDown()
		}

	// ── Network events ─────────────────────────────────────────────────────
	case StatusMsg:
		m.status = msg.Text
		if msg.Text == "SECURE" {
			m.connected = true
		}
		extras = append(extras, m.nextNetwork())

	case IncomingTextMsg:
		m.history = pushMessage(m.history, chatMessage{
			kind:      kindReceived,
			text:      msg.Text,
			timestamp: time.Now(),
		})
		m.viewport.SetContent(m.renderHistory())
		m.viewport.GotoBottom()
		extras = append(extras, m.nextNetwork())

	case IncomingFileMsg:
		m.history = pushMessage(m.history, chatMessage{
			kind:      kindFile,
			text:      msg.Text,
			meta:      msg.Meta,
			timestamp: time.Now(),
		})
		m.viewport.SetContent(m.renderHistory())
		m.viewport.GotoBottom()
		extras = append(extras, m.nextNetwork())

	case FileProgressMsg:
		m.fileStatus = msg.Status
		extras = append(extras, m.nextNetwork())

	case PeerDisconnectedMsg:
		// The peer is gone. Show a notice, lock the input, quit immediately.
		// Session.Zeroize() was already called by the network layer.
		m.disconnected = true
		m.connected = false
		m.status = "DISCONNECTED — keys zeroized"
		m.history = pushMessage(m.history, chatMessage{
			kind:      kindSystem,
			text:      "⚠ peer disconnected · session keys zeroized · re-run to connect again",
			timestamp: time.Now(),
		})
		m.viewport.SetContent(m.renderHistory())
		m.viewport.GotoBottom()
		// Give the user a moment to read the message, then quit.
		return m, tea.Quit
	}

	m.textarea, taCmd = m.textarea.Update(msg)
	m.viewport, vpCmd = m.viewport.Update(msg)
	return m, tea.Batch(append(extras, taCmd, vpCmd)...)
}

// View renders the complete terminal frame as a single string.
// Bubble Tea diffs this against the previous frame and flushes only changes.
func (m Model) View() string {
	if !m.ready {
		return lipgloss.NewStyle().
			Foreground(colorPurple).
			Padding(1, 2).
			Render("◌ initializing road-1337...")
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		m.viewStatusBar(),
		m.viewDivider(),
		m.viewChat(),
		m.viewProgressLine(),
		m.viewInput(),
	)
}

// ── View sub-components ───────────────────────────────────────────────────────

func (m Model) viewStatusBar() string {
	dot := lipgloss.NewStyle().Foreground(colorGreen).Render("●")
	statusText := m.status
	if statusText == "" {
		statusText = "SECURE"
	}
	if m.disconnected {
		dot = lipgloss.NewStyle().Foreground(colorRed).Render("●")
	}

	shortKey := m.peerKey
	if len(shortKey) > 20 {
		shortKey = shortKey[:20] + "…"
	}

	left := lipgloss.NewStyle().Foreground(colorPurple).Bold(true).Render(" road-1337")
	mid := lipgloss.NewStyle().Foreground(colorTextAccent).
		Render(fmt.Sprintf("peer: %s", shortKey))
	right := dot + lipgloss.NewStyle().Foreground(colorTextMuted).
		Render(fmt.Sprintf(" %s ", statusText))

	pad := m.width - lipgloss.Width(left) - lipgloss.Width(mid) - lipgloss.Width(right)
	if pad < 2 {
		pad = 2
	}
	row := left + strings.Repeat(" ", pad/2) + mid +
		strings.Repeat(" ", pad-pad/2) + right

	style := statusBarStyle
	if m.disconnected {
		style = disconnectedBarStyle
	}
	return style.Width(m.width).Render(row)
}

func (m Model) viewDivider() string {
	return dividerStyle.Render(strings.Repeat("─", m.width))
}

func (m Model) viewChat() string {
	return lipgloss.NewStyle().Padding(0, 2).Render(m.viewport.View())
}

func (m Model) viewProgressLine() string {
	if m.fileStatus == "" {
		return strings.Repeat(" ", m.width)
	}
	return progressStyle.Width(m.width).Render(m.fileStatus)
}

func (m Model) viewInput() string {
	style := inputBorderStyle
	if m.disconnected {
		style = inputDisconnectedStyle
	}
	return style.Width(m.width - 2).Render(m.textarea.View())
}

// ── History rendering ─────────────────────────────────────────────────────────

// renderHistory converts the message history into a single string for the viewport.
// Called only when history changes or on resize — not every frame.
func (m Model) renderHistory() string {
	if len(m.history) == 0 {
		return ""
	}
	// Limit bubble width to 65% of viewport to leave alignment breathing room.
	maxBubble := m.viewport.Width * 65 / 100
	if maxBubble < 20 {
		maxBubble = 20
	}

	var sb strings.Builder
	for _, msg := range m.history {
		switch msg.kind {
		case kindSent:
			sb.WriteString(m.renderSent(msg, maxBubble))
		case kindReceived:
			sb.WriteString(m.renderReceived(msg, maxBubble))
		case kindSystem:
			sb.WriteString(m.renderSystem(msg))
		case kindFile:
			sb.WriteString(m.renderFile(msg))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func (m Model) renderSent(msg chatMessage, maxBubble int) string {
	bubble := sentBubbleStyle.MaxWidth(maxBubble).Render(msg.text)
	ts := timestampStyle.Render(msg.timestamp.Format("15:04"))
	block := lipgloss.JoinVertical(lipgloss.Right, bubble, ts)
	return lipgloss.NewStyle().
		Width(m.viewport.Width).Align(lipgloss.Right).Render(block) + "\n"
}

func (m Model) renderReceived(msg chatMessage, maxBubble int) string {
	label := peerLabelStyle.PaddingLeft(1).Render("peer")
	bubble := receivedBubbleStyle.MaxWidth(maxBubble).Render(msg.text)
	ts := timestampStyle.PaddingLeft(1).Render(msg.timestamp.Format("15:04"))
	block := lipgloss.JoinVertical(lipgloss.Left, label, bubble, ts)
	return lipgloss.NewStyle().
		Width(m.viewport.Width).Align(lipgloss.Left).Render(block) + "\n"
}

func (m Model) renderSystem(msg chatMessage) string {
	line := fmt.Sprintf("── %s ──", msg.text)
	return systemMsgStyle.Width(m.viewport.Width).Align(lipgloss.Center).Render(line) + "\n"
}

func (m Model) renderFile(msg chatMessage) string {
	icon := lipgloss.NewStyle().Foreground(colorYellow).Render("📎")
	name := lipgloss.NewStyle().Foreground(colorYellow).Bold(true).Render(msg.text)
	meta := ""
	if msg.meta != "" {
		meta = lipgloss.NewStyle().Foreground(colorTextMuted).
			Render(fmt.Sprintf(" (%s)", msg.meta))
	}
	ts := timestampStyle.Render(" " + msg.timestamp.Format("15:04"))
	return icon + " " + name + meta + ts + "\n"
}

// ── Network polling ───────────────────────────────────────────────────────────

// waitForNetwork returns a Cmd that blocks until the next event arrives on
// the incoming channel and surfaces it as a tea.Msg for Update().
// This is the standard Bubble Tea pattern for integrating background goroutines.
func (m Model) waitForNetwork() tea.Cmd {
	return func() tea.Msg {
		return <-m.incoming
	}
}

// nextNetwork is waitForNetwork guarded by channel presence.
func (m Model) nextNetwork() tea.Cmd {
	if m.incoming == nil {
		return nil
	}
	return m.waitForNetwork()
}

// ── Exported helpers ──────────────────────────────────────────────────────────

// RenderProgress builds a Telegram-style progress bar string.
//
// passport.jpg [████████░░░░░░░░░░░░] 40%
func RenderProgress(filename string, pct int) string {
	const barWidth = 20
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := barWidth * pct / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)
	short := filename
	if len(short) > 20 {
		short = short[:17] + "..."
	}
	return fmt.Sprintf("%-20s [%s] %d%%", short, bar, pct)
}
