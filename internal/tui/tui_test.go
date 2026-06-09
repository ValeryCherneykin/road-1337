package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// ── Pure Function Tests ───────────────────────────────────────────────────────

// TestPushMessage verifies the memory-leak prevention logic in the chat history.
// It ensures that once the maxMessageHistory limit is reached, older messages
// are evicted and the slice does not grow infinitely.
func TestPushMessage(t *testing.T) {
	var history []chatMessage

	// Push 105 messages (5 over the maxMessageHistory limit of 100).
	totalToPush := maxMessageHistory + 5
	for i := 0; i < totalToPush; i++ {
		msg := chatMessage{
			kind: kindSent,
			text: "message " + string(rune(i)),
		}
		history = pushMessage(history, msg)
	}

	// 1. Length check: the slice must never exceed the maximum allowed size.
	if len(history) != maxMessageHistory {
		t.Fatalf("Expected history length %d, got %d", maxMessageHistory, len(history))
	}

	// 2. Data integrity check: it should retain the LATEST messages.
	// If we pushed 105 messages (indices 0 to 104), the first element in the
	// truncated history should be message #5.
	expectedFirstText := "message \x05" // ASCII 5
	if history[0].text != expectedFirstText {
		t.Errorf("Eviction failed. Expected first message text %q, got %q", expectedFirstText, history[0].text)
	}
}

// TestRenderProgress validates the visual formatting of the file transfer bar.
// Table-driven tests are perfect here to check boundary conditions (0%, >100%, <0%).
func TestRenderProgress(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		pct      int
		expected string
	}{
		{
			name:     "Normal 50%",
			filename: "secret.zip",
			pct:      50,
			// 20 chars total: 10 filled, 10 empty
			expected: "secret.zip           [██████████░░░░░░░░░░] 50%",
		},
		{
			name:     "Negative bounds check",
			filename: "data.bin",
			pct:      -10,
			expected: "data.bin             [░░░░░░░░░░░░░░░░░░░░] 0%",
		},
		{
			name:     "Overflow bounds check",
			filename: "data.bin",
			pct:      150,
			expected: "data.bin             [████████████████████] 100%",
		},
		{
			name:     "Filename truncation",
			filename: "very_long_filename_that_exceeds_limits.tar.gz",
			pct:      10,
			// Should truncate to 17 chars + "..." = 20 chars
			expected: "very_long_filenam... [██░░░░░░░░░░░░░░░░░░] 10%",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RenderProgress(tt.filename, tt.pct)
			if got != tt.expected {
				t.Errorf("\nExpected: %q\nGot:      %q", tt.expected, got)
			}
		})
	}
}

// ── State Machine (Update) Tests ──────────────────────────────────────────────

// TestUpdateCommands tests how the Model reacts to specific keyboard input.
// Because Bubble Tea's Update is a pure function, we don't need a real terminal.
// We just inject tea.KeyMsg and assert the resulting state.
func TestUpdateCommands(t *testing.T) {
	// Use a buffered channel so the Update function doesn't block when trying
	// to send the command to the network layer.
	outgoing := make(chan string, 5)

	// Initialize a fresh model.
	m := New("test_peer_key", outgoing, nil)

	// Inject a simulated /clear command.
	m.textarea.SetValue("/clear")
	updatedModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updatedModel.(Model) // Type assertion back to our concrete Model

	// 1. Check side effects: The command should return nil (no further tea.Cmd).
	if cmd != nil {
		t.Error("Expected nil Cmd after /clear, got something else")
	}

	// 2. Check state mutation: History should be wiped clean.
	if len(m.history) != 0 {
		t.Errorf("Expected history to be empty after /clear, got %d items", len(m.history))
	}

	// Inject a normal chat message.
	m.textarea.SetValue("Hello peer")
	updatedModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updatedModel.(Model)

	// 3. Check state mutation: History should contain the new sent message.
	if len(m.history) != 1 {
		t.Fatalf("Expected history length 1, got %d", len(m.history))
	}
	if m.history[0].text != "Hello peer" {
		t.Errorf("Expected message 'Hello peer', got %q", m.history[0].text)
	}

	// 4. Check channel communication: The message should be routed to outgoing.
	select {
	case sentMsg := <-outgoing:
		if sentMsg != "Hello peer" {
			t.Errorf("Expected outgoing channel to receive 'Hello peer', got %q", sentMsg)
		}
	default:
		t.Error("Expected message on outgoing channel, but it was empty")
	}
}

// TestUpdateNetworkEvents verifies that the TUI correctly mutates its state
// when receiving simulated events from the asynchronous network layer.
func TestUpdateNetworkEvents(t *testing.T) {
	m := New("test_peer_key", nil, nil)
	// Clear the default welcome messages for a clean testing slate.
	m.history = nil

	// Simulate an incoming decrypted text message.
	inMsg := IncomingTextMsg{Text: "Top secret intel"}
	updatedModel, _ := m.Update(inMsg)
	m = updatedModel.(Model)

	// Verify history appended the received message.
	if len(m.history) != 1 {
		t.Fatalf("Expected history length 1, got %d", len(m.history))
	}
	if m.history[0].kind != kindReceived {
		t.Errorf("Expected message kindReceived, got %v", m.history[0].kind)
	}
	if m.history[0].text != "Top secret intel" {
		t.Errorf("Expected text 'Top secret intel', got %q", m.history[0].text)
	}

	// Simulate a graceful peer disconnect.
	updatedModel, cmd := m.Update(PeerDisconnectedMsg{})
	m = updatedModel.(Model)

	// 1. It must return tea.Quit to signal the framework to shut down.
	if cmd == nil {
		t.Error("Expected tea.Quit command after PeerDisconnectedMsg, got nil")
	}

	// 2. It must lock the UI state to prevent further input.
	if !m.disconnected {
		t.Error("Expected m.disconnected to be true")
	}
	if m.connected {
		t.Error("Expected m.connected to be false")
	}

	// 3. The status indicator should reflect the zeroized state.
	if !strings.Contains(m.status, "DISCONNECTED") {
		t.Errorf("Expected status to contain DISCONNECTED, got %q", m.status)
	}
}
