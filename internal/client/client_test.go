package client

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ValeryCherneykin/road-1337/internal/crypto"
	"github.com/ValeryCherneykin/road-1337/internal/protocol"
	tea "github.com/charmbracelet/bubbletea"
)

// mockSession creates a lightweight Session instance suitable for unit testing.
// It bypasses real network and TUI initialization while providing properly
// buffered channels to prevent test goroutines from blocking.
func mockSession(t *testing.T) *Session {
	t.Helper()
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to gen keypair: %v", err)
	}
	// Use the same key as peer for testing purposes (self-loop simulation)
	sess := NewSession(kp, kp.PublicKeyBytes())
	// Replace channels with generous buffers so tests don't block on sends
	sess.incoming = make(chan tea.Msg, 100)
	sess.outgoing = make(chan string, 100)
	return sess
}

// TestSession_Zeroize_Concurrency verifies that Zeroize() is idempotent and
// fully thread-safe under heavy concurrent access.
//
// This is a critical security test because Zeroize can be called simultaneously
// from network error paths, user /exit command, and OS signals.
func TestSession_Zeroize_Concurrency(t *testing.T) {
	sess := mockSession(t)

	// Simulate an active file transfer that Zeroize must clean up gracefully
	sess.transfersMu.Lock()
	sess.transfers[123] = &fileTransfer{
		done: false,
		// file: nil - for this test a nil file is sufficient
	}
	sess.transfersMu.Unlock()

	var wg sync.WaitGroup

	// Simulate concurrent calls from multiple goroutines (realistic scenario)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess.Zeroize()
		}()
	}

	wg.Wait()

	// Verify post-Zeroize state
	select {
	case <-sess.done:
		// channel was properly closed
	default:
		t.Error("sess.done channel was not closed")
	}

	sess.transfersMu.Lock()
	if len(sess.transfers) != 0 {
		t.Errorf("expected transfers map to be cleared, got %d items", len(sess.transfers))
	}
	sess.transfersMu.Unlock()
}

// TestSession_AppendChunk validates the core file reconstruction logic
// by simulating chunk arrival without requiring a real network connection.
func TestSession_AppendChunk(t *testing.T) {
	sess := mockSession(t)
	defer sess.Zeroize()

	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "secret_image.png")

	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	fileID := uint32(1337)
	expectedData := []byte("hello blind relay")
	totalSize := uint64(len(expectedData))

	// Manually register a file transfer (what recvFile normally does)
	sess.transfersMu.Lock()
	sess.transfers[fileID] = &fileTransfer{
		fh: protocol.FileHeaderPayload{
			FileID:    fileID,
			Filename:  "secret_image.png",
			TotalSize: totalSize,
		},
		file:    f,
		outPath: outPath,
	}
	sess.transfersMu.Unlock()

	// Simulate receiving data in multiple chunks
	sess.appendChunk(fileID, expectedData[:5])
	sess.appendChunk(fileID, expectedData[5:])

	// Transfer should be removed from map after completion
	sess.transfersMu.Lock()
	_, exists := sess.transfers[fileID]
	sess.transfersMu.Unlock()
	if exists {
		t.Error("transfer was not removed from map after completion")
	}

	// Verify the resulting file content on disk
	result, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read result file: %v", err)
	}
	if !bytes.Equal(result, expectedData) {
		t.Errorf("file data mismatch.\nGot: %s\nWant: %s", result, expectedData)
	}
}

// TestSession_AppendChunk_OversizedReject ensures protection against
// potential memory exhaustion / DoS attacks via malicious oversized chunks.
func TestSession_AppendChunk_OversizedReject(t *testing.T) {
	sess := mockSession(t)
	defer sess.Zeroize()

	tempDir := t.TempDir()
	f, _ := os.Create(filepath.Join(tempDir, "attack.txt"))

	fileID := uint32(999)

	sess.transfersMu.Lock()
	sess.transfers[fileID] = &fileTransfer{
		fh:   protocol.FileHeaderPayload{TotalSize: 100000},
		file: f,
	}
	sess.transfersMu.Unlock()

	// Generate chunk larger than allowed size
	badChunk := make([]byte, protocol.ChunkSize+1)
	if _, err := rand.Read(badChunk); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	sess.appendChunk(fileID, badChunk)

	// Transfer should have been aborted and cleaned up
	sess.transfersMu.Lock()
	_, exists := sess.transfers[fileID]
	sess.transfersMu.Unlock()
	if exists {
		t.Error("oversized chunk did not abort the transfer")
	}
}
