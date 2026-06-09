package onboard

import (
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
)

// TestLifecycle verifies the full state transition of the onboarding process.
// It ensures that IsFirstRun correctly identifies the absence of the sentinel
// file and that MarkDone successfully creates it.
func TestLifecycle(t *testing.T) {
	// 1. Isolate the filesystem.
	// t.TempDir() creates a unique temporary directory for this specific test
	// and automatically cleans it up when the test finishes.
	tempDir := t.TempDir()

	// 2. Mock environment variables.
	// t.Setenv safely overrides environment variables for the duration of the test.
	// This prevents the test from touching the developer's real ~/.config directory.
	t.Setenv("HOME", tempDir)
	t.Setenv("APPDATA", tempDir)

	// Stage 1: Sentinel file does not exist yet.
	if !IsFirstRun() {
		t.Error("IsFirstRun() returned false, expected true for a fresh environment")
	}

	// Stage 2: Create the sentinel file.
	MarkDone()

	// Stage 3: Sentinel file should now exist.
	if IsFirstRun() {
		t.Error("IsFirstRun() returned true, expected false after calling MarkDone()")
	}

	// Stage 4: Idempotency check.
	// Calling MarkDone multiple times should not panic or corrupt the state.
	MarkDone()
	if IsFirstRun() {
		t.Error("IsFirstRun() state corrupted after subsequent MarkDone() calls")
	}
}

// TestRunInteractive simulates user input via os.Stdin to test the interactive
// language selection and guide progression.
func TestRunInteractive(t *testing.T) {
	// Save the original Stdin and Stdout to restore them later.
	// Modifying global state in tests requires careful cleanup.
	origStdin := os.Stdin
	origStdout := os.Stdout
	defer func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	}()

	// Define table-driven test cases for both English and Russian paths.
	tests := []struct {
		name         string
		simulatedIn  string // The keystrokes the "user" will type
		expectedText string // A snippet we expect to see in the output
	}{
		{
			name: "English Guide Selection",
			// "1" + Enter (select EN), then 4 Enters to page through the guide, 1 Enter to generate
			simulatedIn:  "1\n\n\n\n\n\n",
			expectedText: "Security Guide & First-Run Setup",
		},
		{
			name: "Russian Guide Selection",
			// "2" + Enter (select RU), then 4 Enters to page through the guide, 1 Enter to generate
			simulatedIn:  "2\n\n\n\n\n\n",
			expectedText: "Руководство по безопасности и первый запуск",
		},
		{
			name: "Fallback Guide Selection",
			// Invalid input "invalid" + Enter should fallback to English
			simulatedIn:  "invalid\n\n\n\n\n\n",
			expectedText: "Security Guide & First-Run Setup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create simulated Stdin (Reader) and Stdin Writer
			inR, inW, err := os.Pipe()
			if err != nil {
				t.Fatalf("Failed to create stdin pipe: %v", err)
			}
			os.Stdin = inR

			// Create simulated Stdout (Reader) and Stdout Writer
			outR, outW, err := os.Pipe()
			if err != nil {
				t.Fatalf("Failed to create stdout pipe: %v", err)
			}
			os.Stdout = outW

			// Write the simulated keystrokes to the stdin pipe.
			go func() {
				defer func() {
					_ = inW.Close()
				}()
				_, _ = io.WriteString(inW, tt.simulatedIn)
			}()

			// Run the target function. It will read from inR and write to outW.
			Run()

			// Close the writer so io.ReadAll knows when to stop reading.
			_ = outW.Close()

			// Read all captured output.
			capturedOutput, err := io.ReadAll(outR)
			if err != nil {
				t.Fatalf("Failed to read captured output: %v", err)
			}

			// Assert that the expected translated text is present in the output.
			outputStr := string(capturedOutput)
			if !strings.Contains(outputStr, tt.expectedText) {
				t.Errorf("Expected output to contain %q, but it didn't.\nGot snippet: %s",
					tt.expectedText, outputStr[:100])
			}
		})
	}
}

// TestSentinelPathOS verifies the OS-specific path logic.
func TestSentinelPathOS(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)
	t.Setenv("APPDATA", tempDir)

	path, err := sentinelPath()
	if err != nil {
		t.Fatalf("sentinelPath returned unexpected error: %v", err)
	}

	if runtime.GOOS == "windows" {
		if !strings.Contains(path, tempDir) || !strings.Contains(path, "road-1337") {
			t.Errorf("Windows path incorrect. Got: %s", path)
		}
	} else {
		if !strings.Contains(path, tempDir) || !strings.Contains(path, ".config") {
			t.Errorf("Unix path incorrect. Got: %s", path)
		}
	}
}
