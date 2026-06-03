// Package main implements the road-1337 command-line interface.
// It serves as the primary entry point for managing keys, starting the
// relay server, and initiating E2EE client sessions.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ValeryCherneykin/road-1337/internal/crypto"
	"github.com/ValeryCherneykin/road-1337/internal/tui"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

const banner = `
██████╗ ██████╗ █████╗ ██████╗ ██╗██████╗ ██████╗ ███████╗
██╔══██╗██╔═══██╗██╔══██╗██╔══██╗██║╚════██╗╚════██╗╚════██║
██████╔╝██║   ██║███████║██║  ██║█████╗██║ █████╔╝ █████╔╝ ██╔╝
██╔══██╗██║   ██║██╔══██║██║  ██║╚════╝╚═╝ ╚═══██╗ ╚═══██╗ ██╔╝
██║  ██║╚██████╔╝██║  ██║██████╔╝      ██║██████╔╝██████╔╝ ██║
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝       ╚═╝╚═════╝ ╚═════╝  ╚═╝
Blind Relay E2EE — Zero Trust Infrastructure
`

// main acts as the primary application entry point.
func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

// run parses CLI arguments and delegates execution to the corresponding command handler.
func run(args []string) error {
	if len(args) < 2 {
		printUsage()
		return fmt.Errorf("missing command")
	}

	switch args[1] {
	case "generate-keychain":
		return cmdGenerateKeychain()
	case "restore-key":
		return cmdRestoreKey()
	case "server":
		return cmdServer(args[2:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	case "tui", "test":
		// Test mode: Launches the TUI with a dummy peer key.
		p := tea.NewProgram(tui.New("5FzK9pLmXqWv8sY2dJ3kPqR"), tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			return fmt.Errorf("TUI error: %w", err)
		}
		return nil
	default:
		// Attempt to initiate a client session if the argument follows the [target]@[key] pattern.
		if strings.Contains(args[1], "@") {
			return cmdClient(args[1])
		}
		printUsage()
		return fmt.Errorf("unknown command: %s", args[1])
	}
}

// ====================== CLIENT SESSION HANDLER ======================

// cmdClient handles the cryptographic handshake and bootstraps the TUI session.
func cmdClient(target string) error {
	parts := strings.SplitN(target, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid target format. Expected [IP]:[PORT]@[PUBLIC_KEY]\nGot: %s", target)
	}

	serverAddr := parts[0]
	peerPubKeyStr := parts[1]

	if !strings.Contains(serverAddr, ":") {
		return fmt.Errorf("invalid server address: %s (expected host:port)", serverAddr)
	}

	// Initialize cryptographic parameters
	peerPubKey, err := crypto.DecodeBase58(peerPubKeyStr)
	if err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}

	kp, err := crypto.LoadKeyPairFromDisk()
	if err != nil {
		return fmt.Errorf("failed to load private key: %w\nRun 'road-1337 generate-keychain' first", err)
	}
	defer kp.Zeroize()

	// Derive session secret using X25519 ECDH
	sharedSecret, err := kp.ECDH(peerPubKey)
	if err != nil {
		return fmt.Errorf("ECDH exchange failed: %w", err)
	}
	defer clear(sharedSecret)

	// ====================== TUI INITIALIZATION ======================
	fmt.Print(banner)
	fmt.Printf("[ Client ] Connecting to %s\n", serverAddr)
	fmt.Printf(" Peer public key: %s...\n", safePrefix(peerPubKeyStr, 16))
	fmt.Println(" Session key derived via X25519+HKDF ✓")
	fmt.Println()

	p := tea.NewProgram(tui.New(peerPubKeyStr), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	return nil
}

// ====================== UTILITIES ======================

// safePrefix returns the first n characters of a string safely.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// cmdGenerateKeychain creates a new X25519 keypair and persists it to disk.
func cmdGenerateKeychain() error {
	fmt.Print(banner)
	fmt.Println("[ Generating new X25519 keypair... ]")

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}
	defer kp.Zeroize()

	path, err := kp.SavePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	pubKey := kp.PublicKeyBase58()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf(" Private key saved to: %s\n", path)
	fmt.Printf(" Permissions: 0600 (owner read/write only)\n")
	fmt.Println()
	fmt.Println(" Your PUBLIC KEY (share this out-of-band):")
	fmt.Printf(" %s\n", pubKey)
	fmt.Println()
	fmt.Println(" ⚠ NEVER share your private key.")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	return nil
}

// cmdRestoreKey imports a private key from user input and persists it.
func cmdRestoreKey() error {
	fmt.Print(banner)
	fmt.Println("[ Restore private key from manual input ]")
	fmt.Println("Enter your 32-byte private key in Base58 format.")
	fmt.Println("Input will be hidden (paste and press Enter):")
	fmt.Print("> ")

	byteKey, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read secure input: %w", err)
	}
	fmt.Println()

	input := strings.TrimSpace(string(byteKey))
	if input == "" {
		return fmt.Errorf("empty input — aborting")
	}

	rawPriv, err := crypto.DecodeBase58(input)
	if err != nil {
		return fmt.Errorf("invalid Base58 input: %w", err)
	}

	kp, err := crypto.KeyPairFromRawBytes(rawPriv)
	if err != nil {
		clear(rawPriv)
		return fmt.Errorf("invalid private key: %w", err)
	}
	defer kp.Zeroize()
	clear(rawPriv)

	path, err := kp.SavePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf(" ✓ Private key restored and saved to: %s\n", path)
	fmt.Printf(" Your public key: %s\n", kp.PublicKeyBase58())
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	return nil
}

// cmdServer launches the Blind Relay server instance.
func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	port := fs.Int("port", 1337, "TCP port to listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Print(banner)
	fmt.Printf("[ Blind Relay Server ] Starting on port %d\n", *port)
	fmt.Println(" RAM-only mode: no logging, no disk writes.")
	fmt.Println("[NOT IMPLEMENTED YET — Sprint 2]")
	return nil
}

// printUsage displays the CLI manual to the user.
func printUsage() {
	fmt.Print(banner)
	fmt.Println(`Usage:
  road-1337 generate-keychain
  road-1337 restore-key
  road-1337 server --port 1337
  road-1337 [IP]:[PORT]@[PUBLIC_KEY]
  road-1337 tui                      (test UI mode)

Example: road-1337 127.0.0.1:1337@7UZFJb3k...`)
}
