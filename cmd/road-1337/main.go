// Package main implements the road-1337 command-line interface.
//
// road-1337 is a zero-trust, end-to-end encrypted console messenger
// with a Blind Relay architecture. The relay sees only encrypted noise.
//
// Usage:
//
//	road-1337 generate-keychain     — generate keypair, set master passphrase
//	road-1337 restore-key           — restore key from Base58 + set passphrase
//	road-1337 server [--port 1337]  — run the Blind Relay
//	road-1337 [IP]:[PORT]@[PUBKEY]  — connect to a peer
//	road-1337 tui                   — TUI demo (no network)
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ValeryCherneykin/road-1337/internal/client"
	"github.com/ValeryCherneykin/road-1337/internal/crypto"
	"github.com/ValeryCherneykin/road-1337/internal/onboard"
	"github.com/ValeryCherneykin/road-1337/internal/relay"
	"github.com/ValeryCherneykin/road-1337/internal/tui"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

// version is injected at link time: -ldflags "-X main.version=v1.0.0"
var version = "dev"

const banner = `
 ██████╗  ██████╗  █████╗ ██████╗       ██╗██████╗ ██████╗ ███████╗
 ██╔══██╗██╔═══██╗██╔══██╗██╔══██╗      ██║╚════██╗╚════██╗╚════██║
 ██████╔╝██║   ██║███████║██║  ██║█████╗██║ █████╔╝ █████╔╝    ██╔╝
 ██╔══██╗██║   ██║██╔══██║██║  ██║╚════╝╚═╝ ╚═══██╗ ╚═══██╗   ██╔╝
 ██║  ██║╚██████╔╝██║  ██║██████╔╝      ██║██████╔╝██████╔╝   ██║
 ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝       ╚═╝╚═════╝ ╚═════╝    ╚═╝`

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "\n  error: %v\n\n", err)
		os.Exit(1)
	}
}

// run parses args and dispatches to command handlers.
// Separated from main() so tests can invoke it without os.Exit.
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
	case "tui", "test":
		return cmdTUIDemo()
	case "version", "--version":
		fmt.Printf("road-1337 %s\n", version)
		return nil
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		if strings.Contains(args[1], "@") {
			return cmdClient(args[1])
		}
		printUsage()
		return fmt.Errorf("unknown command: %s", args[1])
	}
}

// ── generate-keychain ────────────────────────────────────────────────────────

// cmdGenerateKeychain runs first-run onboarding (if needed), generates an X25519
// keypair, and encrypts the private key with Argon2id + ChaCha20-Poly1305.
func cmdGenerateKeychain() error {
	// First-run wizard: bilingual onboarding guide.
	if onboard.IsFirstRun() {
		onboard.Run()
		onboard.MarkDone()
	}

	fmt.Printf("%s  (%s)\n\n", banner, version)
	fmt.Println("  Generating new X25519 keypair...")
	fmt.Println()

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("key generation: %w", err)
	}
	defer kp.Zeroize()

	passphrase, err := promptNewPassphrase()
	if err != nil {
		return err
	}

	path, err := kp.SavePrivateKeyEncrypted(passphrase)
	if err != nil {
		return fmt.Errorf("save keychain: %w", err)
	}
	// Also mark the manual as seen in the config.
	_ = crypto.MarkManualAsSeen()

	pub := kp.PublicKeyBase58()
	fmt.Println()
	fmt.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Keychain saved  → %s\n", path)
	fmt.Printf("  Encryption      → Argon2id + ChaCha20-Poly1305\n")
	fmt.Printf("  Permissions     → 0600 (owner only)\n")
	fmt.Println()
	fmt.Println("  YOUR PUBLIC KEY — share this out-of-band with your peer:")
	fmt.Println()
	fmt.Printf("    %s\n", pub)
	fmt.Println()
	fmt.Println("  ⚠  Write your PRIVATE KEY on paper and store it safely.")
	fmt.Println("  ⚠  Enable full-disk encryption (FileVault / BitLocker).")
	fmt.Println("  ⚠  NEVER share your passphrase or private key.")
	fmt.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	return nil
}

// ── restore-key ──────────────────────────────────────────────────────────────

// cmdRestoreKey imports a private key from a hidden Base58 prompt and re-encrypts
// it with a new master passphrase. Used when migrating to a new machine.
func cmdRestoreKey() error {
	fmt.Printf("%s  (%s)\n\n", banner, version)
	fmt.Println("  Restore private key from Base58 input.")
	fmt.Println()

	rawInput, err := readHiddenInput("  Private key (Base58, hidden): ")
	if err != nil {
		return err
	}
	if rawInput == "" {
		return fmt.Errorf("empty input — aborting")
	}

	privBytes, err := crypto.DecodeBase58(rawInput)
	if err != nil {
		return fmt.Errorf("invalid Base58: %w", err)
	}

	kp, err := crypto.KeyPairFromRawBytes(privBytes)
	if err != nil {
		clear(privBytes)
		return fmt.Errorf("invalid private key: %w", err)
	}
	defer kp.Zeroize()
	clear(privBytes)

	passphrase, err := promptNewPassphrase()
	if err != nil {
		return err
	}

	path, err := kp.SavePrivateKeyEncrypted(passphrase)
	if err != nil {
		return fmt.Errorf("save keychain: %w", err)
	}

	fmt.Println()
	fmt.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  ✓ Keychain restored → %s\n", path)
	fmt.Printf("  Public key         → %s\n", kp.PublicKeyBase58())
	fmt.Println("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	return nil
}

// ── server ────────────────────────────────────────────────────────────────────

// cmdServer starts the Blind Relay and blocks until SIGINT/SIGTERM.
func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	port := fs.Int("port", 1337, "TCP port to listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Printf("%s  (%s)\n\n", banner, version)
	fmt.Printf("  ┌─ Blind Relay ──────────────────────────────────────┐\n")
	fmt.Printf("  │  port         : %-5d                              │\n", *port)
	fmt.Printf("  │  ram-only     : true  (log → /dev/null)            │\n")
	fmt.Printf("  │  disk I/O     : none                               │\n")
	fmt.Printf("  │  max peers    : 2048                               │\n")
	fmt.Printf("  │  heartbeat    : 45 s eviction                      │\n")
	fmt.Printf("  │  burn-on-read : clear() after every Write()        │\n")
	fmt.Printf("  └────────────────────────────────────────────────────┘\n\n")

	srv := relay.New()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		fmt.Printf("\n  received %s — shutting down relay...\n", sig)
		srv.Stop()
	}()

	return srv.Run(fmt.Sprintf(":%d", *port))
}

// ── client ────────────────────────────────────────────────────────────────────

// cmdClient parses [IP]:[PORT]@[PUBKEY], unlocks the keychain, and starts the TUI session.
func cmdClient(target string) error {
	parts := strings.SplitN(target, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf(
			"invalid target format\n  expected: [IP]:[PORT]@[PUBLIC_KEY]\n  got:      %s", target,
		)
	}

	serverAddr, peerKeyStr := parts[0], parts[1]
	if !strings.Contains(serverAddr, ":") {
		return fmt.Errorf("invalid server address %q — missing port", serverAddr)
	}

	peerPubKey, err := crypto.PublicKeyFromBase58(peerKeyStr)
	if err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}

	// Unlock keychain with master passphrase.
	passphrase, err := readHiddenInput("  Unlock keychain (passphrase): ")
	if err != nil {
		return err
	}

	kp, err := crypto.LoadKeyPairFromDiskEncrypted(passphrase)
	if err != nil {
		return fmt.Errorf("keychain unlock failed: %w\n  run 'generate-keychain' if you haven't yet", err)
	}
	defer kp.Zeroize()

	sess := client.NewSession(kp, peerPubKey)

	// Ctrl+C / SIGTERM during an active session → graceful zeroize.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		sess.Zeroize()
	}()

	return sess.Run(serverAddr)
}

// ── TUI demo ─────────────────────────────────────────────────────────────────

// cmdTUIDemo launches the TUI with fake demo messages.
// No network, no keys — useful for UI layout testing.
func cmdTUIDemo() error {
	out := make(chan string, 16)
	in := make(chan tea.Msg, 64)

	model := tui.New("DemoKey1337PurpleHackerVibes", out, in, false)
	p := tea.NewProgram(model, tea.WithAltScreen())

	// Feed a few demo messages so the layout is visible immediately.
	go func() {
		in <- tui.StatusMsg{Text: "SECURE"}
		in <- tui.IncomingTextMsg{Text: "road-1337 demo mode."}
		in <- tui.IncomingTextMsg{Text: "All traffic is 4096-byte encrypted noise."}
		in <- tui.IncomingTextMsg{Text: "Server sees nothing. Zero trust. 🔐"}
	}()

	// Drain outgoing so the demo doesn't block.
	go func() {
		for range out {
		}
	}()

	_, err := p.Run()
	return err
}

// ── usage ─────────────────────────────────────────────────────────────────────

func printUsage() {
	fmt.Printf("%s  (%s)\n", banner, version)
	fmt.Print(`
USAGE

  road-1337 generate-keychain
      Generate X25519 keypair, encrypt with Argon2id master passphrase.
      Private key: ~/.config/road-1337/config.json  (Linux/macOS)
                   %APPDATA%\road-1337\config.json   (Windows)

  road-1337 restore-key
      Restore private key from Base58 input + set new passphrase.
      Use when migrating to a new machine.

  road-1337 server [--port 1337]
      Start the Blind Relay.
      RAM-only · zero logging · zero plaintext visibility.

  road-1337 [IP]:[PORT]@[PUBLIC_KEY]
      Connect to a peer via the relay.
      Example: road-1337 1.2.3.4:1337@7UZFJb3xKpLm...

  road-1337 tui
      Launch TUI in demo mode (no network required).

  road-1337 version
      Print build version.

CHAT COMMANDS

  /file <path>  — send a file (128 KB chunks, encrypted)
  /exit         — graceful disconnect + session key zeroization
  PgUp / PgDn   — scroll message history
  Ctrl+C        — force quit with key zeroization

SECURITY

  Key exchange     : X25519 ECDH (out-of-band key distribution)
  Key derivation   : HKDF-SHA256 (NIST SP 800-56C)
  Encryption       : ChaCha20-Poly1305 AEAD
  Key at rest      : Argon2id + ChaCha20-Poly1305 (encrypted config.json)
  Packet padding   : all packets fixed at 4096 B (DPI resistance)
  Server model     : Blind Relay — routes encrypted noise only
  Disconnect       : session keys zeroized, no auto-reconnect
  Memory           : clear() on all key material at every exit path

`)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func readHiddenInput(prompt string) (string, error) {
	fmt.Print(prompt)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("read secure input: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func promptNewPassphrase() (string, error) {
	p1, err := readHiddenInput("  Set master passphrase   : ")
	if err != nil {
		return "", err
	}
	if p1 == "" {
		return "", fmt.Errorf("passphrase cannot be empty")
	}

	p2, err := readHiddenInput("  Confirm master passphrase: ")
	if err != nil {
		return "", err
	}

	if p1 != p2 {
		return "", fmt.Errorf("passphrases do not match")
	}
	return p1, nil
}
