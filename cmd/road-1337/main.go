// Package main implements the road-1337 command-line interface.
// road-1337 is a secure, end-to-end encrypted console messenger utilizing a Blind Relay architecture.
// The relay infrastructure operates under a zero-trust model, processing traffic as fixed-size cryptographic noise.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/ValeryCherneykin/road-1337/internal/crypto"
	"golang.org/x/term"
)

// ASCII art banner displayed across subcommands for visual branding.
const banner = `
██████╗  ██████╗  █████╗ ██████╗       ██╗██████╗ ██████╗ ███████╗
██╔══██╗██╔═══██╗██╔══██╗██╔══██╗      ██║╚════██╗╚════██╗╚════██║
██████╔╝██║   ██║███████║██║  ██║█████╗██║ █████╔╝ █████╔╝    ██╔╝
██╔══██╗██║   ██║██╔══██║██║  ██║╚════╝╚═╝ ╚═══██╗ ╚═══██╗   ██╔╝ 
██║  ██║╚██████╔╝██║  ██║██████╔╝      ██║██████╔╝██████╔╝   ██║  
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝       ╚═╝╚═════╝ ╚═════╝    ╚═╝  
Blind Relay E2EE — Zero Trust Infrastructure
`

// main acts as the application entry point, delegating execution to the run function
// and enforcing OS-level exit codes upon failure.
func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

// run parses the command-line arguments and routes execution to the appropriate subcommand handler.
// It returns an error to ensure that deferred cleanup tasks in subcommands are reliably executed.
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

	default:
		// Route to client mode if the argument adheres to the routing format: [address]@[pubkey]
		if strings.Contains(args[1], "@") {
			return cmdClient(args[1])
		}
		printUsage()
		return fmt.Errorf("unknown command: %s", args[1])
	}
}

// cmdGenerateKeychain provisions a new X25519 keypair, serializes the private key to the local filesystem
// with restricted permissions, and outputs the public key in Base58 format.
func cmdGenerateKeychain() error {
	fmt.Print(banner)
	fmt.Println("[ Generating new X25519 keypair... ]")
	fmt.Println()

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}
	defer kp.Zeroize() // Enforce memory zeroization upon function return

	path, err := kp.SavePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	pubKey := kp.PublicKeyBase58()

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  Private key saved to: %s\n", path)
	fmt.Printf("  Permissions: 0600 (owner read/write only)\n")
	fmt.Println()
	fmt.Println("  Your PUBLIC KEY (share this with your peer out-of-band):")
	fmt.Println()
	fmt.Printf("  %s\n", pubKey)
	fmt.Println()
	fmt.Println("  ⚠  NEVER share your private key.")
	fmt.Println("  ⚠  Use full-disk encryption (FileVault/BitLocker).")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	return nil
}

// cmdRestoreKey imports an existing X25519 private key from standard input.
// It utilizes terminal state manipulation to mask input, preventing credential leaking to stdout.
func cmdRestoreKey() error {
	fmt.Print(banner)
	fmt.Println("[ Restore private key from manual input ]")
	fmt.Println()
	fmt.Println("Enter your 32-byte private key in Base58 format.")
	fmt.Println("Input will be hidden (paste and press Enter):")
	fmt.Print("> ")

	// Suppress terminal echo to protect cryptographic material from shoulder-surfing or log capturing
	byteKey, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read secure input: %w", err)
	}
	fmt.Println()

	input := strings.TrimSpace(string(byteKey))
	if input == "" {
		return fmt.Errorf("empty input — aborting")
	}

	// Decode Base58 string to access the raw private key byte slice
	rawPriv, err := crypto.DecodeBase58(input)
	if err != nil {
		return fmt.Errorf("invalid Base58 input: %w", err)
	}

	kp, err := crypto.KeyPairFromRawBytes(rawPriv)
	if err != nil {
		clear(rawPriv) // Immediate sanitization of ephemeral buffer upon initialization failure
		return fmt.Errorf("invalid private key: %w", err)
	}
	defer kp.Zeroize()
	clear(rawPriv) // Scrub raw private bytes once encapsulated inside the secure KeyPair object

	path, err := kp.SavePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	fmt.Println()
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  ✓ Private key restored and saved to: %s\n", path)
	fmt.Printf("  Your public key: %s\n", kp.PublicKeyBase58())
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	return nil
}

// cmdServer initializes and starts the ephemeral Blind Relay node on the designated port.
func cmdServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	port := fs.Int("port", 1337, "TCP port to listen on")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Print(banner)
	fmt.Printf("[ Blind Relay Server ] Starting on port %d\n", *port)
	fmt.Println("  RAM-only mode: no logging, no disk writes.")
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println()

	// TODO Sprint 2: Integrate relay.Run(*port) to orchestrate state-free packet distribution
	fmt.Println("[NOT IMPLEMENTED YET — Sprint 2]")
	_ = port
	return nil
}

// cmdClient establishes a connection to the specified relay node and executes an Diffie-Hellman
// key exchange (ECDH) to derive a shared symmetric session key.
func cmdClient(target string) error {
	// Parse target string using the established format: [IP]:[PORT]@[PUBLIC_KEY_BASE58]
	parts := strings.SplitN(target, "@", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid target format. Expected [IP]:[PORT]@[PUBLIC_KEY]\nGot: %s", target)
	}
	serverAddr := parts[0]
	peerPubKeyStr := parts[1]

	if !strings.Contains(serverAddr, ":") {
		return fmt.Errorf("invalid server address: %s (expected host:port)", serverAddr)
	}

	peerPubKey, err := crypto.DecodeBase58(peerPubKeyStr)
	if err != nil {
		return fmt.Errorf("invalid peer public key: %w", err)
	}

	kp, err := crypto.LoadKeyPairFromDisk()
	if err != nil {
		return fmt.Errorf("cannot load private key: %w\nRun 'road-1337 generate-keychain' first", err)
	}
	defer kp.Zeroize()

	// Execute X25519 Elliptic Curve Diffie-Hellman to compute the shared secret
	sharedSecret, err := kp.ECDH(peerPubKey)
	if err != nil {
		return fmt.Errorf("ECDH failed: %w", err)
	}
	defer clear(sharedSecret) // Mandate zeroization of the derived master secret after use

	fmt.Print(banner)
	fmt.Printf("[ Client ] Connecting to %s\n", serverAddr)
	fmt.Printf("  Peer public key: %s\n", peerPubKeyStr[:16]+"...")
	fmt.Printf("  Session key derived via X25519+HKDF ✓\n")
	fmt.Println()
	fmt.Println("  Type your message and press Enter.")
	fmt.Println("  Commands: /file [path]  /exit")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// TODO Sprint 3: Invoke client.Run(serverAddr, kp, sharedSecret) to begin the cryptographic I/O loop
	fmt.Println("[NOT IMPLEMENTED YET — Sprint 3]")
	_ = serverAddr
	return nil
}

// printUsage outputs standard manual guidelines and architectural security principles to the console.
func printUsage() {
	fmt.Print(banner)
	fmt.Println(`Usage:
  road-1337 generate-keychain
      Generate a new X25519 keypair. Private key saved to ~/.config/road-1337/private.key
      Public key printed in Base58 — share it with your peer out-of-band.

  road-1337 restore-key
      Restore private key by manual input (use when switching machines).

  road-1337 server --port 1337
      Start the Blind Relay server. RAM-only, no logging, no disk writes.

  road-1337 [IP]:[PORT]@[PUBLIC_KEY]
      Connect to a peer via the relay server.
      Example: road-1337 1.2.3.4:1337@7UZFJb3...

  road-1337 help
      Show this message.

Security model:
  - X25519 key exchange (out-of-band)
  - ChaCha20-Poly1305 encryption
  - All packets padded to 4KB (DPI resistance)
  - Server sees only encrypted noise, never plaintext
`)
}
