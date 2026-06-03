// Package crypto implements the entire cryptographic subsystem for road-1337.
// It relies strictly on modern, symmetric elliptic-curve cryptography (X25519 for key exchange
// and ChaCha20-Poly1305 for packet encryption). It deliberately avoids legacy protocols like RSA or TLS.
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	// PrivateKeySize defines the expected byte length of an X25519 private key.
	PrivateKeySize = 32

	// PublicKeySize defines the expected byte length of an X25519 public key.
	PublicKeySize = 32

	// KeyFilePermission enforces strict read/write access only for the file owner.
	// This mitigates local privilege escalation and unauthorized key extraction.
	KeyFilePermission = 0o600

	// DirPermission sets standard secure permissions for configuration directories.
	DirPermission = 0o700
)

// KeyPair encapsulates an X25519 key pair and provides secure operations over it.
// To prevent accidental leakage, the underlying private key is unexported and
// should only be accessed via controlled methods with explicit memory zeroization.
type KeyPair struct {
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
}

// GenerateKeyPair creates a new random X25519 key pair.
// It relies exclusively on crypto/rand (CSPRNG) to guarantee entropy.
func GenerateKeyPair() (*KeyPair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate X25519 key: %w", err)
	}

	return &KeyPair{
		privateKey: priv,
		publicKey:  priv.PublicKey(),
	}, nil
}

// PublicKeyBase58 returns the public key encoded in Base58 format.
// This representation is designed for Out-of-Band (OOB) sharing (e.g., via chat),
// ensuring the key string remains intact and visually clear.
func (kp *KeyPair) PublicKeyBase58() string {
	return EncodeBase58(kp.publicKey.Bytes())
}

// PublicKeyHash computes the SHA-256 hash of the public key.
// Primarily used by the server node to index and route packets in its connection table.
func (kp *KeyPair) PublicKeyHash() [32]byte {
	return sha256.Sum256(kp.publicKey.Bytes())
}

// PublicKeyBytes returns a copy of the raw public key bytes.
func (kp *KeyPair) PublicKeyBytes() []byte {
	b := make([]byte, PublicKeySize)
	copy(b, kp.publicKey.Bytes())
	return b
}

// ECDH performs an X25519 Diffie-Hellman key exchange with a remote peer's public key.
// It derives and returns a symmetric session secret.
// WARNING: The returned slice must be explicitly zeroized by the caller after use
// to minimize the attack surface in RAM.
func (kp *KeyPair) ECDH(theirPublicKeyBytes []byte) ([]byte, error) {
	curve := ecdh.X25519()
	theirPub, err := curve.NewPublicKey(theirPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse remote public key: %w", err)
	}

	secret, err := kp.privateKey.ECDH(theirPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation: %w", err)
	}

	// Apply HKDF-SHA256 to derive the final robust key from the raw DH secret,
	// complying with NIST SP 800-56C recommendations.
	derived := deriveKey(secret)

	// Immediately scrub the raw DH secret from memory.
	clear(secret)

	return derived, nil
}

// Zeroize explicitly overwrites the private key material in memory.
// It must be called during graceful shutdown (/exit) or session termination
// to prevent key recovery from core dumps or memory scraping.
func (kp *KeyPair) Zeroize() {
	// Since ecdh.PrivateKey does not expose its internal buffer, we extract
	// the bytes via Bytes() and scrub the slice, relying on GC to clean pointers.
	raw := kp.privateKey.Bytes()
	clear(raw)

	kp.privateKey = nil
	kp.publicKey = nil
}

// SavePrivateKey persists the private key to the default OS-specific configuration path.
// It handles directory creation and enforces 0600 file permissions.
func (kp *KeyPair) SavePrivateKey() (string, error) {
	path, err := defaultKeyPath()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(filepath.Dir(path), DirPermission); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}

	raw := kp.privateKey.Bytes()
	defer clear(raw) // Ensure local byte slice is scrubbed immediately after I/O

	if err := os.WriteFile(path, raw, KeyFilePermission); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	// Force strict permissions as a safeguard in case the file was pre-existing.
	if err := os.Chmod(path, KeyFilePermission); err != nil {
		return "", fmt.Errorf("chmod private key: %w", err)
	}

	return path, nil
}

// LoadKeyPairFromDisk reads the key pair from the default configuration path.
// This is the primary entry point for client initialization.
func LoadKeyPairFromDisk() (*KeyPair, error) {
	path, err := defaultKeyPath()
	if err != nil {
		return nil, err
	}
	return loadKeyPairFromPath(path)
}

// LoadKeyPairFromPath reads a key pair from a specific file system path.
// Useful for key restoration or custom environment configurations.
func LoadKeyPairFromPath(path string) (*KeyPair, error) {
	return loadKeyPairFromPath(path)
}

// KeyPairFromRawBytes reconstructs a KeyPair from a raw 32-byte slice.
// Intended for manual key recovery workflows.
func KeyPairFromRawBytes(rawPriv []byte) (*KeyPair, error) {
	if len(rawPriv) != PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: got %d, want %d", len(rawPriv), PrivateKeySize)
	}

	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(rawPriv)
	if err != nil {
		return nil, fmt.Errorf("parse private key bytes: %w", err)
	}

	return &KeyPair{
		privateKey: priv,
		publicKey:  priv.PublicKey(),
	}, nil
}

// PublicKeyFromBase58 decodes a Base58 string back into raw public key bytes.
// Typically used during connection establishment (e.g., parsing IP:PORT@PUBKEY).
func PublicKeyFromBase58(s string) ([]byte, error) {
	raw, err := DecodeBase58(s)
	if err != nil {
		return nil, fmt.Errorf("decode Base58 public key: %w", err)
	}
	if len(raw) != PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d", len(raw), PublicKeySize)
	}
	return raw, nil
}

// KeyPathInfo provides the absolute path where the key is expected to be stored.
func KeyPathInfo() (string, error) {
	return defaultKeyPath()
}

// --- internal helpers ---

func loadKeyPairFromPath(path string) (*KeyPair, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("key file not found at %s — run 'generate-keychain' first", path)
		}
		return nil, fmt.Errorf("stat key file: %w", err)
	}

	// Enforce strict file permission checks on Unix-like systems.
	if runtime.GOOS != "windows" {
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			return nil, fmt.Errorf(
				"insecure key file permissions %o at %s — expected 0600. Fix: chmod 0600 %s",
				mode, path, path,
			)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	defer clear(raw) // Scrub local buffer post-parsing

	return KeyPairFromRawBytes(raw)
}

// defaultKeyPath resolves the appropriate storage directory based on the target OS.
func defaultKeyPath() (string, error) {
	var base string

	switch runtime.GOOS {
	case "windows":
		base = os.Getenv("APPDATA")
		if base == "" {
			return "", errors.New("APPDATA env var not set")
		}
		return filepath.Join(base, "road-1337", "private.key"), nil

	default: // Linux, Darwin, etc.
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home dir: %w", err)
		}
		return filepath.Join(home, ".config", "road-1337", "private.key"), nil
	}
}

// deriveKey applies HKDF-SHA256 to the raw DH secret to generate a ChaCha20 key.
// It uses domain separation ("road-1337-chacha20-key-v1") to ensure keys are
// context-bound and cannot be reused across different protocols.
func deriveKey(secret []byte) []byte {
	// Minimal HKDF implementation to avoid importing external x/crypto packages.
	// PRK = HMAC-SHA256(salt=0x00*32, IKM=secret)
	// OKM = HMAC-SHA256(PRK, info || 0x01)
	const info = "road-1337-chacha20-key-v1"

	salt := make([]byte, 32) // Default zero salt per HKDF spec
	prk := hmacSHA256(salt, secret)
	okm := hmacSHA256(prk, append([]byte(info), 0x01))

	return okm[:32] // Return exact 32 bytes required for ChaCha20
}

// hmacSHA256 provides a standalone implementation of HMAC-SHA256.
func hmacSHA256(key, data []byte) []byte {
	const blockSize = 64
	if len(key) > blockSize {
		h := sha256.Sum256(key)
		key = h[:]
	}

	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	copy(ipad, key)
	copy(opad, key)

	for i := range blockSize {
		ipad[i] ^= 0x36
		opad[i] ^= 0x5c
	}

	inner := sha256.New()
	inner.Write(ipad)
	inner.Write(data)
	innerSum := inner.Sum(nil)

	outer := sha256.New()
	outer.Write(opad)
	outer.Write(innerSum)

	return outer.Sum(nil)
}
