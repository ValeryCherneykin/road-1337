// Package crypto implements the cryptographic subsystem for road-1337.
//
// Key management design:
//   - Private keys are encrypted at rest using Argon2id + ChaCha20-Poly1305.
//   - The master passphrase is never stored; it's used to derive the disk key on demand.
//   - Session keys are derived via X25519 ECDH + HKDF-SHA256 (NIST SP 800-56C).
//   - All sensitive byte slices are zeroed via clear() on every exit path.
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// PrivateKeySize is the byte length of an X25519 private key scalar.
	PrivateKeySize = 32
	// PublicKeySize is the byte length of an X25519 public key point.
	PublicKeySize = 32

	// KeyFilePermission enforces owner-only read/write on the config file.
	KeyFilePermission = 0o600
	// DirPermission is used for the config directory.
	DirPermission = 0o700
)

// diskConfig is the on-disk JSON representation of the encrypted private key.
// All binary fields are hex-encoded for human readability and JSON portability.
type diskConfig struct {
	// Salt is the Argon2id salt (16 bytes, hex-encoded).
	Salt string `json:"salt"`
	// Nonce is the ChaCha20-Poly1305 nonce (12 bytes, hex-encoded).
	Nonce string `json:"nonce"`
	// Ciphertext is the encrypted private key + Poly1305 tag (hex-encoded).
	Ciphertext string `json:"ciphertext"`
	// SeenManual tracks whether the user has read the onboarding guide.
	// Stored here to avoid a second sentinel file.
	SeenManual bool `json:"seen_manual"`
}

// KeyPair wraps an X25519 key pair with security-conscious methods.
// The private key is never exposed as a plain field; use controlled methods only.
type KeyPair struct {
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
}

// GenerateKeyPair creates a new random X25519 key pair using crypto/rand.
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate X25519 key: %w", err)
	}
	return &KeyPair{privateKey: priv, publicKey: priv.PublicKey()}, nil
}

// PublicKeyBase58 returns the public key in Base58 format for out-of-band sharing.
func (kp *KeyPair) PublicKeyBase58() string {
	return EncodeBase58(kp.publicKey.Bytes())
}

// PublicKeyHash returns SHA-256(publicKey), used as the relay routing table key.
func (kp *KeyPair) PublicKeyHash() [32]byte {
	return sha256.Sum256(kp.publicKey.Bytes())
}

// PublicKeyBytes returns a copy of the raw 32-byte public key.
func (kp *KeyPair) PublicKeyBytes() []byte {
	b := make([]byte, PublicKeySize)
	copy(b, kp.publicKey.Bytes())
	return b
}

// ECDH performs X25519 Diffie-Hellman with the peer's public key and derives
// a 32-byte session key via HKDF-SHA256.
//
// The raw DH output is zeroed immediately after HKDF extraction.
// The caller must zero the returned slice after use.
func (kp *KeyPair) ECDH(theirPublicKeyBytes []byte) ([]byte, error) {
	theirPub, err := ecdh.X25519().NewPublicKey(theirPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse peer public key: %w", err)
	}

	rawSecret, err := kp.privateKey.ECDH(theirPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation: %w", err)
	}
	defer clear(rawSecret)

	return deriveSessionKey(rawSecret), nil
}

// Zeroize overwrites private key material in RAM.
// Call on session end or process exit to reduce key recovery attack surface.
func (kp *KeyPair) Zeroize() {
	if kp.privateKey == nil {
		return
	}
	raw := kp.privateKey.Bytes()
	clear(raw)
	kp.privateKey = nil
	kp.publicKey = nil
}

// SavePrivateKeyEncrypted encrypts the private key with Argon2id + ChaCha20-Poly1305
// and writes it as a JSON config to the OS-specific config directory.
//
// Argon2id parameters: time=1, memory=64MB, threads=4. Resistant to GPU brute-force.
func (kp *KeyPair) SavePrivateKeyEncrypted(passphrase string) (string, error) {
	path, err := defaultConfigPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), DirPermission); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}

	// Random 16-byte Argon2id salt.
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	diskKey := deriveDiskKey(passphrase, salt)
	defer clear(diskKey)

	aead, err := chacha20poly1305.New(diskKey)
	if err != nil {
		return "", fmt.Errorf("init AEAD: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	rawPriv := kp.privateKey.Bytes()
	ciphertext := aead.Seal(nil, nonce, rawPriv, nil)
	clear(rawPriv)

	// Preserve SeenManual from existing config if present.
	seenManual := false
	if existing, err := readDiskConfig(path); err == nil {
		seenManual = existing.SeenManual
	}

	cfg := diskConfig{
		Salt:       hex.EncodeToString(salt),
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ciphertext),
		SeenManual: seenManual,
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, KeyFilePermission); err != nil {
		return "", fmt.Errorf("write config: %w", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, KeyFilePermission)
	}
	return path, nil
}

// LoadKeyPairFromDiskEncrypted decrypts and loads the key pair from the config file.
// Returns an error if the passphrase is wrong (authentication failure).
func LoadKeyPairFromDiskEncrypted(passphrase string) (*KeyPair, error) {
	path, err := defaultConfigPath()
	if err != nil {
		return nil, err
	}

	cfg, err := readDiskConfig(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no keychain found — run 'generate-keychain' first")
		}
		return nil, err
	}

	salt, _ := hex.DecodeString(cfg.Salt)
	nonce, _ := hex.DecodeString(cfg.Nonce)
	ciphertext, _ := hex.DecodeString(cfg.Ciphertext)

	diskKey := deriveDiskKey(passphrase, salt)
	defer clear(diskKey)

	aead, err := chacha20poly1305.New(diskKey)
	if err != nil {
		return nil, err
	}

	rawPriv, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("wrong passphrase or corrupted keychain")
	}
	defer clear(rawPriv)

	return KeyPairFromRawBytes(rawPriv)
}

// LoadKeyPairFromDisk loads an unencrypted private key (legacy / simple mode).
// Used when the binary format is raw 32 bytes (non-JSON config).
func LoadKeyPairFromDisk() (*KeyPair, error) {
	path, err := defaultKeyPath()
	if err != nil {
		return nil, err
	}
	return loadKeyPairFromPath(path)
}

// CheckFirstRun returns true if the user has not yet read the onboarding guide.
func CheckFirstRun() bool {
	path, err := defaultConfigPath()
	if err != nil {
		return true
	}
	cfg, err := readDiskConfig(path)
	if err != nil {
		return true
	}
	return !cfg.SeenManual
}

// MarkManualAsSeen records that the user has read the guide.
// Writes into the existing config JSON without changing key material.
func MarkManualAsSeen() error {
	path, err := defaultConfigPath()
	if err != nil {
		return err
	}
	cfg, err := readDiskConfig(path)
	if err != nil {
		return err
	}
	cfg.SeenManual = true
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, KeyFilePermission)
}

// KeyPairFromRawBytes reconstructs a KeyPair from a 32-byte private key scalar.
func KeyPairFromRawBytes(rawPriv []byte) (*KeyPair, error) {
	if len(rawPriv) != PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: got %d, want %d",
			len(rawPriv), PrivateKeySize)
	}
	priv, err := ecdh.X25519().NewPrivateKey(rawPriv)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return &KeyPair{privateKey: priv, publicKey: priv.PublicKey()}, nil
}

// PublicKeyFromBase58 decodes a Base58 public key string.
func PublicKeyFromBase58(s string) ([]byte, error) {
	raw, err := DecodeBase58(s)
	if err != nil {
		return nil, fmt.Errorf("decode Base58 public key: %w", err)
	}
	if len(raw) != PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: got %d, want %d",
			len(raw), PublicKeySize)
	}
	return raw, nil
}

// --- internal helpers ---

func readDiskConfig(path string) (diskConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return diskConfig{}, err
	}
	var cfg diskConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return diskConfig{}, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

func loadKeyPairFromPath(path string) (*KeyPair, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("key file not found at %s — run 'generate-keychain' first", path)
		}
		return nil, err
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("insecure permissions on %s — run: chmod 0600 %s", path, path)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return KeyPairFromRawBytes(raw)
}

// defaultConfigPath returns the OS-specific path to the JSON config file.
// Linux/macOS: ~/.config/road-1337/config.json
// Windows:     %APPDATA%\road-1337\config.json
func defaultConfigPath() (string, error) {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("APPDATA")
		if base == "" {
			return "", errors.New("APPDATA env var not set")
		}
		return filepath.Join(base, "road-1337", "config.json"), nil
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home dir: %w", err)
		}
		return filepath.Join(home, ".config", "road-1337", "config.json"), nil
	}
}

// defaultKeyPath returns the legacy unencrypted key path (raw bytes).
func defaultKeyPath() (string, error) {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("APPDATA")
		if base == "" {
			return "", errors.New("APPDATA env var not set")
		}
		return filepath.Join(base, "road-1337", "private.key"), nil
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("get home dir: %w", err)
		}
		return filepath.Join(home, ".config", "road-1337", "private.key"), nil
	}
}

// deriveSessionKey applies HKDF-SHA256 to the raw ECDH output.
// Uses a fixed info string for domain separation from disk key derivation.
func deriveSessionKey(rawSecret []byte) []byte {
	r := hkdf.New(sha256.New, rawSecret, nil, []byte("road-1337-chacha20-session-key-v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		// HKDF over SHA-256 with 32-byte output cannot fail given valid inputs.
		panic("hkdf: " + err.Error())
	}
	return key
}

// deriveDiskKey applies Argon2id to derive a 32-byte key from a passphrase.
// Parameters are deliberately conservative: 64 MB RAM, 4 threads, 1 time iteration.
func deriveDiskKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}
