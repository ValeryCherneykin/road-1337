// Package crypto implements the network-level encryption layer for road-1337.
package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// PacketSize defines the strict, fixed size of every network packet (4KB).
	// Uniform packet sizes prevent Deep Packet Inspection (DPI) firewalls from
	// fingerprinting or classifying application traffic based on payload lengths.
	PacketSize = 4096

	// NonceSize defines the standard nonce length for ChaCha20-Poly1305 (12 bytes).
	NonceSize = chacha20poly1305.NonceSize

	// TagSize defines the overhead of the Poly1305 Message Authentication Code (16 bytes).
	TagSize = 16

	// MaxPlaintextSize defines the upper bound for the user data payload inside a single packet.
	// Calculated as: PacketSize - NonceSize - TagSize - 2 bytes (for length prefix).
	MaxPlaintextSize = PacketSize - NonceSize - TagSize - 2
)

// Session manages the symmetric AEAD state for an active connection.
// It wraps a ChaCha20-Poly1305 cipher instance and retains a local key copy for safe zeroization.
type Session struct {
	aead cipher.AEAD
	key  []byte
}

// NewSession initializes a secure encryption session using a 32-byte symmetric key.
// The key is typically derived from an X25519 ECDH key exchange followed by HKDF-SHA256.
func NewSession(key []byte) (*Session, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create chacha20poly1305: %w", err)
	}

	// Make a defensive copy of the key to gain explicit control over its memory lifecycle.
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &Session{
		aead: aead,
		key:  keyCopy,
	}, nil
}

// Seal transforms a variable-length plaintext slice into a fixed-size 4096-byte encrypted packet.
// It applies padding BEFORE encryption to mitigate traffic analysis attacks and guarantee
// strict cryptographic payload integrity.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPlaintextSize {
		return nil, fmt.Errorf("plaintext too large: %d > %d", len(plaintext), MaxPlaintextSize)
	}

	// 1. Allocate a structured buffer for the unencrypted payload (Plaintext + Padding).
	innerSize := PacketSize - NonceSize - TagSize
	innerPayload := make([]byte, innerSize)

	// 2. Encode the actual plaintext length into the first 2 bytes (Big-Endian).
	binary.BigEndian.PutUint16(innerPayload[0:2], uint16(len(plaintext)))

	// 3. Position user data immediately following the length prefix.
	copy(innerPayload[2:], plaintext)

	// 4. Fill the remaining buffer space with cryptographically secure random padding to blind DPI.
	paddingStart := 2 + len(plaintext)
	if _, err := io.ReadFull(rand.Reader, innerPayload[paddingStart:]); err != nil {
		return nil, fmt.Errorf("generate padding: %w", err)
	}

	// 5. Generate a unique 12-byte nonce required for safe AEAD invocation.
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// 6. Encrypt the entire inner payload block (including the random padding).
	ciphertext := s.aead.Seal(nil, nonce, innerPayload, nil)
	clear(innerPayload) // Instantly scrub transient plaintext bytes from RAM

	// 7. Construct the final wire packet: [Nonce: 12B] + [Ciphertext + Tag: 4084B]
	finalPacket := make([]byte, PacketSize)
	copy(finalPacket[:NonceSize], nonce)
	copy(finalPacket[NonceSize:], ciphertext)

	return finalPacket, nil
}

// Open authenticates and decrypts a fixed-size 4096-byte network packet.
// It isolates the original plaintext payload and strips away any random padding.
func (s *Session) Open(packet []byte) ([]byte, error) {
	if len(packet) != PacketSize {
		return nil, fmt.Errorf("invalid packet size: got %d, want %d", len(packet), PacketSize)
	}

	// 1. Isolate the nonce and the encrypted ciphertext boundaries.
	nonce := packet[:NonceSize]
	ciphertext := packet[NonceSize:]

	// 2. Decrypt the full payload block. AEAD automatically validates packet authentication.
	innerPayload, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: authentication failed (tampered packet or wrong key)")
	}
	defer clear(innerPayload) // Ensure decrypted buffer is scrubbed upon function exit

	// 3. Extract the original payload length from the header.
	origLen := int(binary.BigEndian.Uint16(innerPayload[0:2]))
	if origLen > len(innerPayload)-2 {
		return nil, fmt.Errorf("corrupted internal length prefix: %d", origLen)
	}

	// 4. Allocate and extract the clean plaintext payload, excluding the padding bytes.
	result := make([]byte, origLen)
	copy(result, innerPayload[2:2+origLen])

	return result, nil
}

// Zeroize securely overwrites secret key materials and destroys the AEAD state.
// Must be executed upon session teardown or application exit to prevent post-quantum RAM scanning.
func (s *Session) Zeroize() {
	if s.key != nil {
		clear(s.key)
		s.key = nil
	}
	s.aead = nil
}
