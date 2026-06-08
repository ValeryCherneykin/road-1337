// Package crypto — symmetric encryption layer for road-1337.
//
// Every packet on the wire is exactly PacketSize (4096) bytes.
// Uniform size hides message length from network observers and DPI.
//
// Wire format (all 4096 bytes):
//
//	[nonce: 12 B][ciphertext+tag: innerSize+16 B]
//
// innerSize = PacketSize - NonceSize - TagSize = 4068 bytes.
// The inner plaintext is always padded to innerSize before encryption:
//
//	[origLen: 2 B][plaintext: N B][random padding: innerSize-2-N B]
//
// This means the AEAD always encrypts exactly innerSize bytes, producing
// exactly innerSize+TagSize bytes of ciphertext. No ambiguity on decryption.
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
	// PacketSize is the exact size of every wire packet.
	// Uniform sizing prevents traffic analysis via packet length.
	PacketSize = 4096

	// NonceSize is the ChaCha20-Poly1305 nonce length (RFC 7539: 12 bytes).
	NonceSize = chacha20poly1305.NonceSize

	// TagSize is the Poly1305 authentication tag length (16 bytes).
	TagSize = 16

	// innerSize is the fixed-length plaintext block fed to AEAD.
	// Always padded to this size before encryption.
	innerSize = PacketSize - NonceSize - TagSize // 4068 bytes

	// MaxPlaintextSize is the maximum user payload per packet.
	// 2 bytes are reserved for the origLen prefix inside the inner block.
	MaxPlaintextSize = innerSize - 2 // 4066 bytes
)

// Session is a ChaCha20-Poly1305 AEAD session tied to one connection.
// Create with NewSession; call Zeroize when the connection ends.
type Session struct {
	aead cipher.AEAD
	key  []byte // retained for Zeroize
}

// NewSession initialises a Session from a 32-byte symmetric key.
// The key is typically the output of KeyPair.ECDH → HKDF-SHA256.
func NewSession(key []byte) (*Session, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size: got %d, want %d",
			len(key), chacha20poly1305.KeySize)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("init chacha20poly1305: %w", err)
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &Session{aead: aead, key: keyCopy}, nil
}

// Seal encrypts plaintext and returns exactly PacketSize bytes.
//
// Encryption steps:
//  1. Build innerSize-byte inner block: [origLen:2][plaintext:N][rand padding: rest]
//  2. Generate a random 12-byte nonce.
//  3. AEAD.Seal(inner) → ciphertext of exactly innerSize+TagSize bytes.
//  4. Wire packet = nonce || ciphertext.
//
// The padded inner block is always the same size regardless of plaintext length,
// so the ciphertext is always the same size. No length leakage.
func (s *Session) Seal(plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPlaintextSize {
		return nil, fmt.Errorf("plaintext too large: %d > %d",
			len(plaintext), MaxPlaintextSize)
	}

	// Step 1: build padded inner block.
	inner := make([]byte, innerSize)
	binary.BigEndian.PutUint16(inner[0:2], uint16(len(plaintext)))
	copy(inner[2:], plaintext)
	// inner[2+len(plaintext):] is already zero from make().
	// Fill with random bytes for padding to prevent statistical analysis
	// of the zero-byte region when plaintext is short.
	if _, err := io.ReadFull(rand.Reader, inner[2+len(plaintext):]); err != nil {
		return nil, fmt.Errorf("generate padding: %w", err)
	}

	// Step 2: random nonce.
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		clear(inner)
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Step 3: encrypt. Seal appends tag → len(ciphertext) = innerSize + TagSize.
	ciphertext := s.aead.Seal(nil, nonce[:], inner, nil)
	clear(inner) // scrub plaintext from RAM immediately

	// Step 4: assemble wire packet.
	// Invariant: len(nonce) + len(ciphertext) == NonceSize + innerSize + TagSize == PacketSize.
	packet := make([]byte, PacketSize)
	copy(packet[:NonceSize], nonce[:])
	copy(packet[NonceSize:], ciphertext)

	return packet, nil
}

// Open decrypts a PacketSize-byte wire packet and returns the original plaintext.
// Returns an error if authentication fails (tampered packet or wrong key).
func (s *Session) Open(packet []byte) ([]byte, error) {
	if len(packet) != PacketSize {
		return nil, fmt.Errorf("invalid packet size: got %d, want %d",
			len(packet), PacketSize)
	}

	nonce := packet[:NonceSize]
	// ciphertext is exactly innerSize+TagSize bytes — always, by construction.
	ciphertext := packet[NonceSize:]

	inner, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Do not expose internal error details; authentication failure is enough.
		return nil, fmt.Errorf("decrypt: authentication failed (tampered or wrong key)")
	}
	defer clear(inner)

	if len(inner) < 2 {
		return nil, fmt.Errorf("inner block too short after decryption")
	}

	origLen := int(binary.BigEndian.Uint16(inner[0:2]))
	if origLen > len(inner)-2 {
		return nil, fmt.Errorf("corrupted length prefix: %d > %d", origLen, len(inner)-2)
	}

	out := make([]byte, origLen)
	copy(out, inner[2:2+origLen])
	return out, nil
}

// Zeroize overwrites the session key in RAM and invalidates the AEAD instance.
// Must be called when the session ends to prevent key material recovery from
// memory dumps or cold-boot attacks.
func (s *Session) Zeroize() {
	if s.key != nil {
		clear(s.key)
		s.key = nil
	}
	s.aead = nil
}
