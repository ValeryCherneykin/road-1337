package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// FuzzDecodeHeader performs fuzz testing on the primary 9-byte wire header parser.
// It ensures DecodeHeader gracefully handles random and malformed input without panicking,
// which is critical for protocol robustness against malicious or corrupted packets.
func FuzzDecodeHeader(f *testing.F) {
	// Seed with a valid header + payload to guide the fuzzer toward interesting cases
	validHdr := WireHeader{
		Type:       TypeMessage,
		ChunkIndex: 1,
		FileID:     1337,
	}.Encode()
	f.Add(append(validHdr, []byte("hello fuzz")...))

	f.Fuzz(func(t *testing.T, data []byte) {
		// We intentionally ignore return values — the goal is to ensure no panics
		_, _, _ = DecodeHeader(data)
	})
}

// FuzzDecodeFileHeader stresses the file metadata parser, including edge cases
// such as maximum filename length and potential integer overflow attacks.
//
// This is a security-critical fuzzer because malformed FileHeaderPayload
// could lead to memory corruption or incorrect file handling.
func FuzzDecodeFileHeader(f *testing.F) {
	// 1. Normal case
	fh := FileHeaderPayload{
		TotalSize:   1024 * 1024,
		TotalChunks: 8,
		FileID:      42,
		Filename:    "exploit_payload.sh",
	}
	validSeed, _ := EncodeFileHeader(fh)
	f.Add(validSeed)

	// 2. Maximum filename length (boundary test)
	fhMax := fh
	fhMax.Filename = string(bytes.Repeat([]byte("A"), 255))
	validSeedMax, _ := EncodeFileHeader(fhMax)
	f.Add(validSeedMax)

	// 3. Malicious payload attempting integer overflow on name length
	// (nameLen = 0xFFFF — should be safely rejected by bounds checking)
	killerPayload := make([]byte, 18)
	binary.BigEndian.PutUint16(killerPayload[16:], 0xFFFF)
	f.Add(killerPayload)

	f.Fuzz(func(t *testing.T, data []byte) {
		// The only requirement is that the parser never panics on adversarial input
		_, _ = DecodeFileHeader(data)
	})
}

// FuzzDecodeHandshake tests the initial 65-byte unencrypted handshake frame parser.
// This is the only unauthenticated frame in the entire protocol, making it a
// high-value target for fuzzing to prevent handshake-related crashes or exploits.
func FuzzDecodeHandshake(f *testing.F) {
	// Seed with a valid handshake
	hp := HandshakePayload{Version: Version}
	for i := 0; i < 32; i++ {
		hp.SenderPubKey[i] = byte(i)
		hp.RecipientKeyHash[i] = byte(i + 10)
	}
	f.Add(EncodeHandshake(hp))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeHandshake(data)
	})
}
