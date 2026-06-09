package crypto

import (
	"bytes"
	"testing"
)

// FuzzBase58 performs round-trip fuzz testing of the Base58 encoding/decoding
// functions. It ensures that any arbitrary byte sequence can be encoded and
// then perfectly decoded back to the original data.
//
// This is critical for cryptographic key handling, as Base58 is used to
// display and share public keys. Any encoding/decoding mismatch could lead
// to corrupted keys or user confusion.
func FuzzBase58(f *testing.F) {
	// Seed the fuzzer with interesting cases to improve coverage
	f.Add([]byte("Hello, world!"))
	f.Add([]byte{0, 0, 0, 1, 2, 3})       // leading zeros (important for key encoding)
	f.Add(bytes.Repeat([]byte{0xFF}, 32)) // maximum byte values

	f.Fuzz(func(t *testing.T, data []byte) {
		// Encode to Base58
		encoded := EncodeBase58(data)

		// Decode back
		decoded, err := DecodeBase58(encoded)
		if err != nil {
			t.Fatalf("failed to decode valid encoded data: %v", err)
		}

		// Verify perfect round-trip
		if !bytes.Equal(data, decoded) {
			t.Errorf("round-trip failed: got %x, want %x", decoded, data)
		}
	})
}

// FuzzBase58Invalid tests the decoder's behavior on invalid or visually
// ambiguous input. Base58 deliberately excludes characters like 0, O, l, I
// to prevent human transcription errors when sharing keys manually.
//
// The test ensures the decoder gracefully handles garbage input without panicking.
func FuzzBase58Invalid(f *testing.F) {
	// Seed with characters that are intentionally excluded from the alphabet
	// as well as other invalid symbols
	f.Add([]byte("0"))
	f.Add([]byte("O"))
	f.Add([]byte("l"))
	f.Add([]byte("I"))
	f.Add([]byte("!!!"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// We expect DecodeBase58 to return an error on invalid input.
		// The main goal is to ensure it never panics.
		_, _ = DecodeBase58(string(data))
	})
}
