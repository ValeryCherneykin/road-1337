// Package crypto implements the cryptographic core of road-1337.
package crypto

import (
	"fmt"
	"math/big"
)

// base58Alphabet is the Bitcoin Base58 alphabet.
// Excludes visually ambiguous characters (0, O, I, l) to prevent
// human transcription errors when sharing public keys manually.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// EncodeBase58 converts a byte slice into a Base58 string.
//
// Uses math/big for the base conversion instead of a byte-level loop
// to avoid O(n²) CPU behaviour on large inputs (e.g. 32-byte keys).
// Leading zero bytes are preserved as '1' characters per the Bitcoin convention,
// which is critical for exact cryptographic key round-trips.
func EncodeBase58(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	// Count leading zero bytes; they map to leading '1' characters.
	leadingZeros := 0
	for leadingZeros < len(input) && input[leadingZeros] == 0 {
		leadingZeros++
	}

	n := new(big.Int).SetBytes(input)
	radix := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var digits []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, radix, mod)
		digits = append(digits, base58Alphabet[mod.Int64()])
	}

	// Allocate exact capacity: leading '1's + reversed digits.
	result := make([]byte, leadingZeros, leadingZeros+len(digits))
	for i := range leadingZeros {
		result[i] = base58Alphabet[0]
	}
	for i, j := leadingZeros, len(digits)-1; j >= 0; i, j = i+1, j-1 {
		result = append(result, digits[j])
	}
	return string(result)
}

// DecodeBase58 decodes a Base58 string back into a byte slice.
// Returns an error if any character is not in the Base58 alphabet.
//
// The inner lookup is a linear scan over the 58-character alphabet.
// For cryptographic key sizes (≤ 64 chars) this is negligible; an array
// lookup table would save ~58 ns per call but adds complexity for no
// practical gain at this scale.
func DecodeBase58(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, nil
	}

	leadingZeros := 0
	for leadingZeros < len(s) && s[leadingZeros] == base58Alphabet[0] {
		leadingZeros++
	}

	n := new(big.Int)
	radix := big.NewInt(58)

	for i := leadingZeros; i < len(s); i++ {
		ch := s[i]
		val := -1
		for idx := range len(base58Alphabet) {
			if base58Alphabet[idx] == ch {
				val = idx
				break
			}
		}
		if val < 0 {
			return nil, fmt.Errorf("invalid Base58 character %q at position %d", ch, i)
		}
		n.Mul(n, radix)
		n.Add(n, big.NewInt(int64(val)))
	}

	decoded := n.Bytes()
	result := make([]byte, leadingZeros+len(decoded))
	copy(result[leadingZeros:], decoded)
	return result, nil
}
