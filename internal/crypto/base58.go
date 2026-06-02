// Package crypto implements the cryptographic core of road-1337.
package crypto

import "fmt"

// base58Alphabet uses the Bitcoin alphabet.
// It deliberately excludes visually ambiguous characters such as 0 (zero), O (capital o),
// I (capital i), and l (lowercase L) to prevent human error during manual key distribution.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// encodeBase58 converts a byte slice into a Base58 string.
// This implementation is zero-dependency and intentionally handles leading zeros
// to preserve the exact byte length, which is critical for cryptographic keys.
func encodeBase58(input []byte) string {
	leadingZeros := 0
	for _, b := range input {
		if b != 0 {
			break
		}
		leadingZeros++
	}

	// Pre-allocate digits slice based on the mathematical upper bound
	// (log256(58) ≈ 1.36) to minimize heap allocations during conversion.
	digits := make([]byte, 0, len(input)*136/100+1)
	for _, b := range input {
		carry := int(b)
		for i := range digits {
			carry += int(digits[i]) << 8
			digits[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}

	result := make([]byte, leadingZeros, leadingZeros+len(digits))
	for i := range leadingZeros {
		result[i] = base58Alphabet[0]
	}
	for i := len(digits) - 1; i >= 0; i-- {
		result = append(result, base58Alphabet[digits[i]])
	}

	return string(result)
}

// decodeBase58 decodes a Base58 encoded string back into a byte slice.
// Returns an error if the string contains invalid characters not present in the alphabet.
func decodeBase58(s string) ([]byte, error) {
	// Pre-compute alphabet map for O(1) lookups instead of strings.Index
	alphabetMap := make(map[byte]int, 58)
	for i := range base58Alphabet {
		alphabetMap[base58Alphabet[i]] = i
	}

	leadingZeros := 0
	for i := range s {
		if s[i] != base58Alphabet[0] {
			break
		}
		leadingZeros++
	}

	// log58(256) ≈ 0.733
	decoded := make([]byte, 0, len(s)*733/1000+1)
	for i := range s {
		val, ok := alphabetMap[s[i]]
		if !ok {
			return nil, fmt.Errorf("invalid Base58 character %q at position %d", s[i], i)
		}

		carry := val
		for j := range decoded {
			carry += int(decoded[j]) * 58
			decoded[j] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			decoded = append(decoded, byte(carry&0xff))
			carry >>= 8
		}
	}

	result := make([]byte, leadingZeros, leadingZeros+len(decoded))
	for i := len(decoded) - 1; i >= 0; i-- {
		result = append(result, decoded[i])
	}

	return result, nil
}
