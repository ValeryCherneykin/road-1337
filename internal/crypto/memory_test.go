package crypto

import (
	"testing"
	"unsafe"
)

// TestSession_Zeroize verifies that the Zeroize method correctly and securely
// wipes all sensitive key material from memory.
//
// This is a critical security test. We use unsafe pointers to inspect the
// actual memory location after zeroization to ensure no remnants of the key
// remain in RAM — protecting against cold-boot attacks and memory scraping.
func TestSession_Zeroize(t *testing.T) {
	// 1. Create a session containing sensitive key material
	s := &Session{
		key: []byte("SECRET_KEY_MUST_BE_ERASED_NOW_!!!"),
	}

	// 2. Capture the raw memory address of the key before zeroization
	// This allows us to inspect the physical memory even after the slice header is cleared
	ptr := unsafe.SliceData(s.key)
	originalLen := len(s.key)

	// 3. Perform zeroization — this is the main operation under test
	s.Zeroize()

	// 4. Inspect the original memory region directly
	// We deliberately read the raw memory where the key used to live
	memView := unsafe.Slice(ptr, originalLen)

	for i, b := range memView {
		if b != 0 {
			t.Errorf("Byte at index %d was not zeroed, value: 0x%02x", i, b)
		}
	}

	// Additional safety check: the slice itself should be nilled out
	if s.key != nil {
		t.Error("s.key slice header was not cleared after Zeroize")
	}
}
