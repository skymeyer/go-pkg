package crypto

import (
	"bytes"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	// Test requesting zero bytes
	zero := RandomBytes(0)
	if len(zero) != 0 {
		t.Errorf("expected 0 bytes, got %d", len(zero))
	}

	// Test requesting specific lengths
	lengths := []int{1, 4, 8, 16, 32, 64, 128}
	for _, l := range lengths {
		b := RandomBytes(l)
		if len(b) != l {
			t.Errorf("expected %d bytes, got %d", l, len(b))
		}
	}

	// Test uniqueness across multiple runs (for reasonably large size)
	b1 := RandomBytes(16)
	b2 := RandomBytes(16)
	if bytes.Equal(b1, b2) {
		t.Error("two consecutive calls to RandomBytes(16) produced identical outputs; CSPRNG may not be working correctly")
	}
}
