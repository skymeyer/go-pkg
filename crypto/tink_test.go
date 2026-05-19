package crypto

import (
	"bytes"
	"testing"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
)

func TestTinkHelpers(t *testing.T) {
	// Generate a valid keyset handle for testing
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("failed to create initial keyset handle: %v", err)
	}

	t.Run("JSON Serialization Roundtrip", func(t *testing.T) {
		jsonBytes, err := KeyHandleToJSON(kh)
		if err != nil {
			t.Fatalf("KeyHandleToJSON failed: %v", err)
		}

		decodedKh, err := JSONToKeyHandle(jsonBytes)
		if err != nil {
			t.Fatalf("JSONToKeyHandle failed: %v", err)
		}

		// Verify we can serialize the decoded back to JSON and get the same output
		jsonBytes2, err := KeyHandleToJSON(decodedKh)
		if err != nil {
			t.Fatalf("second KeyHandleToJSON failed: %v", err)
		}

		if !bytes.Equal(jsonBytes, jsonBytes2) {
			t.Error("roundtrip JSON serialization did not produce identical bytes")
		}
	})

	t.Run("JSON Serialization Errors", func(t *testing.T) {
		_, err := JSONToKeyHandle([]byte("invalid json"))
		if err == nil {
			t.Error("expected error when decoding invalid JSON, got nil")
		}
	})

	t.Run("Binary Serialization Roundtrip", func(t *testing.T) {
		binBytes, err := KeyHandleToBytes(kh)
		if err != nil {
			t.Fatalf("KeyHandleToBytes failed: %v", err)
		}

		decodedKh, err := BytesToKeyHandle(binBytes)
		if err != nil {
			t.Fatalf("BytesToKeyHandle failed: %v", err)
		}

		// Verify we can serialize the decoded back to bytes and get the same output
		binBytes2, err := KeyHandleToBytes(decodedKh)
		if err != nil {
			t.Fatalf("second KeyHandleToBytes failed: %v", err)
		}

		if !bytes.Equal(binBytes, binBytes2) {
			t.Error("roundtrip binary serialization did not produce identical bytes")
		}
	})

	t.Run("Binary Serialization Errors", func(t *testing.T) {
		_, err := BytesToKeyHandle([]byte{0x00, 0x01, 0x02})
		if err == nil {
			t.Error("expected error when decoding invalid binary payload, got nil")
		}
	})
}
