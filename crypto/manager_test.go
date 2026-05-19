package crypto

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/Code-Hex/go-generics-cache/policy/lfu"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
)

func TestSealedSerialization(t *testing.T) {
	now := time.Now().UTC()
	original := &Sealed{
		Blob:       []byte("test-blob"),
		DEK:        []byte("test-dek"),
		DEKVersion: "dek-v1",
		KEKVersion: "kek-v1",
		Timestamp:  &now,
	}

	serialized, err := original.Bytes()
	if err != nil {
		t.Fatalf("failed to serialize Sealed: %v", err)
	}

	deserialized, err := UnmarshalSealed(serialized)
	if err != nil {
		t.Fatalf("failed to deserialize Sealed: %v", err)
	}

	if !bytes.Equal(deserialized.Blob, original.Blob) {
		t.Errorf("expected Blob %q, got %q", original.Blob, deserialized.Blob)
	}
	if !bytes.Equal(deserialized.DEK, original.DEK) {
		t.Errorf("expected DEK %q, got %q", original.DEK, deserialized.DEK)
	}
	if deserialized.DEKVersion != original.DEKVersion {
		t.Errorf("expected DEKVersion %q, got %q", original.DEKVersion, deserialized.DEKVersion)
	}
	if deserialized.KEKVersion != original.KEKVersion {
		t.Errorf("expected KEKVersion %q, got %q", original.KEKVersion, deserialized.KEKVersion)
	}
	if deserialized.Timestamp == nil || !deserialized.Timestamp.Equal(*original.Timestamp) {
		t.Errorf("expected Timestamp %v, got %v", original.Timestamp, deserialized.Timestamp)
	}

	// Test unmarshal error
	_, err = UnmarshalSealed([]byte("invalid json"))
	if err == nil {
		t.Error("expected error for invalid json, got nil")
	}
}

func TestManagerCache(t *testing.T) {
	m := &Manager{
		cache: lfu.NewCache[string, []byte](),
	}

	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("failed to generate keyset: %v", err)
	}

	t.Run("Cache get miss", func(t *testing.T) {
		_, err := m.getDEKFromCache("nonexistent")
		if err == nil {
			t.Error("expected error for cache miss, got nil")
		}
	})

	t.Run("Cache add and hit", func(t *testing.T) {
		err := m.addDEKToCache("key1", kh)
		if err != nil {
			t.Fatalf("addDEKToCache failed: %v", err)
		}

		retrieved, err := m.getDEKFromCache("key1")
		if err != nil {
			t.Fatalf("getDEKFromCache failed: %v", err)
		}

		b1, _ := KeyHandleToBytes(kh)
		b2, _ := KeyHandleToBytes(retrieved)
		if !bytes.Equal(b1, b2) {
			t.Error("retrieved keyset does not match the original")
		}
	})
}

func TestManagerSealUnseal(t *testing.T) {
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("failed to generate keyset: %v", err)
	}

	m := &Manager{
		cache:        lfu.NewCache[string, []byte](),
		dekPlain:     kh,
		dekSealed:    []byte("fake-sealed-dek"),
		dekVersion:   "dek-v1",
		kekVersion:   "kek-v1",
		addTimestamp: true,
	}

	// Pre-load the cache so Unseal doesn't try to call m.kek.Decrypt
	err = m.addDEKToCache("dek-v1", kh)
	if err != nil {
		t.Fatalf("failed to preload cache: %v", err)
	}

	ctx := context.Background()
	plaintext := []byte("hello-world-secret-data")

	t.Run("Happy path with AAD context", func(t *testing.T) {
		ctxWithAAD := ContextWithAAD(ctx, AAD{Content: "test-aad"})
		sealed, err := m.Seal(ctxWithAAD, plaintext)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		if sealed.Timestamp == nil {
			t.Error("expected timestamp to be set, got nil")
		}
		if !bytes.Equal(sealed.DEK, m.dekSealed) {
			t.Errorf("expected DEK %q, got %q", m.dekSealed, sealed.DEK)
		}

		decrypted, err := m.Unseal(ctxWithAAD, sealed)
		if err != nil {
			t.Fatalf("Unseal failed: %v", err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("expected decrypted plaintext %q, got %q", plaintext, decrypted)
		}
	})

	t.Run("Without sealed timestamp Option", func(t *testing.T) {
		m.addTimestamp = false
		sealed, err := m.Seal(ctx, plaintext)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}
		if sealed.Timestamp != nil {
			t.Errorf("expected nil timestamp, got %v", sealed.Timestamp)
		}
	})

	t.Run("Seal / Unseal errors after shutdown", func(t *testing.T) {
		// Shutdown the manager
		m.isShutdown.Store(true)

		_, err := m.Seal(ctx, plaintext)
		if err == nil {
			t.Error("expected Seal to fail after shutdown, got nil")
		}

		_, err = m.Unseal(ctx, &Sealed{})
		if err == nil {
			t.Error("expected Unseal to fail after shutdown, got nil")
		}
	})
}
