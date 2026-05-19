package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestAADContext(t *testing.T) {
	ctx := context.Background()

	// Test default / empty context
	emptyAAD := AADFromContext(ctx)
	if emptyAAD.Content != "" {
		t.Errorf("expected empty AAD, got: %+v", emptyAAD)
	}

	emptyJSON := AADJSONFromContext(ctx)
	var decodedEmpty AAD
	if err := json.Unmarshal(emptyJSON, &decodedEmpty); err != nil {
		t.Fatalf("failed to unmarshal empty AAD JSON: %v", err)
	}
	if decodedEmpty.Content != "" {
		t.Errorf("expected empty AAD from empty context JSON, got: %+v", decodedEmpty)
	}

	// Test context with AAD value
	expectedAAD := AAD{Content: "test-aad-content"}
	ctxWithAAD := ContextWithAAD(ctx, expectedAAD)

	retrievedAAD := AADFromContext(ctxWithAAD)
	if retrievedAAD.Content != expectedAAD.Content {
		t.Errorf("expected retrieved AAD content to be %q, got %q", expectedAAD.Content, retrievedAAD.Content)
	}

	jsonBytes := AADJSONFromContext(ctxWithAAD)
	var decoded AAD
	if err := json.Unmarshal(jsonBytes, &decoded); err != nil {
		t.Fatalf("failed to unmarshal AAD JSON: %v", err)
	}
	if decoded.Content != expectedAAD.Content {
		t.Errorf("expected decoded AAD content to be %q, got %q", expectedAAD.Content, decoded.Content)
	}

	// Verify raw JSON representation
	expectedRaw, _ := json.Marshal(expectedAAD)
	if !bytes.Equal(jsonBytes, expectedRaw) {
		t.Errorf("expected JSON bytes %s, got %s", string(expectedRaw), string(jsonBytes))
	}
}
