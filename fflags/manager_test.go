package fflags_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.skymeyer.dev/pkg/fflags"
)

func TestManager_Dump(t *testing.T) {
	ctx := context.Background()

	// Create a temporary directory for the fileblob
	tmpDir := t.TempDir()

	// Create an empty flags.yaml file initially
	flagsPath := filepath.Join(tmpDir, "flags.yaml")
	if err := os.WriteFile(flagsPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write initial flags.yaml: %v", err)
	}

	uri := "file://" + filepath.ToSlash(tmpDir) + "/flags.yaml"
	manager, err := fflags.NewManager(uri, fflags.WithRefresh(1*time.Second))
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer manager.Close()

	if manager.Client() == nil {
		t.Fatalf("expected non-nil client")
	}

	// Dump should return empty map
	dump, err := manager.Dump(ctx)
	if err != nil {
		t.Fatalf("Dump failed: %v", err)
	}
	if len(dump) != 0 {
		t.Errorf("expected empty dump, got %d items", len(dump))
	}
}
