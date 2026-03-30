package fflags_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.skymeyer.dev/pkg/fflags"
)

func TestServingStatus(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()

	flagsPath := filepath.Join(tmpDir, "flags.yaml")
	if err := os.WriteFile(flagsPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write initial flags.yaml: %v", err)
	}

	uri := "file://" + filepath.ToSlash(tmpDir) + "/flags.yaml"
	manager, err := fflags.NewManager(uri)
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}
	defer manager.Close()

	srv := "test-service"

	// It shouldn't be serving initially (default is false)
	isServing, _ := manager.IsServing(ctx, srv)
	if isServing {
		t.Errorf("expected service to not be serving")
	}

	// Create serving flag
	err = manager.CreateServing(ctx, srv, fflags.SERVING_STATUS_SERVING)
	if err != nil {
		t.Fatalf("CreateServing failed: %v", err)
	}

	status, err := manager.GetServing(ctx, srv)
	if err != nil {
		t.Errorf("GetServing failed: %v", err)
	}
	if status != fflags.SERVING_STATUS_SERVING {
		t.Errorf("expected status 'serving', got %s", status)
	}

	// Set to not-serving
	err = manager.SetServing(ctx, srv, fflags.SERVING_STATUS_NOT_SERVING)
	if err != nil {
		t.Fatalf("SetServing failed: %v", err)
	}

	isServing, err = manager.IsServing(ctx, srv)
	if isServing {
		t.Errorf("expected service to not be serving after update")
	}

	// Try to create an already existing flag (should error)
	err = manager.CreateServing(ctx, srv, fflags.SERVING_STATUS_SERVING)
	if err == nil {
		t.Fatalf("CreateServing unexpectedly succeeded for existing flag")
	}

	// Delete serving flag
	err = manager.DeleteServing(ctx, srv)
	if err != nil {
		t.Fatalf("DeleteServing failed: %v", err)
	}

	// Verify it reverts to default (not serving)
	isServing, _ = manager.IsServing(ctx, srv)
	if isServing {
		t.Errorf("expected service to not be serving after delete")
	}

	// Try to delete an already deleted flag (should error)
	err = manager.DeleteServing(ctx, srv)
	if err == nil {
		t.Fatalf("DeleteServing unexpectedly succeeded for non-existent flag")
	}
}

func TestServingStatusStrings(t *testing.T) {
	s := fflags.SERVING_STATUS_SERVING
	if s.String() != "serving" {
		t.Errorf("expected 'serving', got %s", s.String())
	}
	
	sp := s.StringP()
	if sp == nil || *sp != "serving" {
		t.Errorf("expected 'serving' pointer, got %v", sp)
	}
}
