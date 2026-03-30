package fflags_test

import (
	"testing"

	"go.skymeyer.dev/pkg/fflags"
)

func TestNewBlobStore(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{
			name:    "valid gs URI",
			in:      "gs://my-bucket/flags.yaml",
			wantErr: false,
		},
		{
			name:    "valid file URI",
			in:      "file:///tmp/my-dir/flags.yaml",
			wantErr: false,
		},
		{
			name:    "invalid URI missing file extension",
			in:      "gs://my-bucket/flags",
			wantErr: true,
		},
		{
			name:    "invalid scheme",
			in:      "http://example.com/flags.yaml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fflags.NewBlobStore(tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewBlobStore() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == nil {
				t.Errorf("NewBlobStore() returned a nil *BlobStore without error")
			}
		})
	}
}

func TestBlobStore_Methods(t *testing.T) {
	b, err := fflags.NewBlobStore("gs://my-bucket/flags/test.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got := b.Bucket(); got != "gs://my-bucket" {
		t.Errorf("Bucket() = %v, want %v", got, "gs://my-bucket")
	}

	if got := b.Object(); got != "flags/test.yaml" {
		t.Errorf("Object() = %v, want %v", got, "flags/test.yaml")
	}

	if got := b.Retriever(); got == nil {
		t.Errorf("Retriever() returned nil")
	}
}
