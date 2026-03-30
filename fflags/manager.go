package fflags

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/gcsblob"

	ffclient "github.com/thomaspoignant/go-feature-flag"
	"github.com/thomaspoignant/go-feature-flag/modules/core/dto"
)

const (
	defaultRefresh = 60 * time.Second
)

// Manager provides methods to manage and evaluate feature flags.
type Manager struct {
	client    *ffclient.GoFeatureFlag
	blobStore *BlobStore
	refresh   time.Duration
	mutex     sync.RWMutex
}

// Option is a functional option pattern for configuring a Manager.
type Option func(*Manager)

// WithRefresh configures the cache polling interval for the Manager.
func WithRefresh(refresh time.Duration) Option {
	return func(m *Manager) {
		m.refresh = refresh
	}
}

// NewManager initializes a new Manager with the provided storage URI and options.
func NewManager(blobstore string, opts ...Option) (*Manager, error) {
	blobStore, err := NewBlobStore(blobstore)
	if err != nil {
		return nil, err
	}

	m := &Manager{
		blobStore: blobStore,
		refresh:   defaultRefresh,
	}

	for _, opt := range opts {
		opt(m)
	}

	client, err := ffclient.New(ffclient.Config{
		PollingInterval: m.refresh,
		Retriever:       blobStore.Retriever(),
	})
	if err != nil {
		return nil, err
	}
	m.client = client

	return m, nil
}

// Close gracefully shuts down the underlying feature flag client.
func (m *Manager) Close() {
	m.client.Close()
}

// Client provides access to the initialized go-feature-flag evaluation client.
func (m *Manager) Client() *ffclient.GoFeatureFlag {
	return m.client
}

// Dump loads and returns all current feature flags from the underlying storage.
func (m *Manager) Dump(ctx context.Context) (map[string]dto.DTO, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.loadFlags(ctx)
}

func (m *Manager) storeFlags(ctx context.Context, flags map[string]dto.DTO) error {
	// Marshal flags
	data, err := yaml.Marshal(flags)
	if err != nil {
		return err
	}

	// Open the bucket
	bucket, err := blob.OpenBucket(ctx, m.blobStore.Bucket())
	if err != nil {
		return err
	}
	defer bucket.Close()

	// Create writer
	w, err := bucket.NewWriter(ctx, m.blobStore.Object(), nil)
	if err != nil {
		return err
	}
	defer w.Close()

	// Write the data
	if _, err := w.Write(data); err != nil {
		return err
	}
	w.Close()

	// Force cache refresh
	if !m.client.ForceRefresh() {
		return fmt.Errorf("failed to refresh cache")
	}

	return nil
}

func (m *Manager) loadFlags(ctx context.Context) (map[string]dto.DTO, error) {

	// Open the bucket
	bucket, err := blob.OpenBucket(ctx, m.blobStore.Bucket())
	if err != nil {
		return nil, err
	}
	defer bucket.Close()

	// Read the file
	r, err := bucket.NewReader(ctx, m.blobStore.Object(), nil)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var flags map[string]dto.DTO
	if err := yaml.Unmarshal(data, &flags); err != nil {
		return nil, err
	}

	return flags, nil
}
