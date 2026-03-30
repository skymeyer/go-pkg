package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	sm "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/Code-Hex/go-generics-cache/policy/lfu"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/rs/zerolog/log"
)

var (
	manager     *Manager
	onceManager sync.Once
)

func Initialize(ctx context.Context, kekResource, dekResource string, opts ...ManagerOption) error {
	var err error
	onceManager.Do(func() {
		var tmpManager *Manager
		tmpManager, err = NewManager(ctx, kekResource, dekResource, opts...)
		if err == nil {
			manager = tmpManager
		}
	})
	return err
}

func Seal(ctx context.Context, plain []byte) (*Sealed, error) {
	return manager.Seal(ctx, plain)
}

func Unseal(ctx context.Context, sealed *Sealed) ([]byte, error) {
	return manager.Unseal(ctx, sealed)
}

func Close() error {
	return manager.Close()
}

type Sealed struct {
	Blob       []byte     `json:"blob"`
	DEK        []byte     `json:"dek"`
	DEKVersion string     `json:"dek_version"`
	KEKVersion string     `json:"kek_version"`
	Timestamp  *time.Time `json:"timestamp"`
}

func (s *Sealed) Bytes() ([]byte, error) {
	return json.Marshal(s)
}

func UnmarshalSealed(b []byte) (*Sealed, error) {
	var s Sealed
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

type ManagerOption func(*Manager)

func WithSealedTimestamp() ManagerOption {
	return func(m *Manager) {
		m.addTimestamp = true
	}
}

func NewManager(ctx context.Context, kekResource, dekResource string, opts ...ManagerOption) (*Manager, error) {
	m := &Manager{
		kekResource: kekResource,
		dekResource: dekResource,
		cache:       lfu.NewCache[string, []byte](),
	}

	for _, opt := range opts {
		opt(m)
	}

	// Initialize KEK
	kek, err := NewKMS(ctx, kekResource)
	if err != nil {
		return nil, err
	}
	m.kek = kek

	// Initialize DEK
	if err := m.refreshDEK(ctx); err != nil {
		return nil, err
	}

	return m, nil
}

type Manager struct {
	kekResource string // The resource name of the KEK to use
	dekResource string // The resource name of the DEK to use
	kekVersion  string // The version of the KEK in use
	dekVersion  string // The version of the DEK in use

	cache        *lfu.Cache[string, []byte] // Cache for plain DEKs
	kek          *KMS                       // KEK KMS service
	dekPlain     *keyset.Handle             // Active plain DEK key
	dekSealed    []byte                     // Encrypted DEK
	addTimestamp bool

	mutex      sync.Mutex  // Mutex for thread safety
	isShutdown atomic.Bool // Flag to indicate if the manager is shutdown
}

func (m *Manager) Seal(ctx context.Context, plain []byte) (*Sealed, error) {
	if m.isShutdown.Load() {
		return nil, fmt.Errorf("manager is shutdown")
	}

	a, err := aead.New(m.dekPlain)
	if err != nil {
		return nil, fmt.Errorf("failed to create aead: %w", err)
	}

	blob, err := a.Encrypt(plain, AADJSONFromContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt blob: %w", err)
	}

	s := &Sealed{
		Blob:       blob,
		DEK:        m.dekSealed,
		DEKVersion: m.dekVersion,
		KEKVersion: m.kekVersion,
	}
	if m.addTimestamp {
		now := time.Now().UTC()
		s.Timestamp = &now
	}
	return s, nil
}

func (m *Manager) Unseal(ctx context.Context, sealed *Sealed) ([]byte, error) {
	if m.isShutdown.Load() {
		return nil, fmt.Errorf("manager is shutdown")
	}

	// Decrypt the DEK
	var (
		dek *keyset.Handle
		err error
	)
	dek, err = m.getDEKFromCache(sealed.DEKVersion)
	if err != nil {
		khBytes, err := m.kek.Decrypt(ctx, sealed.DEK)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt dek: %w", err)
		}
		reader := keyset.NewJSONReader(bytes.NewReader(khBytes))
		dek, err = insecurecleartextkeyset.Read(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read dek: %w", err)
		}
		m.addDEKToCache(sealed.DEKVersion, dek)
	}

	if dek == nil {
		return nil, fmt.Errorf("dek is nil and should not be")
	}

	// Decrypt the blob
	a, err := aead.New(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create aead: %w", err)
	}

	blob, err := a.Decrypt(sealed.Blob, AADJSONFromContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt blob: %w", err)
	}

	return blob, nil
}

func (m *Manager) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.isShutdown.Store(true)

	if m.isShutdown.Load() {
		return fmt.Errorf("manager is shutdown")
	}

	var errs []error
	if err := m.kek.Close(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing manager: %v", errs)
	}
	return nil
}

func (m *Manager) addDEKToCache(name string, kh *keyset.Handle) error {
	b, err := KeyHandleToBytes(kh)
	if err != nil {
		log.Error().Err(err).Str("name", name).Msg("failed to encode dek")
		return fmt.Errorf("failed to encode dek: %w", err)
	}
	log.Debug().Str("name", name).Msg("cache add")
	m.cache.Set(name, b)
	return nil
}

func (m *Manager) getDEKFromCache(name string) (*keyset.Handle, error) {
	b, ok := m.cache.Get(name)
	if !ok {
		log.Debug().Str("name", name).Msg("cache miss")
		return nil, fmt.Errorf("dek not found in cache")
	}

	log.Debug().Str("name", name).Msg("cache hit")
	return BytesToKeyHandle(b)
}

func (m *Manager) refreshDEK(ctx context.Context) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	client, err := sm.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create secretmanager client: %w", err)
	}
	defer client.Close()

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: m.dekResource + "/versions/latest",
	}

	result, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to access secret version: %w", err)
	}
	m.dekVersion = result.Name

	// Import the currently active DEK
	reader := keyset.NewJSONReader(bytes.NewReader(result.Payload.Data))
	kh, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		return err
	}
	log.Debug().Str("key", kh.String()).Msg("active dek")
	m.dekPlain = kh

	m.addDEKToCache(m.dekVersion, kh)

	// Encrypt DEK with KEK
	buf := new(bytes.Buffer)
	writer := keyset.NewJSONWriter(buf)
	if err := insecurecleartextkeyset.Write(kh, writer); err != nil {
		return fmt.Errorf("failed to write keyset: %w", err)
	}

	dekSealed, version, err := m.kek.Encrypt(ctx, buf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to encrypt dek: %w", err)
	}
	m.dekSealed = dekSealed
	m.kekVersion = version

	return nil
}
