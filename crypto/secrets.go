package crypto

import (
	"bytes"
	"context"
	"fmt"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	sm "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

type SecretManager struct {
	client    *secretmanager.Client
	projectID string
}

func NewSecretManager(ctx context.Context, projectID string) (*SecretManager, error) {
	client, err := sm.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secretmanager client: %w", err)
	}
	return &SecretManager{client: client, projectID: projectID}, nil
}

func (m *SecretManager) Close() {
	m.client.Close()
}

func (m *SecretManager) FetchSecret(ctx context.Context, name string) ([]byte, error) {
	resource := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", m.projectID, name)
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: resource,
	}

	result, err := m.client.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %w", err)
	}
	return result.Payload.Data, nil
}

func (m *SecretManager) SetSecret(ctx context.Context, name string, value []byte) (string, error) {
	req := &secretmanagerpb.AddSecretVersionRequest{
		Parent: fmt.Sprintf("projects/%s/secrets/%s", m.projectID, name),
		Payload: &secretmanagerpb.SecretPayload{
			Data: value,
		},
	}

	result, err := m.client.AddSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to add secret version: %w", err)
	}
	return result.Name, nil
}

func (m *SecretManager) RotateDEK(ctx context.Context, name string) (string, error) {
	kh, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	if err != nil {
		return "", fmt.Errorf("failed to create keyset handle: %w", err)
	}

	buf := new(bytes.Buffer)
	writer := keyset.NewJSONWriter(buf)

	if err := insecurecleartextkeyset.Write(kh, writer); err != nil {
		return "", fmt.Errorf("failed to write keyset: %w", err)
	}
	return m.SetSecret(ctx, name, buf.Bytes())
}
