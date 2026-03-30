package crypto

import (
	"context"
	"fmt"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

type KMS struct {
	resource string
	client   *kms.KeyManagementClient
}

func NewKMS(ctx context.Context, resource string) (*KMS, error) {
	k := &KMS{
		resource: resource,
	}

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create kms client: %w", err)
	}
	k.client = client

	return k, nil
}

func (k *KMS) Encrypt(ctx context.Context, plain []byte) ([]byte, string, error) {
	req := &kmspb.EncryptRequest{
		Name:      k.resource,
		Plaintext: plain,
	}
	resp, err := k.client.Encrypt(ctx, req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt: %w", err)
	}
	return resp.Ciphertext, resp.Name, nil
}

func (k *KMS) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	req := &kmspb.DecryptRequest{
		Name:       k.resource,
		Ciphertext: ciphertext,
	}
	resp, err := k.client.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}
	return resp.Plaintext, nil
}

func (k *KMS) Close() error {
	return k.client.Close()
}
