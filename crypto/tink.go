package crypto

import (
	"bytes"
	"fmt"

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

func KeyHandleToJSON(kh *keyset.Handle) ([]byte, error) {
	buf := new(bytes.Buffer)
	writer := keyset.NewJSONWriter(buf)
	if err := insecurecleartextkeyset.Write(kh, writer); err != nil {
		return nil, fmt.Errorf("failed to write keyset: %w", err)
	}
	return buf.Bytes(), nil
}

func JSONToKeyHandle(b []byte) (*keyset.Handle, error) {
	reader := keyset.NewJSONReader(bytes.NewReader(b))
	kh, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyset: %w", err)
	}
	return kh, nil
}

func KeyHandleToBytes(kh *keyset.Handle) ([]byte, error) {
	buf := new(bytes.Buffer)
	writer := keyset.NewBinaryWriter(buf)
	if err := insecurecleartextkeyset.Write(kh, writer); err != nil {
		return nil, fmt.Errorf("failed to write keyset: %w", err)
	}
	return buf.Bytes(), nil
}

func BytesToKeyHandle(b []byte) (*keyset.Handle, error) {
	reader := keyset.NewBinaryReader(bytes.NewReader(b))
	kh, err := insecurecleartextkeyset.Read(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read keyset: %w", err)
	}
	return kh, nil
}
