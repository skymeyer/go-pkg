package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(t *testing.T) []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
}

func TestParseCertsPEM(t *testing.T) {
	certPEM := generateTestCert(t)

	t.Run("Valid single certificate", func(t *testing.T) {
		certs, err := ParseCertsPEM(certPEM)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("expected 1 certificate, got %d", len(certs))
		}
		if certs[0].Subject.CommonName != "test.example.com" {
			t.Errorf("expected CommonName test.example.com, got %q", certs[0].Subject.CommonName)
		}
	})

	t.Run("Valid multiple certificates", func(t *testing.T) {
		certPEM2 := generateTestCert(t)
		multiPEM := append(certPEM, certPEM2...)

		certs, err := ParseCertsPEM(multiPEM)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(certs) != 2 {
			t.Fatalf("expected 2 certificates, got %d", len(certs))
		}
	})

	t.Run("Invalid block type ignored", func(t *testing.T) {
		privateKeyBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: []byte{0x01, 0x02, 0x03},
		})

		// Append the actual cert after the private key block
		mixedPEM := append(privateKeyBlock, certPEM...)

		certs, err := ParseCertsPEM(mixedPEM)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("expected 1 certificate, got %d", len(certs))
		}
	})

	t.Run("No certificates error", func(t *testing.T) {
		privateKeyBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: []byte{0x01, 0x02, 0x03},
		})

		_, err := ParseCertsPEM(privateKeyBlock)
		if err == nil {
			t.Error("expected error for no certificates found, got nil")
		} else if err.Error() != "no certificates found" {
			t.Errorf("expected 'no certificates found' error, got %q", err.Error())
		}
	})

	t.Run("Malformed PEM block error", func(t *testing.T) {
		malformedCertPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: []byte{0x01, 0x02, 0x03}, // Invalid DER bytes
		})

		_, err := ParseCertsPEM(malformedCertPEM)
		if err == nil {
			t.Error("expected error for malformed certificate block, got nil")
		}
	})

	t.Run("Empty input error", func(t *testing.T) {
		_, err := ParseCertsPEM(nil)
		if err == nil {
			t.Error("expected error for empty input, got nil")
		}
	})
}
