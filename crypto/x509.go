package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func ParseCertsPEM(pemCerts []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(pemCerts) > 0 {
		block, rest := pem.Decode(pemCerts)
		if block == nil {
			break
		}
		pemCerts = rest
		// Ensure it's a certificate block
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates found")
	}
	return certs, nil
}
