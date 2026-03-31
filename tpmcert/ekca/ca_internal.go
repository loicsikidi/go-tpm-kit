// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ekca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

const (
	// DefaultRootValidity is the default validity period for root certificates.
	DefaultRootValidity = 30 * 365 * 24 * time.Hour
	// DefaultIntermediateValidity is the default validity period for intermediate certificates.
	DefaultIntermediateValidity = 25 * 365 * 24 * time.Hour
	// DefaultLeafValidity is the default validity period for leaf certificates.
	DefaultLeafValidity = 20 * 365 * 24 * time.Hour
)

// generateECDSAKey generates a new ECDSA private key using P-256 curve.
func generateECDSAKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ECDSA key: %w", err)
	}
	return key, nil
}

// createRootCertificate creates a self-signed root CA certificate.
//
// The subject and validity parameters are optional. If subject is nil, default values are used.
// If validity is zero, [DefaultRootValidity] is used.
func createRootCertificate(signer crypto.Signer, subject *pkix.Name, validity time.Duration) (*x509.Certificate, error) {
	if subject == nil {
		return nil, fmt.Errorf("subject is required for root certificate")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()

	// Set default validity if not provided
	certValidity := DefaultRootValidity
	if validity > 0 {
		certValidity = validity
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               *subject,
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("create root certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse root certificate: %w", err)
	}

	return cert, nil
}

// createIntermediateCertificate creates an intermediate CA certificate signed by the root CA.
//
// The subject and validity parameters are optional. If subject is nil, default values are used.
// If validity is zero, [DefaultIntermediateValidity] is used.
func createIntermediateCertificate(rootCert *x509.Certificate, rootSigner crypto.Signer, intSigner crypto.Signer, subject *pkix.Name, validity time.Duration) (*x509.Certificate, error) {
	if subject == nil {
		return nil, fmt.Errorf("subject is required for intermediate certificate")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()

	// Set default validity if not provided
	certValidity := DefaultIntermediateValidity
	if validity > 0 {
		certValidity = validity
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               *subject,
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(certValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, intSigner.Public(), rootSigner)
	if err != nil {
		return nil, fmt.Errorf("create intermediate certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse intermediate certificate: %w", err)
	}

	return cert, nil
}
