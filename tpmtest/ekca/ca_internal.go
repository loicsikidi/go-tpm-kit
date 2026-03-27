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
	// defaultRootValidity is the default validity period for root certificates.
	defaultRootValidity = 1 * time.Hour
	// defaultIntermediateValidity is the default validity period for intermediate certificates.
	defaultIntermediateValidity = 10 * time.Minute
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
func createRootCertificate(signer crypto.Signer) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"TPM Simulator Test CA"},
			CommonName:   "TPM Simulator Root CA",
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(defaultRootValidity),
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
func createIntermediateCertificate(rootCert *x509.Certificate, rootSigner crypto.Signer, intSigner crypto.Signer) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"TPM Simulator Test CA"},
			CommonName:   "TPM Simulator Intermediate CA",
		},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(defaultIntermediateValidity),
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
