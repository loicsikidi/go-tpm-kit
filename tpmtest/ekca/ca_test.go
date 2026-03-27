// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ekca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/loicsikidi/go-tpm-kit/tpmtest/ekca"
)

func TestNewCA(t *testing.T) {
	ca, err := ekca.NewCA()
	if err != nil {
		t.Fatalf("NewCA failed: %v", err)
	}

	if ca.Root == nil {
		t.Error("root certificate is nil")
	}
	if ca.RootSigner == nil {
		t.Error("root signer is nil")
	}
	if ca.Intermediate == nil {
		t.Error("intermediate certificate is nil")
	}
	if ca.IntSigner == nil {
		t.Error("intermediate signer is nil")
	}

	// Verify intermediate is signed by root
	if err := ca.Intermediate.CheckSignatureFrom(ca.Root); err != nil {
		t.Errorf("intermediate not signed by root: %v", err)
	}
}

func TestGenerateCertificate(t *testing.T) {
	ca, err := ekca.NewCA()
	if err != nil {
		t.Fatalf("NewCA failed: %v", err)
	}

	tests := []struct {
		name             string
		keyType          string // "RSA" or "ECC"
		curve            elliptic.Curve
		withTPMSpec      bool
		expectedKeyUsage x509.KeyUsage
	}{
		{
			name:             "RSA",
			keyType:          "RSA",
			withTPMSpec:      false,
			expectedKeyUsage: x509.KeyUsageKeyEncipherment,
		},
		{
			name:             "RSA_with_TPMSpec",
			keyType:          "RSA",
			withTPMSpec:      true,
			expectedKeyUsage: x509.KeyUsageKeyEncipherment,
		},
		{
			name:             "ECC",
			keyType:          "ECC",
			curve:            elliptic.P256(),
			withTPMSpec:      false,
			expectedKeyUsage: x509.KeyUsageKeyAgreement,
		},
		{
			name:             "ECC_with_TPMSpec",
			keyType:          "ECC",
			curve:            elliptic.P256(),
			withTPMSpec:      true,
			expectedKeyUsage: x509.KeyUsageKeyAgreement,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate key based on type
			var publicKey any
			switch tt.keyType {
			case "RSA":
				rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("generate RSA key: %v", err)
				}
				publicKey = &rsaKey.PublicKey
			case "ECC":
				eccKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
				if err != nil {
					t.Fatalf("generate ECC key: %v", err)
				}
				publicKey = &eccKey.PublicKey
			default:
				t.Fatalf("unknown key type: %s", tt.keyType)
			}

			// Build certificate request
			req := ekca.CertificateRequest{
				PublicKey: publicKey,
				NotAfter:  time.Now().AddDate(1, 0, 0),
				SAN: &ekca.SubjectAltName{
					TPMManufacturer: "id:53494D55",
					TPMModel:        "test-model",
					TPMVersion:      "id:00000001",
				},
			}

			if tt.withTPMSpec {
				req.TPMSpec = &ekca.TPMSpecification{
					Family:   "2.0",
					Level:    0,
					Revision: 116,
				}
			}

			// Generate certificate
			certDER, err := ca.GenerateCertificate(req)
			if err != nil {
				t.Fatalf("GenerateCertificate failed: %v", err)
			}

			// Parse and validate
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				t.Fatalf("ParseCertificate failed: %v", err)
			}

			// Verify signature
			if err := cert.CheckSignatureFrom(ca.Intermediate); err != nil {
				t.Errorf("signature verification failed: %v", err)
			}

			// Verify key usage
			if cert.KeyUsage != tt.expectedKeyUsage {
				t.Errorf("expected %v, got %v", tt.expectedKeyUsage, cert.KeyUsage)
			}

			// Verify EK certificate OID
			found := false
			for _, oid := range cert.UnknownExtKeyUsage {
				if oid.Equal(ekca.OIDEKCertificate) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("certificate missing EKCertificate OID")
			}

			// Verify IsCA is false
			if cert.IsCA {
				t.Error("certificate should not be a CA")
			}

			// Verify TPM spec extension if requested
			if tt.withTPMSpec {
				found := false
				for _, ext := range cert.Extensions {
					if ext.Id.Equal(ekca.OIDSubjectDirectoryAttributes) {
						found = true
						break
					}
				}
				if !found {
					t.Error("certificate missing TPM specification extension")
				}
			}
		})
	}
}

func TestCertificateRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     ekca.CertificateRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: ekca.CertificateRequest{
				PublicKey: &rsa.PublicKey{N: big.NewInt(1), E: 65537},
				NotAfter:  time.Now().AddDate(1, 0, 0),
				SAN: &ekca.SubjectAltName{
					TPMManufacturer: "id:53494D55",
					TPMModel:        "test-model",
					TPMVersion:      "id:00000001",
				},
			},
			wantErr: false,
		},
		{
			name: "missing public key",
			req: ekca.CertificateRequest{
				NotAfter: time.Now().AddDate(1, 0, 0),
				SAN: &ekca.SubjectAltName{
					TPMManufacturer: "id:53494D55",
					TPMModel:        "test-model",
					TPMVersion:      "id:00000001",
				},
			},
			wantErr: true,
		},
		{
			name: "missing NotAfter",
			req: ekca.CertificateRequest{
				PublicKey: &rsa.PublicKey{N: big.NewInt(1), E: 65537},
				SAN: &ekca.SubjectAltName{
					TPMManufacturer: "id:53494D55",
					TPMModel:        "test-model",
					TPMVersion:      "id:00000001",
				},
			},
			wantErr: true,
		},
		{
			name: "missing SAN",
			req: ekca.CertificateRequest{
				PublicKey: &rsa.PublicKey{N: big.NewInt(1), E: 65537},
				NotAfter:  time.Now().AddDate(1, 0, 0),
			},
			wantErr: true,
		},
		{
			name: "incomplete SAN",
			req: ekca.CertificateRequest{
				PublicKey: &rsa.PublicKey{N: big.NewInt(1), E: 65537},
				NotAfter:  time.Now().AddDate(1, 0, 0),
				SAN: &ekca.SubjectAltName{
					TPMManufacturer: "id:53494D55",
					// Missing TPMModel and TPMVersion
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.CheckAndSetDefault()
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckAndSetDefault() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
