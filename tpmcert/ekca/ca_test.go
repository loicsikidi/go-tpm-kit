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
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/loicsikidi/go-tpm-kit/tpmcert/ekca"
	tpmoid "github.com/loicsikidi/go-tpm-kit/tpmcert/oid"
	"github.com/loicsikidi/go-tpm-kit/tpmcert/x509ext"
)

func TestNewCA(t *testing.T) {
	ca, err := ekca.New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if ca.Root == nil {
		t.Error("root certificate is nil")
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
	ca, err := ekca.New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
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
				SAN: &x509ext.SubjectAltName{
					TPMManufacturer: "id:53494D55",
					TPMModel:        "test-model",
					TPMVersion:      "id:00000001",
				},
			}

			if tt.withTPMSpec {
				req.TPMSpec = &x509ext.TPMSpecification{
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
				if oid.Equal(tpmoid.EKCertificate) {
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
					if ext.Id.Equal(tpmoid.SubjectDirectoryAttributes) {
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

func TestNewCA_WithCustomConfig(t *testing.T) {
	customRootSubject := pkix.Name{
		Organization: []string{"Custom Test Org"},
		CommonName:   "Custom Root CA",
	}
	customIntSubject := pkix.Name{
		Organization: []string{"Custom Test Org"},
		CommonName:   "Custom Intermediate CA",
	}

	ca, err := ekca.New(ekca.CAConfig{
		Root: &ekca.CertConfig{
			Subject:  &customRootSubject,
			Validity: 2 * time.Hour,
		},
		Intermediate: &ekca.CertConfig{
			Subject:  &customIntSubject,
			Validity: 1 * time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	// Verify root subject
	if ca.Root.Subject.CommonName != "Custom Root CA" {
		t.Errorf("expected root CN 'Custom Root CA', got %q", ca.Root.Subject.CommonName)
	}

	// Verify intermediate subject
	if ca.Intermediate.Subject.CommonName != "Custom Intermediate CA" {
		t.Errorf("expected intermediate CN 'Custom Intermediate CA', got %q", ca.Intermediate.Subject.CommonName)
	}

	// Verify intermediate is signed by root
	if err := ca.Intermediate.CheckSignatureFrom(ca.Root); err != nil {
		t.Errorf("intermediate not signed by root: %v", err)
	}

	// Verify validity periods
	rootValidity := ca.Root.NotAfter.Sub(ca.Root.NotBefore)
	if rootValidity < 2*time.Hour || rootValidity > 2*time.Hour+2*time.Minute {
		t.Errorf("expected root validity ~2h, got %v", rootValidity)
	}

	intValidity := ca.Intermediate.NotAfter.Sub(ca.Intermediate.NotBefore)
	if intValidity < 1*time.Hour || intValidity > 1*time.Hour+2*time.Minute {
		t.Errorf("expected intermediate validity ~1h, got %v", intValidity)
	}
}

func TestNewCA_WithExistingIntermediateCertificate(t *testing.T) {
	// Create a reference CA to get existing certificates
	refCA, err := ekca.New()
	if err != nil {
		t.Fatalf("failed to create reference CA: %v", err)
	}

	t.Run("intermediate without root should fail", func(t *testing.T) {
		_, err := ekca.New(ekca.CAConfig{
			Intermediate: &ekca.CertConfig{
				Certificate: refCA.Intermediate,
				Signer:      refCA.IntSigner,
			},
		})
		if err == nil {
			t.Fatal("expected error when providing intermediate without root")
		}
		expectedMsg := "root certificate must be provided when intermediate certificate is provided"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("expected error to contain %q, got %q", expectedMsg, err.Error())
		}
	})

	t.Run("intermediate with root should succeed", func(t *testing.T) {
		ca, err := ekca.New(ekca.CAConfig{
			Root: &ekca.CertConfig{
				Certificate: refCA.Root,
				Signer:      refCA.IntSigner, // Using same signer for simplicity
			},
			Intermediate: &ekca.CertConfig{
				Certificate: refCA.Intermediate,
				Signer:      refCA.IntSigner,
			},
		})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}

		// Verify that provided certificates are used
		if !ca.Root.Equal(refCA.Root) {
			t.Error("expected CA to use provided root certificate")
		}
		if !ca.Intermediate.Equal(refCA.Intermediate) {
			t.Error("expected CA to use provided intermediate certificate")
		}
		if ca.IntSigner != refCA.IntSigner {
			t.Error("expected CA to use provided intermediate signer")
		}
	})

	t.Run("intermediate not signed by root should fail", func(t *testing.T) {
		// Create another CA to get an unrelated intermediate certificate
		otherCA, err := ekca.New()
		if err != nil {
			t.Fatalf("failed to create other CA: %v", err)
		}

		// Try to create a CA with mismatched certificates
		_, err = ekca.New(ekca.CAConfig{
			Root: &ekca.CertConfig{
				Certificate: refCA.Root,
				Signer:      refCA.IntSigner,
			},
			Intermediate: &ekca.CertConfig{
				Certificate: otherCA.Intermediate, // Different intermediate not signed by refCA.Root
				Signer:      otherCA.IntSigner,
			},
		})
		if err == nil {
			t.Fatal("expected error when intermediate is not signed by root")
		}
		expectedMsg := "intermediate certificate must be signed by root certificate"
		if !strings.Contains(err.Error(), expectedMsg) {
			t.Errorf("expected error to contain %q, got %q", expectedMsg, err.Error())
		}
	})

	t.Run("only custom root subject provided should succeed", func(t *testing.T) {
		customSubject := &pkix.Name{
			Organization: []string{"Custom Org"},
			CommonName:   "Custom Root CA",
		}

		ca, err := ekca.New(ekca.CAConfig{
			Root: &ekca.CertConfig{
				Subject: customSubject,
			},
		})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}

		// Root should use custom subject
		if ca.Root.Subject.CommonName != "Custom Root CA" {
			t.Errorf("expected root CN %q, got %q", "Custom Root CA", ca.Root.Subject.CommonName)
		}

		// Intermediate should be newly generated with default subject
		if ca.Intermediate.Subject.CommonName != "TPM Simulator Intermediate CA" {
			t.Errorf("expected default intermediate CN, got %q", ca.Intermediate.Subject.CommonName)
		}

		// Intermediate should be signed by our root
		if err := ca.Intermediate.CheckSignatureFrom(ca.Root); err != nil {
			t.Errorf("intermediate not signed by root: %v", err)
		}
	})
}

func TestCertConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ekca.CertConfig
		wantErr bool
	}{
		{
			name:    "empty config",
			cfg:     ekca.CertConfig{},
			wantErr: false,
		},
		{
			name: "certificate without signer",
			cfg: ekca.CertConfig{
				Certificate: &x509.Certificate{},
			},
			wantErr: true,
		},
		{
			name: "signer without certificate",
			cfg: ekca.CertConfig{
				Signer: &ecdsa.PrivateKey{},
			},
			wantErr: true,
		},
		{
			name: "valid certificate and signer",
			cfg: ekca.CertConfig{
				Certificate: &x509.Certificate{},
				Signer:      &ecdsa.PrivateKey{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.CheckAndSetDefault()
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckAndSetDefault() error = %v, wantErr %v", err, tt.wantErr)
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
				SAN: &x509ext.SubjectAltName{
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
				SAN: &x509ext.SubjectAltName{
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
				SAN: &x509ext.SubjectAltName{
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
