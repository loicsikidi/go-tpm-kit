// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/loicsikidi/go-tpm-kit/internal/utils/testutil"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmtest"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
	"github.com/loicsikidi/go-utils/crypto/pkiutil/tinyca"
)

func TestNewKey_PersistentKey_RSA(t *testing.T) {
	tpm := tpmtest.OpenSimulator(t)

	srk, err := tpmutil.GetSRKHandle(tpm)
	if err != nil {
		t.Fatalf("GetSRKHandle failed: %v", err)
	}

	template := tpmutil.MustApplicationKeyTemplate(tpmutil.KeyConfig{
		KeyType: tpmutil.RSA2048,
	})
	keyHandle, err := tpmutil.Create(tpm, tpmutil.CreateConfig{
		ParentHandle: srk,
		InPublic:     template,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer keyHandle.Close()

	persistedHandle, err := tpmutil.Persist(tpm, tpmutil.PersistConfig{
		TransientHandle:  keyHandle,
		PersistentHandle: tpmutil.NewHandle(tpm2.TPMHandle(0x81000100)),
	})
	if err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	ca := tinyca.Must()
	cert := createCertificateWithTPMKey(t, ca, tpm, keyHandle)

	signer, err := New(Config{
		TPM:    tpm,
		Handle: persistedHandle,
		Cert:   cert,
	})
	if err != nil {
		t.Fatalf("NewKey failed: %v", err)
	}
	defer signer.Close()

	if signer.Public() == nil {
		t.Fatal("Public() returned nil")
	}
	if _, ok := signer.Public().(*rsa.PublicKey); !ok {
		t.Fatalf("Expected RSA public key, got %T", signer.Public())
	}

	testSigning(t, signer)
}

func TestNewKey_TransientKey_ECC(t *testing.T) {
	tpm := tpmtest.OpenSimulator(t)

	// Create SRK
	srk, err := tpmutil.GetSRKHandle(tpm)
	if err != nil {
		t.Fatalf("GetSRKHandle failed: %v", err)
	}

	// Create application key with result
	template := tpmutil.MustApplicationKeyTemplate(tpmutil.KeyConfig{
		KeyType: tpmutil.ECCNISTP256,
	})
	result, err := tpmutil.CreateWithResult(tpm, tpmutil.CreateConfig{
		ParentHandle: srk,
		InPublic:     template,
	})
	if err != nil {
		t.Fatalf("CreateWithResult failed: %v", err)
	}

	publicBlob := tpm2.Marshal(result.OutPublic)
	privateBlob := tpm2.Marshal(result.OutPrivate)

	// Load key to get public key
	keyHandle, err := tpmutil.Load(tpm, tpmutil.LoadConfig{
		ParentHandle: srk,
		InPrivate:    result.OutPrivate,
		InPublic:     result.OutPublic,
	})
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer keyHandle.Close()

	ca := tinyca.Must()
	cert := createCertificateWithTPMKey(t, ca, tpm, keyHandle)

	signer, err := New(Config{
		TPM: tpm,
		Key: &TransientKey{
			Parent: ParentKey{Algorithm: AlgorithmECC},
			Blob: &Blob{
				Public:  publicBlob,
				Private: privateBlob,
			},
		},
		Cert: cert,
	})
	if err != nil {
		t.Fatalf("NewKey failed: %v", err)
	}
	defer signer.Close()

	if signer.Public() == nil {
		t.Fatal("Public() returned nil")
	}
	if _, ok := signer.Public().(*ecdsa.PublicKey); !ok {
		t.Fatalf("Expected ECDSA public key, got %T", signer.Public())
	}

	testSigning(t, signer)
}

func TestNewKey_CertFromNV(t *testing.T) {
	tpm := tpmtest.OpenSimulator(t)

	srk, err := tpmutil.GetSRKHandle(tpm)
	if err != nil {
		t.Fatalf("GetSRKHandle failed: %v", err)
	}

	template := tpmutil.MustApplicationKeyTemplate(tpmutil.KeyConfig{
		KeyType: tpmutil.ECCNISTP256,
	})
	keyHandle, err := tpmutil.Create(tpm, tpmutil.CreateConfig{
		ParentHandle: srk,
		InPublic:     template,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer keyHandle.Close()

	ca := tinyca.Must()
	cert := createCertificateWithTPMKey(t, ca, tpm, keyHandle)

	nvIndex := tpm2.TPMHandle(0x01800000)
	if err := tpmutil.NVWrite(tpm, tpmutil.NVWriteConfig{
		Index: nvIndex,
		Data:  cert.Raw,
	}); err != nil {
		t.Fatalf("NVWrite failed: %v", err)
	}

	signer, err := New(Config{
		TPM:         tpm,
		Handle:      keyHandle,
		CertNVIndex: tpmutil.NewHandle(nvIndex),
	})
	if err != nil {
		t.Fatalf("NewKey failed: %v", err)
	}
	defer signer.Close()

	tlsCert := signer.Certificate()
	if tlsCert.Leaf == nil {
		t.Fatal("Certificate().Leaf is nil")
	}
	if !tlsCert.Leaf.Equal(cert) {
		t.Fatal("Certificate mismatch")
	}
	if tlsCert.PrivateKey != signer {
		t.Fatal("PrivateKey should be the signer")
	}
	if len(tlsCert.Certificate) != 1 {
		t.Fatalf("Expected 1 certificate in chain, got %d", len(tlsCert.Certificate))
	}
}

func TestSign_Concurrent(t *testing.T) {
	tpm := tpmtest.OpenSimulator(t)

	srk, err := tpmutil.GetSRKHandle(tpm)
	if err != nil {
		t.Fatalf("GetSRKHandle failed: %v", err)
	}

	template := tpmutil.MustApplicationKeyTemplate(tpmutil.KeyConfig{
		KeyType: tpmutil.ECCNISTP256,
	})
	keyHandle, err := tpmutil.Create(tpm, tpmutil.CreateConfig{
		ParentHandle: srk,
		InPublic:     template,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	defer keyHandle.Close()

	ca := tinyca.Must()
	cert := createCertificateWithTPMKey(t, ca, tpm, keyHandle)

	signer, err := New(Config{
		TPM:    tpm,
		Handle: keyHandle,
		Cert:   cert,
	})
	if err != nil {
		t.Fatalf("NewKey failed: %v", err)
	}
	defer signer.Close()

	// Run concurrent signing operations
	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := range numGoroutines {
		go func(i int) {
			defer wg.Done()
			digest := sha256.Sum256([]byte("concurrent test"))
			_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Errorf("Sign failed in goroutine %d: %v", i, err)
			}
		}(i)
	}

	wg.Wait()
}

func TestClose_Idempotent(t *testing.T) {
	tpm := tpmtest.OpenSimulator(t)

	srk, err := tpmutil.GetSRKHandle(tpm)
	if err != nil {
		t.Fatalf("GetSRKHandle failed: %v", err)
	}

	template := tpmutil.MustApplicationKeyTemplate(tpmutil.KeyConfig{
		KeyType: tpmutil.ECCNISTP256,
	})
	keyHandle, err := tpmutil.Create(tpm, tpmutil.CreateConfig{
		ParentHandle: srk,
		InPublic:     template,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	ca := tinyca.Must()
	cert := createCertificateWithTPMKey(t, ca, tpm, keyHandle)

	signer, err := New(Config{
		TPM:    tpm,
		Handle: keyHandle,
		Cert:   cert,
	})
	if err != nil {
		t.Fatalf("NewKey failed: %v", err)
	}

	// Close multiple times should not error
	if err := signer.Close(); err != nil {
		t.Fatalf("First Close failed: %v", err)
	}
	if err := signer.Close(); err != nil {
		t.Fatalf("Second Close failed: %v", err)
	}
	if err := signer.Close(); err != nil {
		t.Fatalf("Third Close failed: %v", err)
	}
}

func TestConfig_Validation(t *testing.T) {
	tpm := tpmtest.OpenSimulator(t)

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{
			name:    "nil TPM",
			cfg:     Config{},
			wantErr: "bad parameter: TPM is required",
		},
		{
			name: "both Handle and Key set",
			cfg: Config{
				TPM:    tpm,
				Handle: tpmutil.NewHandle(tpm2.TPMHandle(0x81000000)),
				Key:    &TransientKey{},
			},
			wantErr: "bad parameter: Handle and Key are mutually exclusive",
		},
		{
			name: "neither Handle nor Key set",
			cfg: Config{
				TPM: tpm,
			},
			wantErr: "bad parameter: either Handle or Key must be set",
		},
		{
			name: "both Cert and CertNVIndex set",
			cfg: Config{
				TPM:         tpm,
				Handle:      tpmutil.NewHandle(tpm2.TPMHandle(0x81000000)),
				Cert:        &x509.Certificate{},
				CertNVIndex: tpmutil.NewHandle(tpm2.TPMHandle(0x01800000)),
			},
			wantErr: "bad parameter: Cert and CertNVIndex are mutually exclusive",
		},
		{
			name: "neither Cert nor CertNVIndex set",
			cfg: Config{
				TPM:    tpm,
				Handle: tpmutil.NewHandle(tpm2.TPMHandle(0x81000000)),
			},
			wantErr: "bad parameter: either Cert or CertNVIndex must be set",
		},
		{
			name: "both Chain and CertChainNVIndexStart set",
			cfg: Config{
				TPM:                   tpm,
				Handle:                tpmutil.NewHandle(tpm2.TPMHandle(0x81000000)),
				Cert:                  &x509.Certificate{},
				Chain:                 []*x509.Certificate{},
				CertChainNVIndexStart: tpmutil.NewHandle(tpm2.TPMHandle(0x01800001)),
			},
			wantErr: "bad parameter: Chain and CertChainNVIndexStart are mutually exclusive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.CheckAndSetDefaults()
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("Expected error %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// Helper functions

func createCertificateWithTPMKey(t *testing.T, ca *tinyca.CA, tpm transport.TPM, keyHandle tpmutil.HandleCloser) *x509.Certificate {
	t.Helper()

	publicKey, err := tpmcrypto.PublicKey(keyHandle.Public())
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}

	signer := &Signer{
		tpm:       tpm,
		handle:    keyHandle,
		publicKey: publicKey,
	}

	cert, _, err := ca.Generate(tinyca.CertificateRequest{
		Subject:     pkix.Name{CommonName: "test-client"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		Signer:      signer,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("Generate certificate failed: %v", err)
	}

	return cert
}

func testSigning(t *testing.T, signer crypto.Signer) {
	t.Helper()
	testutil.TestSigning(t, signer, signer.Public())
}
