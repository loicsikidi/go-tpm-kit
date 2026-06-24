// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

// Algorithm represents the key algorithm type.
type Algorithm string

const (
	// AlgorithmECC represents Elliptic Curve Cryptography keys.
	AlgorithmECC Algorithm = "ECC"
	// AlgorithmRSA represents RSA keys.
	AlgorithmRSA Algorithm = "RSA"
)

// ParentKey specifies the parent key configuration for transient keys.
type ParentKey struct {
	// Algorithm specifies the key family (RSA or ECC).
	Algorithm Algorithm
}

// Blob contains the encrypted private and public portions of a TPM key.
type Blob struct {
	// Public is the marshaled tpm2.TPM2BPublic.
	Public []byte
	// Private is the marshaled tpm2.TPM2BPrivate.
	Private []byte
}

// CheckAndSetDefaults validates Blob fields.
func (b *Blob) CheckAndSetDefaults() error {
	if len(b.Public) == 0 {
		return errors.New("bad parameter: Public is required")
	}
	if len(b.Private) == 0 {
		return errors.New("bad parameter: Private is required")
	}
	return nil
}

// TransientKey represents a key loaded dynamically from a blob.
type TransientKey struct {
	// Parent specifies the parent key configuration.
	Parent ParentKey
	// Blob contains the key material.
	Blob *Blob
}

// CheckAndSetDefaults validates TransientKey fields.
func (e *TransientKey) CheckAndSetDefaults() error {
	if e.Blob == nil {
		return errors.New("bad parameter: Blob is required")
	}
	if err := e.Blob.CheckAndSetDefaults(); err != nil {
		return err
	}
	if e.Parent.Algorithm != AlgorithmRSA && e.Parent.Algorithm != AlgorithmECC {
		return fmt.Errorf("bad parameter: invalid Parent.Algorithm: %s (must be RSA or ECC)", e.Parent.Algorithm)
	}
	return nil
}

// Config holds configuration for creating a TPM-backed signer.
type Config struct {
	// TPM is the TPM transport connection.
	// Required.
	TPM transport.TPM

	// Key source (mutually exclusive: Handle XOR Key)
	//
	// Handle is a persistent TPM key handle.
	Handle tpmutil.Handle
	// Key is a transient key loaded from a blob.
	Key *TransientKey

	// Certificate source (mutually exclusive: Cert XOR CertNVIndex)
	//
	// Cert is the certificate (if stored externally).
	Cert *x509.Certificate
	// CertNVIndex is the NV index where the certificate is stored in the TPM.
	CertNVIndex tpmutil.Handle

	// Certificate chain source (mutually exclusive: Chain XOR CertChainNVIndexStart)
	// Optional.
	//
	// Chain is the certificate chain (if stored externally).
	Chain []*x509.Certificate
	// CertChainNVIndexStart is the starting NV index where the certificate chain
	// is stored in the TPM using multi-index storage.
	CertChainNVIndexStart tpmutil.Handle
}

// CheckAndSetDefaults validates and sets default values for Config.
func (c *Config) CheckAndSetDefaults() error {
	if c.TPM == nil {
		return errors.New("bad parameter: TPM is required")
	}

	if c.Handle != nil && c.Key != nil {
		return errors.New("bad parameter: Handle and Key are mutually exclusive")
	}
	if c.Handle == nil && c.Key == nil {
		return errors.New("bad parameter: either Handle or Key must be set")
	}

	if c.Cert != nil && c.CertNVIndex != nil {
		return errors.New("bad parameter: Cert and CertNVIndex are mutually exclusive")
	}
	if c.Cert == nil && c.CertNVIndex == nil {
		return errors.New("bad parameter: either Cert or CertNVIndex must be set")
	}

	if c.Chain != nil && c.CertChainNVIndexStart != nil {
		return errors.New("bad parameter: Chain and CertChainNVIndexStart are mutually exclusive")
	}

	if c.Key != nil {
		if err := c.Key.CheckAndSetDefaults(); err != nil {
			return err
		}
	}

	return nil
}

// Signer implements [crypto.Signer] for TPM-backed TLS keys with certificate management.
//
// Signer is thread-safe and can be used concurrently from multiple goroutines.
type Signer struct {
	mu sync.RWMutex

	tpm       transport.TPM
	handle    tpmutil.HandleCloser
	publicKey crypto.PublicKey

	cert  *x509.Certificate
	chain []*x509.Certificate
}

// New creates a TPM-backed signer from the provided configuration.
//
// The returned Signer must be closed when no longer needed to release TPM resources.
func New(cfg Config) (*Signer, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, err
	}

	k := &Signer{
		tpm: cfg.TPM,
	}

	var err error
	if cfg.Handle != nil {
		// Persistent key
		k.handle, err = tpmutil.ToHandleCloser(cfg.TPM, cfg.Handle)
		if err != nil {
			return nil, fmt.Errorf("failed to get persistent key handle: %w", err)
		}
	} else {
		// Transient key
		k.handle, err = k.loadTransientKey(cfg)
		if err != nil {
			return nil, err
		}
	}

	if !k.handle.HasPublic() {
		k.handle.Close() //nolint:errcheck
		return nil, errors.New("handle does not have public key")
	}
	k.publicKey, err = tpmcrypto.PublicKey(k.handle.Public())
	if err != nil {
		k.handle.Close() //nolint:errcheck
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	if cfg.Cert != nil {
		k.cert = cfg.Cert
	} else {
		certDER, err := tpmutil.NVRead(cfg.TPM, tpmutil.NVReadConfig{
			Index:      cfg.CertNVIndex.Handle(),
			MultiIndex: false,
		})
		if err != nil {
			k.handle.Close() //nolint:errcheck
			return nil, fmt.Errorf("failed to read certificate from NV: %w", err)
		}
		k.cert, err = x509.ParseCertificate(certDER)
		if err != nil {
			k.handle.Close()
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
	}

	// Load certificate chain (optional)
	if cfg.Chain != nil {
		k.chain = cfg.Chain
	}
	if cfg.CertChainNVIndexStart != nil {
		chainDER, err := tpmutil.NVRead(cfg.TPM, tpmutil.NVReadConfig{
			Index:      cfg.CertChainNVIndexStart.Handle(),
			MultiIndex: true,
		})
		if err != nil {
			k.handle.Close()
			return nil, fmt.Errorf("failed to read certificate chain from NV: %w", err)
		}
		k.chain, err = x509.ParseCertificates(chainDER)
		if err != nil {
			k.handle.Close()
			return nil, fmt.Errorf("failed to parse certificate chain: %w", err)
		}
	}

	return k, nil
}

// loadTransientKey loads a transient key from a TransientKey blob.
func (s *Signer) loadTransientKey(cfg Config) (tpmutil.HandleCloser, error) {
	var keyFamily tpmutil.KeyFamily
	switch cfg.Key.Parent.Algorithm {
	case AlgorithmRSA:
		keyFamily = tpmutil.RSA
	case AlgorithmECC:
		keyFamily = tpmutil.ECC
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", cfg.Key.Parent.Algorithm)
	}

	srkHandle, err := tpmutil.GetSRKHandle(cfg.TPM, tpmutil.ParentConfig{
		KeyFamily: keyFamily,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get SRK handle: %w", err)
	}

	inPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](cfg.Key.Blob.Public)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public blob: %w", err)
	}

	inPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](cfg.Key.Blob.Private)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal private blob: %w", err)
	}

	handle, err := tpmutil.Load(cfg.TPM, tpmutil.LoadConfig{
		ParentHandle: srkHandle,
		InPublic:     *inPublic,
		InPrivate:    *inPrivate,
		ParentAuth:   tpmutil.NoAuth,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load transient key: %w", err)
	}

	return handle, nil
}

// Must creates a TPM-backed signer and panics on error.
//
// This is a convenience wrapper around [New] for use in initialization
// where errors should be fatal.
func Must(cfg Config) *Signer {
	signer, err := New(cfg)
	if err != nil {
		panic(fmt.Sprintf("tpmtls.Must: %v", err))
	}
	return signer
}
