// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls

import (
	"crypto"
	"crypto/tls"
	"io"

	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

// Public returns the public key associated with this signer.
//
// This method implements [crypto.Signer].
func (s *Signer) Public() crypto.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.publicKey
}

// Sign signs the given digest using the TPM key.
//
// This method implements [crypto.Signer].
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return tpmutil.Sign(s.tpm, tpmutil.SignConfig{
		KeyHandle:  s.handle,
		Digest:     digest,
		SignerOpts: opts,
		Validation: tpmutil.NullTicket,
	})
}

// Certificate returns a [tls.Certificate] ready for use in TLS configurations.
// The certificate chain includes the leaf certificate and any intermediate certificates
// if they were provided during key creation.
func (s *Signer) Certificate() tls.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()

	certChain := [][]byte{s.cert.Raw}
	for _, cert := range s.chain {
		certChain = append(certChain, cert.Raw)
	}

	return tls.Certificate{
		Certificate: certChain,
		PrivateKey:  s,
		Leaf:        s.cert,
	}
}

// Close releases resources associated with this key.
//
// This method is idempotent and can be called multiple times safely.
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.handle != nil {
		err := s.handle.Close()
		s.handle = nil // Prevent double-close
		return err
	}
	return nil
}
