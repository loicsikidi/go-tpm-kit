// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
)

// TestSigning verifies that a crypto.Signer correctly signs data and
// that the signature can be verified using the provided public key.
func TestSigning(t *testing.T, signer crypto.Signer, pub crypto.PublicKey) {
	t.Helper()

	data := []byte("test message")
	hash := crypto.SHA256

	// Get digest
	digest, err := tpmcrypto.GetDigest(data, hash)
	if err != nil {
		t.Fatalf("GetDigest failed: %v", err)
	}

	// Sign the digest
	sigBytes, err := signer.Sign(rand.Reader, digest, hash)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sigBytes) == 0 {
		t.Fatal("Signature is empty")
	}

	// Parse signature based on key type and verify
	var sig tpm2.TPMTSignature
	switch pub.(type) {
	case *rsa.PublicKey:
		sig = tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: sigBytes},
				},
			),
		}
	case *ecdsa.PublicKey:
		// ECDSA signatures are ASN.1 DER-encoded (R, S)
		var ecdsaSig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(sigBytes, &ecdsaSig); err != nil {
			t.Fatalf("failed to unmarshal ECDSA signature: %v", err)
		}

		sig = tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSignatureECC{
					Hash:       tpm2.TPMAlgSHA256,
					SignatureR: tpm2.TPM2BECCParameter{Buffer: ecdsaSig.R.Bytes()},
					SignatureS: tpm2.TPM2BECCParameter{Buffer: ecdsaSig.S.Bytes()},
				},
			),
		}
	default:
		t.Fatalf("unsupported key type: %T", pub)
	}

	if err := tpmcrypto.VerifySignature(pub, sig, hash, data); err != nil {
		t.Fatalf("VerifySignature failed: %v", err)
	}
}
