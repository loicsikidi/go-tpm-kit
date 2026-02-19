// Copyright (c) 2025, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmkit

import (
	"crypto"

	"github.com/google/go-tpm/tpm2"
)

const (
	// MaxBufferSize is the size of TPM2B_MAX_BUFFER.
	// This value is TPM-dependent; the value here is what all TPMs support.
	// See TPM 2.0 spec, part 2, section 10.4.8 TPM2B_MAX_BUFFER.
	MaxBufferSize = 1024
	// SRKHandle is the persistent handle for the Storage Root Key (SRK).
	// See TCG TPM v2.0 Provisioning Guidance v1.0 rev 1.0, section 7.8 "NV Memory".
	SRKHandle = tpm2.TPMHandle(0x81000001)
)

// HashInfo maps TPM hash algorithms to Go crypto.Hash types.
var HashInfo = []struct {
	Alg  tpm2.TPMAlgID
	Hash crypto.Hash
}{
	{tpm2.TPMAlgSHA1, crypto.SHA1},
	{tpm2.TPMAlgSHA256, crypto.SHA256},
	{tpm2.TPMAlgSHA384, crypto.SHA384},
	{tpm2.TPMAlgSHA512, crypto.SHA512},
	{tpm2.TPMAlgSHA3256, crypto.SHA3_256},
	{tpm2.TPMAlgSHA3384, crypto.SHA3_384},
	{tpm2.TPMAlgSHA3512, crypto.SHA3_512},
}
