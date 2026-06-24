// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tpmtls implements [crypto.Signer] for TLS keys stored in a TPM.
//
// This package allows storing TLS private keys in a Trusted Platform Module (TPM)
// while implementing the standard Go crypto.Signer interface. This provides
// enhanced security by keeping private keys in hardware rather than in memory
// or on disk.
//
// The package supports:
//   - Persistent keys (stored in TPM)
//   - Transient keys (loaded dynamically from blobs)
//   - Certificates stored in TPM NV storage or provided externally
//   - Certificate chains for complete TLS validation
//
// All operations are thread-safe through internal mutex synchronization.
//
// # Basic Usage
//
// For a persistent key:
//
//	signer, err := tpmtls.New(tpmtls.Config{
//		TPM:    tpm,
//		Handle: persistentKeyHandle,
//		Cert:   certificate,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer signer.Close()
//
//	tlsCert := signer.Certificate()
//
// For a transient key loaded from blob:
//
//	signer, err := tpmtls.New(tpmtls.Config{
//		TPM: tpm,
//		Key: &tpmtls.TransientKey{
//			Parent: tpmtls.ParentKey{Algorithm: tpmtls.AlgorithmRSA},
//			Blob:   &tpmtls.Blob{Public: pubBlob, Private: privBlob},
//		},
//		Cert: certificate,
//	})
package tpmtls
