// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtest

import (
	"testing"
)

func TestSingletonSigners(t *testing.T) {
	// Get CA without HTTP server
	ca1, err := GetEndorsementCA()
	if err != nil {
		t.Fatalf("failed to get CA: %v", err)
	}

	// Get CA with HTTP server
	ca2, err := getEndorsementCAWithHTTPServer("http://localhost:8080")
	if err != nil {
		t.Fatalf("failed to get CA with HTTP server: %v", err)
	}

	// Verify that both CAs use the same signers
	if ca1.RootSigner != rootSigner {
		t.Error("CA1 root signer does not match singleton root signer")
	}
	if ca1.IntSigner != intermediateSigner {
		t.Error("CA1 intermediate signer does not match singleton intermediate signer")
	}

	if ca2.RootSigner != rootSigner {
		t.Error("CA2 root signer does not match singleton root signer")
	}
	if ca2.IntSigner != intermediateSigner {
		t.Error("CA2 intermediate signer does not match singleton intermediate signer")
	}

	// Verify that both CAs use the same signers between them
	if ca1.RootSigner != ca2.RootSigner {
		t.Error("CA1 and CA2 do not share the same root signer")
	}
	if ca1.IntSigner != ca2.IntSigner {
		t.Error("CA1 and CA2 do not share the same intermediate signer")
	}

	t.Log("Both CAs correctly use singleton signers")
}
