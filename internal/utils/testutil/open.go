// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package testutil

import (
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// OpenSimulator opens a connection to the TPM simulator for testing.
//
// The simulator connection is automatically cleaned up when the test completes.
func OpenSimulator(t *testing.T) transport.TPM {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	t.Cleanup(func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("could not close TPM simulator: %v", err)
		}
	})
	return tpm
}
