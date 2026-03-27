// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtest

import (
	"sync"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/loicsikidi/go-tpm-kit/internal/utils"
	"github.com/loicsikidi/go-tpm-kit/tpmtest/ekca"
)

var (
	caOnce     sync.Once
	caInstance *ekca.CA
	caErr      error
)

// GetEndorsementCA returns the singleton [ekca.CA] instance.
//
// The CA is created once on the first call using [sync.Once] and reused
// for subsequent calls. This ensures all EK certificates are signed by
// the same CA across all tests.
func GetEndorsementCA() (*ekca.CA, error) {
	caOnce.Do(func() {
		caInstance, caErr = ekca.NewCA()
	})
	return caInstance, caErr
}

// OpenConfig configures the simulator initialization with EK certificates.
type OpenConfig struct {
	// EKCerts is the list of EK templates to provision with certificates.
	//
	// Default: [TemplateRSA], [TemplateECC] (low-range RSA 2048 and ECC P256).
	EKCerts []Template
	// SkipProvisioning disables EK certificate provisioning.
	// When true, the simulator is opened without any EK certificates.
	//
	// Default: false.
	SkipProvisioning bool
}

// CheckAndSetDefault checks and sets default values for the open configuration.
func (c *OpenConfig) CheckAndSetDefault() error {
	if len(c.EKCerts) == 0 {
		// Default: low-range RSA and ECC
		c.EKCerts = []Template{TemplateRSA, TemplateECC}
	}
	return nil
}

// OpenSimulator opens a TPM simulator and provisions it with EK certificates.
//
// The certificates are signed by a test CA accessible via [GetEndorsementCA].
//
// Note: the connection is automatically closed when the test completes.
//
// Example:
//
//	tpm := tpmtest.OpenSimulator(t) // Default: RSA + ECC
//
//	// Or with custom templates:
//	tpm := tpmtest.OpenSimulator(t, tpmtest.OpenConfig{
//	    EKCerts: []tpmtest.Template{
//	        tpmtest.TemplateRSA2048,
//	        tpmtest.TemplateECCP384,
//	    },
//	})
//
//	// Or without provisioning:
//	tpm := tpmtest.OpenSimulator(t, tpmtest.OpenConfig{
//	    SkipProvisioning: true,
//	})
func OpenSimulator(t *testing.T, optionalCfg ...OpenConfig) transport.TPM {
	t.Helper()

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	t.Cleanup(func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("could not close TPM simulator: %v", err)
		}
	})

	cfg := utils.OptionalArg(optionalCfg)
	if !cfg.SkipProvisioning {
		initSimu(t, tpm, cfg)
	}

	return tpm
}
