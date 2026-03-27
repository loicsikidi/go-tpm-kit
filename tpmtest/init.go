// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtest

import (
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/loicsikidi/go-tpm-kit/tpmtest/ekca"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

const (
	// defaultTPMManufacturer is the default TPM manufacturer for simulator certificates.
	defaultTPMManufacturer = "id:53494D55" // "SIMU" in hex
	// defaultTPMModel is the default TPM model for simulator certificates.
	defaultTPMModel = "tpmtest-simulator"
	// defaultTPMVersion is the default TPM version for simulator certificates.
	defaultTPMVersion = "id:00000001"
	// defaultValidityMinutes is the default certificate validity period in years.
	defaultValidityMinutes = 10
)

// initSimu provisions a TPM simulator with EK certificates.
func initSimu(t *testing.T, tpm transport.TPM, cfg OpenConfig) {
	t.Helper()

	if err := cfg.CheckAndSetDefault(); err != nil {
		t.Fatalf("invalid config: %v", err)
	}

	ca, err := GetEndorsementCA()
	if err != nil {
		t.Fatalf("failed to get CA: %v", err)
	}

	for _, template := range cfg.EKCerts {
		provisionEK(t, tpm, ca, template)
	}
}

// provisionEK creates an EK and its certificate for the given template.
func provisionEK(t *testing.T, tpm transport.TPM, ca *ekca.CA, template Template) {
	t.Helper()

	hc, err := tpmutil.CreatePrimary(tpm, tpmutil.CreatePrimaryConfig{
		InPublic:      template.Public,
		PrimaryHandle: tpm2.TPMRHEndorsement,
	})
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer func() { _ = hc.Close() }()

	publicKey, err := tpm2.Pub(*hc.Public())
	if err != nil {
		t.Fatalf("extract public key failed: %v", err)
	}

	certDER, err := ca.GenerateCertificate(ekca.CertificateRequest{
		PublicKey: publicKey,
		NotAfter:  time.Now().Add(defaultValidityMinutes * time.Minute),
		SAN: &ekca.SubjectAltName{
			TPMManufacturer: defaultTPMManufacturer,
			TPMModel:        defaultTPMModel,
			TPMVersion:      defaultTPMVersion,
		},
	})
	if err != nil {
		t.Fatalf("generate certificate failed: %v", err)
	}

	if err := tpmutil.NVWrite(tpm, tpmutil.NVWriteConfig{
		Index: template.Index,
		Data:  certDER,
	}); err != nil {
		t.Fatalf("NVWrite failed: %v", err)
	}
}
