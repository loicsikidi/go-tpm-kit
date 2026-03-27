// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtest_test

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/loicsikidi/go-tpm-kit/tpmtest"
	"github.com/loicsikidi/go-tpm-kit/tpmtest/ekca"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestOpenSimulator_Default(t *testing.T) {
	tpm := tpmtest.OpenSimulator(t)

	verifyCertInNV(t, tpm, tpmtest.RSACertIndex)
	verifyCertInNV(t, tpm, tpmtest.ECCCertIndex)
}

func TestOpenSimulator_CustomTemplates(t *testing.T) {
	tests := []struct {
		name      string
		templates []tpmtest.Template
	}{
		{"RSA only", []tpmtest.Template{tpmtest.TemplateRSA}},
		{"ECC only", []tpmtest.Template{tpmtest.TemplateECC}},
		{"RSA2048", []tpmtest.Template{tpmtest.TemplateRSA2048}},
		{"ECCP256", []tpmtest.Template{tpmtest.TemplateECCP256}},
		{"ECCP384", []tpmtest.Template{tpmtest.TemplateECCP384}},
		{"ECCP521", []tpmtest.Template{tpmtest.TemplateECCP521}},
		{"all templates", []tpmtest.Template{
			tpmtest.TemplateRSA, tpmtest.TemplateECC, tpmtest.TemplateRSA2048,
			tpmtest.TemplateECCP256, tpmtest.TemplateECCP384, tpmtest.TemplateECCP521,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := tpmtest.OpenSimulator(t, tpmtest.OpenConfig{EKCerts: tt.templates})

			for _, template := range tt.templates {
				verifyCertInNV(t, tpm, template.Index)
			}
		})
	}
}

func verifyCertInNV(t *testing.T, tpm transport.TPM, index tpm2.TPMHandle) {
	t.Helper()

	certDER, err := tpmutil.NVRead(tpm, tpmutil.NVReadConfig{Index: index})
	if err != nil {
		t.Fatalf("NVRead failed: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	ca, err := tpmtest.GetEndorsementCA()
	if err != nil {
		t.Fatalf("GetEndorsementCA failed: %v", err)
	}

	if err := ca.Verify(cert); err != nil {
		t.Errorf("certificate chain verification failed: %v", err)
	}

	// Verify subject is empty (typical for EK certificates)
	if cert.Subject.String() != "" {
		t.Logf("Note: certificate has non-empty subject: %s", cert.Subject.String())
	}

	// Verify EK certificate OID in extended key usage
	found := false
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(ekca.OIDEKCertificate) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("certificate missing EKCertificate OID in extended key usage")
	}
}
