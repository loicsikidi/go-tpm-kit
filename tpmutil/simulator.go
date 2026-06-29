// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil

import (
	"crypto"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/loicsikidi/go-tpm-kit/tpmcert/ekca"
	"github.com/loicsikidi/go-tpm-kit/tpmcert/x509ext"
)

const (
	// defaultTPMManufacturer is the default TPM manufacturer for simulator certificates.
	defaultTPMManufacturer = "SIM0"
	// defaultTPMModel is the default TPM model for simulator certificates.
	defaultTPMModel = "simulator"
	// defaultTPMVersion is the default TPM version for simulator certificates.
	defaultTPMVersion = "id:00000001"
	// defaultValidityMinutes is the default certificate validity period in minutes.
	defaultValidityMinutes = 10
)

const (
	// DefaultRootValidity is the default validity period for root certificates.
	DefaultRootValidity = 1 * time.Hour
	// DefaultIntermediateValidity is the default validity period for intermediate certificates.
	DefaultIntermediateValidity = 30 * time.Minute
)

// EKCertOptions configures EK certificate generation.
type EKCertOptions struct {
	// IssuingCertificateURL is an optional list of URLs for the AIA extension.
	// These URLs point to the issuing CA certificate.
	IssuingCertificateURL []string
	// CRLDistributionPoints is an optional list of URLs for CRL distribution points.
	CRLDistributionPoints []string
	// SAN is the Subject Alternative Name to use for the EK certificates.
	// If nil, a default SAN will be created.
	SAN *x509ext.SubjectAltName
	// ValidityMinutes overrides the default certificate validity period.
	ValidityMinutes int
}

// SimulatorConfig configures the simulator initialization.
type SimulatorConfig struct {
	// EKCerts is the list of EK templates to provision with certificates.
	//
	// Default: [TemplateRSA], [TemplateECC] (low-range RSA 2048 and ECC P256).
	EKCerts []Template
	// SkipProvisioning disables EK certificate provisioning.
	// When true, the simulator is opened without any EK certificates.
	//
	// Default: false.
	SkipProvisioning bool
	// CA is the Certificate Authority used to sign EK certificates.
	// Required with Skip
	CA *ekca.CA
	// CertOptions configures EK certificate generation.
	// If nil, default options will be used.
	CertOptions *EKCertOptions
}

// CheckAndSetDefaults checks and sets default values for the simulator configuration.
func (c *SimulatorConfig) CheckAndSetDefaults() error {
	if !c.SkipProvisioning {
		if c.CA == nil {
			ca, err := createDefaultCA()
			if err != nil {
				return fmt.Errorf("failed to create CA: %w", err)
			}
			c.CA = ca
		}
		if len(c.EKCerts) == 0 {
			c.EKCerts = []Template{TemplateRSA, TemplateECC}
		}
		if c.CertOptions == nil {
			c.CertOptions = &EKCertOptions{}
		}
		if c.CertOptions.SAN == nil {
			c.CertOptions.SAN = &x509ext.SubjectAltName{
				TPMManufacturer: defaultTPMManufacturer,
				TPMModel:        defaultTPMModel,
				TPMVersion:      defaultTPMVersion,
			}
		}
		if c.CertOptions.ValidityMinutes <= 0 {
			c.CertOptions.ValidityMinutes = defaultValidityMinutes
		}
	}
	return nil
}

// Simulator represents a TPM simulator instance with provisioned EK certificates.
type Simulator struct {
	tpm transport.TPMCloser
}

// TPM returns the underlying TPM transport.
func (s *Simulator) TPM() transport.TPM {
	return s.tpm
}

// Close closes the simulator and releases resources.
func (s *Simulator) Close() error {
	return s.tpm.Close()
}

// OpenSimulator opens a TPM simulator and optionally provisions it with EK certificates.
//
// The simulator is automatically provisioned with EK certificates signed by the provided CA
// unless [SimulatorConfig.SkipProvisioning] is set to true.
//
// The caller is responsible for closing the simulator by calling [Simulator.Close].
//
// Example:
//
//	sim, err := tpmutil.OpenSimulator(tpmutil.SimulatorConfig{
//	    CA: ca,
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer sim.Close()
//
//	// Use sim.TPM() to interact with the simulator
func OpenSimulator(cfg SimulatorConfig) (*Simulator, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		return nil, fmt.Errorf("open simulator: %w", err)
	}

	sim := &Simulator{tpm: tpm}

	if !cfg.SkipProvisioning {
		for _, template := range cfg.EKCerts {
			if err := provisionEK(tpm, cfg, template); err != nil {
				sim.Close() //nolint:errcheck
				return nil, fmt.Errorf("provision EK: %w", err)
			}
		}
	}

	return sim, nil
}

// provisionEK creates an EK and its certificate for the given template.
func provisionEK(tpm transport.TPM, cfg SimulatorConfig, template Template) error {
	hc, err := CreatePrimary(tpm, CreatePrimaryConfig{
		InPublic:      template.Public,
		PrimaryHandle: tpm2.TPMRHEndorsement,
	})
	if err != nil {
		return fmt.Errorf("create primary: %w", err)
	}
	defer func() { _ = hc.Close() }()

	publicKey, err := tpm2.Pub(*hc.Public())
	if err != nil {
		return fmt.Errorf("extract public key: %w", err)
	}

	req := ekca.CertificateRequest{
		PublicKey:             publicKey,
		NotAfter:              time.Now().Add(time.Duration(cfg.CertOptions.ValidityMinutes) * time.Minute),
		IssuingCertificateURL: cfg.CertOptions.IssuingCertificateURL,
		CRLDistributionPoints: cfg.CertOptions.CRLDistributionPoints,
		SAN:                   cfg.CertOptions.SAN,
	}

	certDER, err := cfg.CA.GenerateCertificate(req)
	if err != nil {
		return fmt.Errorf("generate certificate: %w", err)
	}

	if err := NVWrite(tpm, NVWriteConfig{
		Index: template.Index,
		Data:  certDER,
	}); err != nil {
		return fmt.Errorf("write certificate to NV: %w", err)
	}

	return nil
}

func GetDefaultCAConfig(rootSigner, intermediateSigner crypto.Signer) ekca.CAConfig {
	return ekca.CAConfig{
		Root: &ekca.CertConfig{
			Subject: &pkix.Name{
				Organization: []string{"go-tpm-kit"},
				CommonName:   "TPM Simulator Root CA",
			},
			Validity: DefaultRootValidity,
			Signer:   rootSigner,
		},
		Intermediate: &ekca.CertConfig{
			Subject: &pkix.Name{
				Organization: []string{"go-tpm-kit"},
				CommonName:   "TPM Simulator Intermediate CA",
			},
			Validity: DefaultIntermediateValidity,
			Signer:   intermediateSigner,
		},
	}
}

// createDefaultCA creates a simple CA with default settings
func createDefaultCA() (*ekca.CA, error) {
	// we delegate key generation to the ekca
	cfg := GetDefaultCAConfig(
		/* rootSigner = */ nil,
		/* intermediateSigner = */ nil,
	)
	return ekca.New(cfg)
}
