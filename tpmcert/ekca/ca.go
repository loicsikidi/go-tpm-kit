// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ekca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/loicsikidi/go-tpm-kit/tpmcert/oid"
	"github.com/loicsikidi/go-tpm-kit/tpmcert/x509ext"
	goutils "github.com/loicsikidi/go-utils"
)

var ErrEKInvalidSAN = errors.New("subject alternative name must contain TPMManufacturer, TPMModel, and TPMVersion with valid values")

// CA represents a two-level certificate authority (Root + Intermediate).
//
// The CA is used to sign EK certificates (essentially for testing or ready-to-use scenarios [eg. memory-based PKI]).
// It follows the standard CA hierarchy with a self-signed root and
// an intermediate CA signed by the root.
type CA struct {
	// Root is the self-signed root CA certificate.
	Root *x509.Certificate
	// Intermediate is the intermediate CA certificate signed by the root.
	Intermediate *x509.Certificate
	// RootSigner is the private key for the root CA.
	RootSigner crypto.Signer
	// IntSigner is the private key for the intermediate CA.
	IntSigner crypto.Signer
}

// CertConfig defines configuration options for generating a CA certificate.
type CertConfig struct {
	// Subject for the certificate.
	//
	// Optional. If not provided, defaults will be used based on certificate type.
	Subject *pkix.Name
	// Validity is the duration for which the certificate is valid.
	//
	// Optional. If not provided, defaults will be used:
	//   - Root: [DefaultRootValidity]
	//   - Intermediate: [DefaultIntermediateValidity]
	Validity time.Duration
	// Certificate is an existing certificate to use instead of generating a new one.
	//
	// Optional. When provided, Signer must also be provided.
	Certificate *x509.Certificate
	// Signer is the private key for the certificate.
	//
	// Optional.
	Signer crypto.Signer
	// IssuingCertificateURL contains URLs to issuer certificates (AIA extension).
	//
	// Optional.
	IssuingCertificateURL []string
	// CRLDistributionPoints contains URLs to Certificate Revocation Lists.
	//
	// Optional.
	CRLDistributionPoints []string
}

// CheckAndSetDefault validates the configuration.
func (c *CertConfig) CheckAndSetDefaults() error {
	if c.Certificate != nil && c.Signer == nil {
		return errors.New("invalid input: Certificate requires Signer to be provided")
	}
	return nil
}

// hasExistingCert returns true if an existing certificate and signer are provided.
func (c *CertConfig) hasExistingCert() bool {
	return c != nil && c.Certificate != nil
}

// CAConfig defines configuration options for creating a [CA].
type CAConfig struct {
	// Root configuration for the root CA certificate.
	//
	// Optional.
	Root *CertConfig
	// Intermediate configuration for the intermediate CA certificate.
	//
	// Optional.
	Intermediate *CertConfig
}

// CheckAndSetDefault validates and sets default values for the CA configuration.
func (c *CAConfig) CheckAndSetDefaults() error {
	if c.Root != nil {
		if err := c.Root.CheckAndSetDefaults(); err != nil {
			return fmt.Errorf("root config: %w", err)
		}
	}
	if c.Intermediate != nil {
		if err := c.Intermediate.CheckAndSetDefaults(); err != nil {
			return fmt.Errorf("intermediate config: %w", err)
		}
	}

	if c.Intermediate.hasExistingCert() && !c.Root.hasExistingCert() {
		return errors.New("root certificate must be provided when intermediate certificate is provided")
	}

	if c.Root.hasExistingCert() && c.Intermediate.hasExistingCert() {
		if err := c.Intermediate.Certificate.CheckSignatureFrom(c.Root.Certificate); err != nil {
			return fmt.Errorf("intermediate certificate must be signed by root certificate: %w", err)
		}
	}

	return nil
}

// New creates a new [CA] with Root + Intermediate structure.
//
// If not provided, default values are used for both root and intermediate certificates.
//
// Example:
//
//	// Default CA
//	ca, err := ekca.New()
//
//	// Custom subject and validity
//	ca, err := ekca.New(ekca.CAConfig{
//	    Root: &ekca.CertConfig{
//	        Subject: &pkix.Name{
//	            Organization: []string{"My Org"},
//	            CommonName:   "My Root CA",
//	        },
//	        Validity: 24 * time.Hour,
//	    },
//	})
//
//	// With existing signers (certificates will be generated)
//	ca, err := ekca.New(ekca.CAConfig{
//	    Root: &ekca.CertConfig{
//	        Signer: existingRootKey,
//	    },
//	    Intermediate: &ekca.CertConfig{
//	        Signer: existingIntKey,
//	    },
//	})
func New(optionalCfg ...CAConfig) (*CA, error) {
	cfg := goutils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	rootCert, rootSigner, err := initRootCA(cfg.Root)
	if err != nil {
		return nil, fmt.Errorf("init root CA: %w", err)
	}

	intCert, intSigner, err := initIntermediateCA(cfg.Intermediate, rootCert, rootSigner)
	if err != nil {
		return nil, fmt.Errorf("init intermediate CA: %w", err)
	}

	return &CA{
		Root:         rootCert,
		Intermediate: intCert,
		RootSigner:   rootSigner,
		IntSigner:    intSigner,
	}, nil
}

// Verify checks that cert was issued by this CA.
//
// It clears [x509.Certificate.UnhandledCriticalExtensions] before verification
// because TPM-specific OIDs (e.g. SAN with TPM attributes) are not recognized
// by the standard library.
func (ca *CA) Verify(cert *x509.Certificate) error {
	pool, poolInt := x509.NewCertPool(), x509.NewCertPool()
	pool.AddCert(ca.Root)
	poolInt.AddCert(ca.Intermediate)

	certCopy := *cert
	certCopy.UnhandledCriticalExtensions = nil

	_, err := certCopy.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: poolInt,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

type certRequester interface {
	GetPublicKey() crypto.PublicKey
	Subject() pkix.Name
	SAN() *x509ext.SubjectAltName
	TPMSpec() *x509ext.TPMSpecification
}

// CertificateRequest is a request to generate an EK certificate.
type CertificateRequest struct {
	// PublicKey is the public key to sign.
	//
	// Required (unless provided via CertRequest).
	PublicKey crypto.PublicKey
	// NotAfter is the time after which the issued certificate will be no longer valid.
	//
	// Required.
	NotAfter time.Time
	// Subject is the subject to include in the certificate.
	//
	// Optional. EK certificates typically have an empty subject, with TPM
	// attributes encoded in the Subject Alternative Name extension instead.
	Subject pkix.Name
	// SAN is the Subject Alternative Name to include in the certificate.
	//
	// Required for EK certificates (unless provided via CertRequest). Must contain TPMManufacturer, TPMModel,
	// and TPMVersion.
	SAN *x509ext.SubjectAltName
	// TPMSpec is the TPM specification to include in the certificate.
	//
	// Optional.
	TPMSpec *x509ext.TPMSpecification

	// CertRequester is an optional interface that can be used to
	// populate the certificate request fields.
	//
	// When provided, this interface overrides PublicKey, Subject, SAN, and TPMSpec fields
	// during [CertificateRequest.CheckAndSetDefault].
	//
	// Optional.
	CertRequester certRequester

	// IssuingCertificateURL contains URLs to issuer certificates (AIA extension).
	//
	// Optional.
	IssuingCertificateURL []string

	// CRLDistributionPoints contains URLs to Certificate Revocation Lists.
	//
	// Optional.
	CRLDistributionPoints []string
}

// CheckAndSetDefault checks and sets default values for the certificate request.
func (c *CertificateRequest) CheckAndSetDefaults() error {
	if c.CertRequester != nil {
		c.PublicKey = c.CertRequester.GetPublicKey()
		c.Subject = c.CertRequester.Subject()
		c.SAN = c.CertRequester.SAN()
		c.TPMSpec = c.CertRequester.TPMSpec()
	}

	if c.PublicKey == nil {
		return fmt.Errorf("missing parameter PublicKey")
	}
	if c.NotAfter.IsZero() {
		c.NotAfter = time.Now().Add(DefaultLeafValidity)
	}
	if c.SAN == nil || c.SAN.TPMManufacturer == "" || c.SAN.TPMModel == "" || c.SAN.TPMVersion == "" {
		return ErrEKInvalidSAN
	}
	return nil
}

// GenerateCertificate generates an X.509 certificate based on the provided request.
//
// The certificate is signed by the intermediate CA and returned as DER-encoded bytes.
//
// The certificate includes:
//   - Serial number: 128-bit random number
//   - Subject: From request (typically empty for EK certificates)
//   - NotBefore: Current time minus 1 minute (to prevent clock skew issues)
//   - NotAfter: From request
//   - KeyUsage: KeyEncipherment (RSA) or KeyAgreement (ECDSA)
//   - ExtKeyUsage: EKCertificate OID (2.23.133.8.1)
//   - Extensions: Subject Alternative Name (with TPM attributes)
//   - Extensions: TPM Specification (if provided)
//
// The Subject Alternative Name extension is marked as critical when the Subject
// field is empty, as required by the X.509 specification.
func (ca *CA) GenerateCertificate(req CertificateRequest) ([]byte, error) {
	if err := req.CheckAndSetDefaults(); err != nil {
		return nil, fmt.Errorf("validate request: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	keyUsage, err := getKeyUsage(req.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("get key usage: %w", err)
	}

	extensions, err := getExtensions(req)
	if err != nil {
		return nil, fmt.Errorf("get extensions: %w", err)
	}

	template := &x509.Certificate{
		Version:      3,
		SerialNumber: serialNumber,
		Subject:      req.Subject,
		// NotBefore is one minute in the past to prevent "Not yet valid" errors on
		// time skewed systems.
		NotBefore:             time.Now().UTC().Add(-1 * time.Minute),
		NotAfter:              req.NotAfter,
		KeyUsage:              keyUsage,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oid.EKCertificate},
		ExtraExtensions:       extensions,
		IssuingCertificateURL: req.IssuingCertificateURL,
		CRLDistributionPoints: req.CRLDistributionPoints,
		// BasicConstraintsValid is true to not allow any intermediate certs.
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, ca.Intermediate, req.PublicKey, ca.IntSigner)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return certBytes, nil
}

// getKeyUsage returns the appropriate key usage for the public key type.
func getKeyUsage(pub crypto.PublicKey) (x509.KeyUsage, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return x509.KeyUsageKeyEncipherment, nil
	case *ecdsa.PublicKey:
		return x509.KeyUsageKeyAgreement, nil
	default:
		return 0, fmt.Errorf("unsupported public key type %T", pub)
	}
}

// getExtensions builds the X.509 extensions for the certificate.
func getExtensions(req CertificateRequest) ([]pkix.Extension, error) {
	var extensions []pkix.Extension
	critical := (req.Subject.String() == "")

	if req.SAN != nil {
		san, err := x509ext.MarshalSubjectAltName(req.SAN, critical)
		if err != nil {
			return nil, fmt.Errorf("marshal subject alt name: %w", err)
		}
		extensions = append(extensions, san)
	}

	if req.TPMSpec != nil {
		spec, err := x509ext.MarshalTpmSpecification(req.TPMSpec, critical)
		if err != nil {
			return nil, fmt.Errorf("marshal tpm specification: %w", err)
		}
		extensions = append(extensions, spec)
	}
	return extensions, nil
}
