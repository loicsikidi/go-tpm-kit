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

	"github.com/loicsikidi/go-tpm-kit/internal/utils"
	"github.com/loicsikidi/go-tpm-kit/tpmcert/oid"
	"github.com/loicsikidi/go-tpm-kit/tpmcert/x509ext"
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
	// Signer is the private key for an existing certificate.
	//
	// Optional. When provided, Certificate must also be provided.
	Signer crypto.Signer
}

// CheckAndSetDefault validates the configuration.
func (c *CertConfig) CheckAndSetDefault() error {
	if (c.Certificate != nil && c.Signer == nil) || (c.Certificate == nil && c.Signer != nil) {
		return errors.New("invalid input: Certificate and Signer must both be provided or both be nil")
	}
	return nil
}

// hasExistingCert returns true if an existing certificate and signer are provided.
func (c *CertConfig) hasExistingCert() bool {
	return c != nil && c.Certificate != nil
}

// hasCustomConfig returns true if custom configuration (subject or validity) is provided.
func (c *CertConfig) hasCustomConfig() bool {
	return c != nil && (c.Subject != nil || c.Validity > 0)
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
func (c *CAConfig) CheckAndSetDefault() error {
	if c.Root != nil {
		if err := c.Root.CheckAndSetDefault(); err != nil {
			return fmt.Errorf("root config: %w", err)
		}
	}
	if c.Intermediate != nil {
		if err := c.Intermediate.CheckAndSetDefault(); err != nil {
			return fmt.Errorf("intermediate config: %w", err)
		}
	}

	// If an existing intermediate certificate is provided, root must also be provided
	if c.Intermediate.hasExistingCert() && !c.Root.hasExistingCert() {
		return errors.New("root certificate must be provided when intermediate certificate is provided")
	}

	// If both certificates are provided, verify that intermediate is signed by root
	if c.Root.hasExistingCert() && c.Intermediate.hasExistingCert() {
		if err := c.Intermediate.Certificate.CheckSignatureFrom(c.Root.Certificate); err != nil {
			return fmt.Errorf("intermediate certificate must be signed by root certificate: %w", err)
		}
	}

	return nil
}

// New creates a new [CA] with Root + Intermediate structure.
//
// The optionalCfg parameter can be used to customize the CA certificates.
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
func New(optionalCfg ...CAConfig) (*CA, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	var rootCert *x509.Certificate
	var rootKey crypto.Signer
	var err error

	// Use existing root certificate or create a new one
	if cfg.Root.hasExistingCert() {
		rootCert = cfg.Root.Certificate
		rootKey = cfg.Root.Signer
	} else {
		rootKey, err = generateECDSAKey()
		if err != nil {
			return nil, fmt.Errorf("generate root key: %w", err)
		}

		// Set default subject if not provided
		rootSubject := &pkix.Name{
			Organization: []string{"go-tpm-kit"},
			CommonName:   "TPM Simulator Root CA",
		}
		var rootValidity time.Duration
		if cfg.Root.hasCustomConfig() {
			if cfg.Root.Subject != nil {
				rootSubject = cfg.Root.Subject
			}
			rootValidity = cfg.Root.Validity
		}

		rootCert, err = createRootCertificate(rootKey, rootSubject, rootValidity)
		if err != nil {
			return nil, fmt.Errorf("create root certificate: %w", err)
		}
	}

	var intCert *x509.Certificate
	var intKey crypto.Signer

	// Use existing intermediate certificate or create a new one
	if cfg.Intermediate.hasExistingCert() {
		intCert = cfg.Intermediate.Certificate
		intKey = cfg.Intermediate.Signer
	} else {
		intKey, err = generateECDSAKey()
		if err != nil {
			return nil, fmt.Errorf("generate intermediate key: %w", err)
		}

		// Set default subject if not provided
		intSubject := &pkix.Name{
			Organization: []string{"go-tpm-kit"},
			CommonName:   "TPM Simulator Intermediate CA",
		}
		var intValidity time.Duration
		if cfg.Intermediate.hasCustomConfig() {
			if cfg.Intermediate.Subject != nil {
				intSubject = cfg.Intermediate.Subject
			}
			intValidity = cfg.Intermediate.Validity
		}

		intCert, err = createIntermediateCertificate(rootCert, rootKey, intKey, intSubject, intValidity)
		if err != nil {
			return nil, fmt.Errorf("create intermediate certificate: %w", err)
		}
	}

	return &CA{
		Root:         rootCert,
		Intermediate: intCert,
		IntSigner:    intKey,
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
}

// CheckAndSetDefault checks and sets default values for the certificate request.
func (c *CertificateRequest) CheckAndSetDefault() error {
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
	if err := req.CheckAndSetDefault(); err != nil {
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
		NotBefore:          time.Now().UTC().Add(-1 * time.Minute),
		NotAfter:           req.NotAfter,
		KeyUsage:           keyUsage,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oid.EKCertificate},
		ExtraExtensions:    extensions,
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
