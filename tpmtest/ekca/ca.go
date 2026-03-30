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
)

var ErrEKInvalidSAN = errors.New("subject alternative name must contain TPMManufacturer, TPMModel, and TPMVersion with valid values")

// CA represents a two-level certificate authority (Root + Intermediate).
//
// The CA is used to sign EK certificates for testing purposes.
// It follows the standard CA hierarchy with a self-signed root and
// an intermediate CA signed by the root.
type CA struct {
	// Root is the self-signed root CA certificate.
	Root *x509.Certificate
	// RootSigner is the private key for the root CA.
	RootSigner crypto.Signer
	// Intermediate is the intermediate CA certificate signed by the root.
	Intermediate *x509.Certificate
	// IntSigner is the private key for the intermediate CA.
	IntSigner crypto.Signer
}

// NewCA creates a new [CA] with Root + Intermediate structure.
func NewCA() (*CA, error) {
	// Generate root key pair
	rootKey, err := generateECDSAKey()
	if err != nil {
		return nil, fmt.Errorf("generate root key: %w", err)
	}

	// Create self-signed root certificate
	rootCert, err := createRootCertificate(rootKey)
	if err != nil {
		return nil, fmt.Errorf("create root certificate: %w", err)
	}

	// Generate intermediate key pair
	intKey, err := generateECDSAKey()
	if err != nil {
		return nil, fmt.Errorf("generate intermediate key: %w", err)
	}

	// Create intermediate certificate signed by root
	intCert, err := createIntermediateCertificate(rootCert, rootKey, intKey)
	if err != nil {
		return nil, fmt.Errorf("create intermediate certificate: %w", err)
	}

	return &CA{
		Root:         rootCert,
		RootSigner:   rootKey,
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
