package ekcert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/loicsikidi/go-tpm-kit/internal/utils"
	"github.com/loicsikidi/go-tpm-kit/tpmcert/oid"
	"github.com/loicsikidi/go-tpm-kit/tpmcert/x509ext"
)

var (
	ErrExtensionNotFound               = errors.New("extension not found")
	ErrMustBeV3                        = errors.New("certificate must be version 3")
	ErrInvalidSerialNumber             = errors.New("serial number must be positive")
	ErrSanMustBeCritical               = errors.New("subject alternative name must be critical")
	ErrCertExpired                     = errors.New("certificate has expired")
	ErrCertNotYetValid                 = errors.New("certificate is not yet valid")
	ErrCertificateRevoked              = errors.New("certificate is revoked")
	ErrEKCannotBeCA                    = errors.New("EK certificate cannot be a CA certificate")
	ErrEKKeyUsageMustBeKeyEncipherment = errors.New("certificate must have KeyEncipherment key usage for RSA public keys")
	ErrEKKeyUsageMustBeKeyAgreement    = errors.New("certificate must have KeyAgreement key usage for ECDSA public keys")
	ErrEKInvalidSAN                    = errors.New("subject alternative name must contain TPMManufacturer, TPMModel, and TPMVersion with valid values")
)

const (
	tpmDeviceAttrPrefix = "id:"
)

// EKCertRequester provides an interface for exporting relevant fields
// to produce a Local EK (LEK) certificate derived from an existing
// EK certificate (signed by a OEM's Certificate Authority).
type EKCertRequester interface {
	GetPublicKey() crypto.PublicKey
	Subject() pkix.Name
	SAN() *x509ext.SubjectAltName
	TPMSpec() *x509ext.TPMSpecification
}

// EKCertificate represents an Endorsement Key (EK) certificate as specified
// in TCG EK Credential Profile for TPM Family 2.0 v2.6
//
// Source: https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf
//
// Notes:
//   - this resource is intented to be used ONLY by the Trust Service (i.e. backend).
//   - the struct is able to validate the EK certificate based on the spec
//   - the struct exposes nicely parsed EK certificate extensions (e.g. SAN, TPM Specification)
type EKCertificate struct {
	EKCertRequester
	cert             *x509.Certificate
	SubjectAltName   *x509ext.SubjectAltName
	TPMSpecification *x509ext.TPMSpecification
	strictMode       bool
	downloader       *downloader
	maxDownloads     int
}

type Config struct {
	// StrictModeEnabled determines whether strict mode checks are enabled.
	//
	// When enabled, additional checks such as revocation checks are performed.
	// We could add more strict checks in the future if needed.
	StrictModeEnabled bool
	// MaxDownloads specifies the maximum number of concurrent downloads allowed.
	//
	// This limit helps prevent excessive resource usage and potential denial-of-service attacks.
	MaxDownloads int
	// DownloaderHttpClient specifies the HTTP client used by the downloader.
	//
	// This component retrieves necessary data from external sources:
	//   - Certificate Revocation Lists (CRLs)
	//   - Issuer Certificates
	//   - External Endorsement Key Certificates
	//
	// If not provided, [http.DefaultClient] will be used.
	DownloaderHttpClient httpClient
	// DownloaderTimeout specifies the request timeout for the downloader.
	//
	// If not provided, a default downloader with [DefaultDownloadTimeout] will be used.
	DownloaderTimeout time.Duration
}

func (cfg *Config) CheckAndSetDefault() error {
	if cfg.MaxDownloads <= 0 {
		cfg.MaxDownloads = DefaultMaxDownloads
	}
	if cfg.DownloaderHttpClient == nil {
		cfg.DownloaderHttpClient = http.DefaultClient
	}
	if cfg.DownloaderTimeout <= 0 {
		cfg.DownloaderTimeout = DefaultDownloadTimeout
	}
	return nil
}

func NewEKCertificate(cert *x509.Certificate, optionalCfg ...Config) (*EKCertificate, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}

	if cert == nil {
		return nil, errors.New("certificate cannot be nil")
	}
	san, err := x509ext.GetSubjectAltNameFromCertificate(cert)
	if err != nil {
		return nil, err
	}
	spec, err := x509ext.GetTpmSpecficationFromCertificate(cert)
	if err != nil {
		return nil, err
	}
	return &EKCertificate{
		cert:             cert,
		SubjectAltName:   san,
		TPMSpecification: spec,
		downloader: &downloader{
			client:  cfg.DownloaderHttpClient,
			timeout: cfg.DownloaderTimeout,
		},
		maxDownloads: cfg.MaxDownloads,
		strictMode:   cfg.StrictModeEnabled,
	}, nil
}

// Perform checks according to requirements described in TCG EK Credential Profile v2.4 rev3 section 3.2
//
// / NOTE: only MUST checks are implemented.
//
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf#page=26
func (ek *EKCertificate) Check() error {
	if err := checkVersion(ek); err != nil {
		return err
	}
	if err := checkSerialNumber(ek); err != nil {
		return err
	}
	if err := checkSAN(ek); err != nil {
		return err
	}
	if err := checkKeyUsage(ek); err != nil {
		return err
	}
	if err := checkValidity(ek); err != nil {
		return err
	}
	if err := checkBasicConstraints(ek); err != nil {
		return err
	}
	if ek.strictMode {
		if err := checkRevocation(ek); err != nil {
			return err
		}
	}
	return nil
}

func (ek *EKCertificate) GetCertificate() *x509.Certificate {
	return ek.cert
}

func (ek *EKCertificate) GetPublicKey() crypto.PublicKey {
	return ek.cert.PublicKey
}

func (ek *EKCertificate) Subject() pkix.Name {
	return ek.cert.Subject
}

func (ek *EKCertificate) SAN() *x509ext.SubjectAltName {
	return ek.SubjectAltName
}

func (ek *EKCertificate) TPMSpec() *x509ext.TPMSpecification {
	return ek.TPMSpecification
}

func checkVersion(ek *EKCertificate) error {
	if ek.cert.Version != 3 {
		return ErrMustBeV3
	}
	return nil
}

func checkSerialNumber(ek *EKCertificate) error {
	if ek.cert.SerialNumber.Sign() <= 0 {
		return ErrInvalidSerialNumber
	}
	return nil
}

func checkSAN(ek *EKCertificate) error {
	if ek.cert.Subject.String() == "" {
		ext, err := getCertificateExtension(ek.cert, oid.SubjectAltName)
		if err != nil {
			return err
		}
		if !ext.Critical {
			return ErrSanMustBeCritical
		}
	}
	if ek.SubjectAltName.TPMManufacturer == "" ||
		ek.SubjectAltName.TPMModel == "" ||
		ek.SubjectAltName.TPMVersion == "" {
		return ErrEKInvalidSAN
	}
	if err := checkSANTPMAttrs(ek.SubjectAltName); err != nil {
		return err
	}
	return nil
}

func checkSANTPMAttrs(san *x509ext.SubjectAltName) error {
	manufacturer := san.TPMManufacturer.Raw()
	if !strings.HasPrefix(manufacturer, tpmDeviceAttrPrefix) ||
		!strings.HasPrefix(san.TPMVersion, tpmDeviceAttrPrefix) {
		return ErrEKInvalidSAN
	}

	// According to the spec, these fields must be exactly 11 characters long
	// Details:
	// - "id:" prefix is 3 characters long
	// - <value> is represented with 4-byte represented as 2 digit (4x2=8)
	// so total length is 3+8=11 characters
	if len(manufacturer) != 11 || len(san.TPMVersion) != 11 {
		return ErrEKInvalidSAN
	}

	return nil
}

func checkKeyUsage(ek *EKCertificate) error {
	switch ek.cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if ek.cert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
			return ErrEKKeyUsageMustBeKeyEncipherment
		}
	case *ecdsa.PublicKey:
		if ek.cert.KeyUsage&x509.KeyUsageKeyAgreement == 0 {
			return ErrEKKeyUsageMustBeKeyAgreement
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", ek.cert.PublicKey)
	}
	return nil
}

func checkValidity(ek *EKCertificate) error {
	now := time.Now()

	if now.Before(ek.cert.NotBefore) {
		return ErrCertNotYetValid
	}
	if now.After(ek.cert.NotAfter) {
		return ErrCertExpired

	}
	return nil
}

func checkBasicConstraints(ek *EKCertificate) error {
	if ek.cert.IsCA {
		return ErrEKCannotBeCA
	}
	return nil
}

// TODO(lsi):
//   - support reccursive search for the full chain
//   - support a list of static issuers (if some content is not easily retrievable)
func checkRevocation(ek *EKCertificate) error {
	// if the downloader is not enabled, we don't check for revocation
	if ek.downloader != nil {
		if len(ek.cert.CRLDistributionPoints) > 0 {
			// an arbitrary limit, so that we don't start making a large number of HTTP requests (if needed)
			if len(ek.cert.CRLDistributionPoints) > ek.maxDownloads {
				return fmt.Errorf("number of CRLs (%d) bigger than the maximum allowed number (%d) of downloads", len(ek.cert.CRLDistributionPoints), ek.maxDownloads)
			}

			issuers, err := getIssuerCertificates(ek)
			if err != nil {
				return err
			}

			crlUrls, err := prepareCRLUrls(ek.cert.CRLDistributionPoints)
			if err != nil {
				return err
			}

			for _, url := range crlUrls {
				crl, err := ek.downloader.DownloadCRL(context.Background(), url)
				if err != nil {
					return fmt.Errorf("failed to download CRL from %q: %w", url, err)
				}

				if err := crl.Verify(issuers...); err != nil {
					return err
				}

				if crl.IsRevoked(ek.cert) {
					return fmt.Errorf("certificate revoked: %w", ErrCertificateRevoked)
				}
			}
		}
	}
	return nil
}

func prepareCRLUrls(urls []string) ([]*url.URL, error) {
	var crlURLs []*url.URL
	for _, u := range urls {
		parsedURL, err := url.Parse(u)
		if err != nil {
			return nil, fmt.Errorf("failed to parse CRL URL %q: %w", u, err)
		}

		// we only support HTTP URLs for CRLs (at least for now)
		if parsedURL.Scheme != "http" {
			continue
		}
		crlURLs = append(crlURLs, parsedURL)
	}
	return crlURLs, nil
}

// getIssuerCertificates retrieves the issuer certificates for the EK certificates.
// it's a strict function that expects to get all the issuer certificates
func getIssuerCertificates(ek *EKCertificate) ([]*x509.Certificate, error) {
	issuerUrls, err := prepareCRLUrls(ek.cert.IssuingCertificateURL)
	if err != nil {
		return nil, err
	}

	issuers := make([]*x509.Certificate, len(issuerUrls))
	for idx, url := range issuerUrls {
		cert, err := ek.downloader.DownloadCRLSigner(context.Background(), url)
		if err != nil {
			return nil, err
		}
		issuers[idx] = cert
	}
	return issuers, nil
}

func getCertificateExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, error) {
	if cert != nil {
		for _, ext := range cert.Extensions {
			if ext.Id.Equal(oid) {
				return ext, nil
			}
		}
	}
	return pkix.Extension{}, ErrExtensionNotFound
}
