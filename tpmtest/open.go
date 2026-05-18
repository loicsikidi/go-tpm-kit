// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"sync"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"github.com/loicsikidi/go-tpm-kit/tpmcert/ekca"
	goutils "github.com/loicsikidi/go-utils"
)

var (
	caOnce     sync.Once
	caInstance *ekca.CA
	caErr      error

	httpServerMu    sync.Mutex
	httpServerCache = make(map[string]*HTTPServer)

	rootSigner         crypto.Signer
	intermediateSigner crypto.Signer
)

func init() {
	var err error
	rootSigner, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("failed to generate root signer: " + err.Error())
	}

	intermediateSigner, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("failed to generate intermediate signer: " + err.Error())
	}
}

const (
	// defaultRootValidity is the default validity period for root certificates.
	defaultRootValidity = 1 * time.Hour
	// defaultIntermediateValidity is the default validity period for intermediate certificates.
	defaultIntermediateValidity = 30 * time.Minute
)

// GetEndorsementCA returns the singleton [ekca.CA] instance.
//
// This ensures all EK certificates are signed by the same CA across all tests.
func GetEndorsementCA() (*ekca.CA, error) {
	caOnce.Do(func() {
		cfg := ekca.CAConfig{
			Root: &ekca.CertConfig{
				Subject: &pkix.Name{
					Organization: []string{"go-tpm-kit"},
					CommonName:   "TPM Simulator Root CA",
				},
				Validity: defaultRootValidity,
				Signer:   rootSigner,
			},
			Intermediate: &ekca.CertConfig{
				Subject: &pkix.Name{
					Organization: []string{"go-tpm-kit"},
					CommonName:   "TPM Simulator Intermediate CA",
				},
				Validity: defaultIntermediateValidity,
				Signer:   intermediateSigner,
			},
		}
		caInstance, caErr = ekca.New(cfg)
	})
	return caInstance, caErr
}

// MustGetEndorsementCA returns the singleton [ekca.CA] instance.
//
// This function panics if the CA cannot be created.
func MustGetEndorsementCA() *ekca.CA {
	ca, err := GetEndorsementCA()
	if err != nil {
		panic(err)
	}
	return ca
}

// GetHTTPServer returns the HTTP server associated with the given test.
func GetHTTPServer(t *testing.T) *HTTPServer {
	httpServerMu.Lock()
	defer httpServerMu.Unlock()
	return httpServerCache[t.Name()]
}

// getEndorsementCAWithHTTPServer creates a new CA instance with HTTP server URLs.
func getEndorsementCAWithHTTPServer(baseURL string) (*ekca.CA, error) {
	cfg := ekca.CAConfig{
		Root: &ekca.CertConfig{
			Subject: &pkix.Name{
				Organization: []string{"go-tpm-kit"},
				CommonName:   "TPM Simulator Root CA",
			},
			Validity:              defaultRootValidity,
			Signer:                rootSigner,
			CRLDistributionPoints: []string{baseURL + "/crl/root"},
		},
		Intermediate: &ekca.CertConfig{
			Subject: &pkix.Name{
				Organization: []string{"go-tpm-kit"},
				CommonName:   "TPM Simulator Intermediate CA",
			},
			Validity:              defaultIntermediateValidity,
			Signer:                intermediateSigner,
			IssuingCertificateURL: []string{baseURL + "/issuer/root"},
			CRLDistributionPoints: []string{baseURL + "/crl/root"},
		},
	}
	return ekca.New(cfg)
}

// storeHTTPServer stores the HTTP server in the cache for the given test.
func storeHTTPServer(t *testing.T, server *HTTPServer) {
	httpServerMu.Lock()
	defer httpServerMu.Unlock()
	httpServerCache[t.Name()] = server
}

// removeHTTPServer removes the HTTP server from the cache for the given test.
func removeHTTPServer(t *testing.T) {
	httpServerMu.Lock()
	defer httpServerMu.Unlock()
	delete(httpServerCache, t.Name())
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
	// SkipCleanup disables cleaning up the simulator on test completion.
	// When true, the simulator is not closed automatically.
	//
	// Default: false.
	SkipCleanup bool
	// EnableHTTPServer enables the HTTP server for serving CA certificates and CRLs.
	// When enabled, AIA (Authority Information Access) and CRL Distribution Points
	// extensions are added to all certificates (Root, Intermediate, and EK).
	//
	// The HTTP server can be accessed via [GetHTTPServer] for testing purposes.
	//
	// Default: false.
	EnableHTTPServer bool
}

// CheckAndSetDefault checks and sets default values for the open configuration.
func (c *OpenConfig) CheckAndSetDefaults() error {
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
// Note: the connection is automatically closed when the test completes
// unless [OpenConfig.SkipCleanup] is set to true.
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
func OpenSimulator(t *testing.T, optionalCfg ...OpenConfig) transport.TPMCloser {
	t.Helper()

	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	cfg := goutils.OptionalArg(optionalCfg)
	if !cfg.SkipProvisioning {
		var httpServer *HTTPServer
		var ca *ekca.CA

		if cfg.EnableHTTPServer {
			httpServer = NewHTTPServer()

			ca, err = getEndorsementCAWithHTTPServer(httpServer.BaseURL())
			if err != nil {
				httpServer.Close()
				t.Fatalf("failed to create CA with HTTP server: %v", err)
			}

			if err := httpServer.Initialize(ca); err != nil {
				httpServer.Close()
				t.Fatalf("failed to initialize HTTP server: %v", err)
			}

			// Store HTTP server in cache for later access
			storeHTTPServer(t, httpServer)

			t.Cleanup(func() {
				httpServer.Close()
				removeHTTPServer(t)
			})
		} else {
			ca, err = GetEndorsementCA()
			if err != nil {
				t.Fatalf("failed to get CA: %v", err)
			}
		}

		initSimu(t, tpm, cfg, ca, httpServer)
	}
	if !cfg.SkipCleanup {
		t.Cleanup(func() {
			if err := tpm.Close(); err != nil {
				t.Errorf("could not close TPM simulator: %v", err)
			}
		})
	}
	return tpm
}
