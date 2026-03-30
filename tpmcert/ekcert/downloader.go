// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ekcert

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/loicsikidi/go-tpm-kit/internal/utils"
	crlutil "github.com/loicsikidi/go-tpm-kit/internal/utils/crl"
	httputil "github.com/loicsikidi/go-tpm-kit/internal/utils/http"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
)

const (
	DefaultDownloadTimeout = 2 * time.Second
	DefaultMaxDownloads    = 10
)

// httpClient interface is used essentially to mock [http.Client] in tests
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// CRL interface is duplicate here to avoid a reference to an internal package (i.e. crlutil)
type CRL crlutil.CRL

type downloader struct {
	client  httpClient
	timeout time.Duration
}

type intelEKCertResponse struct {
	Pubhash     string `json:"pubhash"`
	Certificate string `json:"certificate"`
}

// DownloadCRL downloads a Certificate Revocation List (CRL) from the specified URL.
func (d *downloader) DownloadCRL(ctx context.Context, url *url.URL) (CRL, error) {
	ctx, cancel := utils.WithTimeout(ctx, d.timeout)
	defer cancel()

	crlBytes, err := httputil.HttpGET(ctx, d.client, url.String())
	if err != nil {
		return nil, fmt.Errorf("failed retrieving CRL from %q: %w", url, err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing CRL from %q: %w", url, err)
	}

	return crlutil.NewCRL(crl)
}

// DownloadCRLSigner downloads the signer certificate for a CRL from the specified URL.
func (d *downloader) DownloadCRLSigner(ctx context.Context, url *url.URL) (*x509.Certificate, error) {
	ctx, cancel := utils.WithTimeout(ctx, d.timeout)
	defer cancel()

	certBytes, err := httputil.HttpGET(ctx, d.client, url.String())
	if err != nil {
		return nil, fmt.Errorf("failed retrieving certificate from %q: %w", url, err)
	}

	// RFC 5280 section 4.2.2.1 states that the certificate
	// is expected to be in DER format in HTTP/FTP.
	crl, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed parsing certificate from %q: %w", url, err)
	}

	return crl, nil
}

// DownloadEKCertificate attempts to download the EK certificate from ekURL.
func (d *downloader) DownloadEKCertificate(ctx context.Context, ekURL *url.URL) (*x509.Certificate, error) {
	ctx, cancel := utils.WithTimeout(ctx, d.timeout)
	defer cancel()

	body, err := httputil.HttpGET(ctx, d.client, ekURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed retrieving EK certificate from %q: %w", ekURL, err)
	}

	var ekCert *x509.Certificate
	switch {
	case strings.Contains(ekURL.String(), tpmcrypto.IntelEKCertServiceURL):
		var c intelEKCertResponse
		if err := json.Unmarshal(body, &c); err != nil {
			return nil, fmt.Errorf("failed decoding EK certificate response: %w", err)
		}
		cb, err := base64.RawURLEncoding.DecodeString(strings.ReplaceAll(c.Certificate, "%3D", "")) // strip padding; decode raw
		if err != nil {
			return nil, fmt.Errorf("failed decoding EK certificate: %w", err)
		}
		ekCert, err = tpmcrypto.ParseEKCertificate(cb)
		if err != nil {
			return nil, fmt.Errorf("failed parsing EK certificate: %w", err)
		}
	case strings.Contains(ekURL.String(), tpmcrypto.AmdEKCertServiceURL):
		ekCert, err = tpmcrypto.ParseEKCertificate(body)
		if err != nil {
			return nil, err
		}
	// Also see https://learn.microsoft.com/en-us/mem/autopilot/networking-requirements#tpm
	default:
		ekCert, err = tpmcrypto.ParseEKCertificate(body)
		if err != nil {
			return nil, err
		}
	}
	return ekCert, nil
}

func (d *downloader) SetTimeout(timeout time.Duration) {
	d.timeout = timeout
}
