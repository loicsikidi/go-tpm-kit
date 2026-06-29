// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtest_test

import (
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/loicsikidi/go-tpm-kit/tpmtest"
)

func TestHTTPServer_Endpoints(t *testing.T) {
	// Create HTTP server
	server := tpmtest.NewHTTPServer()
	defer server.Close()

	// Create and initialize CA
	ca := tpmtest.GetEndorsementCA()
	if err := server.Initialize(ca); err != nil {
		t.Fatalf("failed to initialize HTTP server: %v", err)
	}

	tests := []struct {
		name        string
		path        string
		wantStatus  int
		contentType string
		validate    func(t *testing.T, body []byte)
	}{
		{
			name:        "root issuer",
			path:        "/issuer/root",
			wantStatus:  http.StatusOK,
			contentType: "application/x-x509-ca-cert",
			validate: func(t *testing.T, body []byte) {
				cert, err := x509.ParseCertificate(body)
				if err != nil {
					t.Fatalf("failed to parse root certificate: %v", err)
				}
				if !cert.IsCA {
					t.Error("root certificate is not a CA")
				}
				if cert.Subject.CommonName != "TPM Simulator Root CA" {
					t.Errorf("unexpected root CN: %s", cert.Subject.CommonName)
				}
			},
		},
		{
			name:        "intermediate issuer",
			path:        "/issuer/intermediate",
			wantStatus:  http.StatusOK,
			contentType: "application/x-x509-ca-cert",
			validate: func(t *testing.T, body []byte) {
				cert, err := x509.ParseCertificate(body)
				if err != nil {
					t.Fatalf("failed to parse intermediate certificate: %v", err)
				}
				if !cert.IsCA {
					t.Error("intermediate certificate is not a CA")
				}
				if cert.Subject.CommonName != "TPM Simulator Intermediate CA" {
					t.Errorf("unexpected intermediate CN: %s", cert.Subject.CommonName)
				}
			},
		},
		{
			name:        "root CRL",
			path:        "/crl/root",
			wantStatus:  http.StatusOK,
			contentType: "application/pkix-crl",
			validate: func(t *testing.T, body []byte) {
				crl, err := x509.ParseRevocationList(body)
				if err != nil {
					t.Fatalf("failed to parse root CRL: %v", err)
				}
				if err := crl.CheckSignatureFrom(ca.Root); err != nil {
					t.Errorf("root CRL signature verification failed: %v", err)
				}
			},
		},
		{
			name:        "intermediate CRL",
			path:        "/crl/intermediate",
			wantStatus:  http.StatusOK,
			contentType: "application/pkix-crl",
			validate: func(t *testing.T, body []byte) {
				crl, err := x509.ParseRevocationList(body)
				if err != nil {
					t.Fatalf("failed to parse intermediate CRL: %v", err)
				}
				if err := crl.CheckSignatureFrom(ca.Intermediate); err != nil {
					t.Errorf("intermediate CRL signature verification failed: %v", err)
				}
			},
		},
		{
			name:       "invalid endpoint",
			path:       "/invalid/endpoint",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "invalid CA type",
			path:       "/issuer/invalid",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := server.BaseURL() + tt.path
			resp, err := http.Get(url)
			if err != nil {
				t.Fatalf("GET %s failed: %v", url, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status code = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			if tt.contentType != "" {
				if ct := resp.Header.Get("Content-Type"); ct != tt.contentType {
					t.Errorf("content type = %s, want %s", ct, tt.contentType)
				}
			}

			if tt.validate != nil {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("failed to read response body: %v", err)
				}
				tt.validate(t, body)
			}
		})
	}
}

func TestHTTPServer_HelperMethods(t *testing.T) {
	server := tpmtest.NewHTTPServer()
	defer server.Close()

	baseURL := server.BaseURL()
	if baseURL == "" {
		t.Error("BaseURL() returned empty string")
	}

	if !strings.HasPrefix(baseURL, "http://") {
		t.Errorf("BaseURL() = %s, expected http:// prefix", baseURL)
	}

	issuerURL := server.IssuerURL(tpmtest.CATypeRoot)
	expectedIssuer := baseURL + "/issuer/root"
	if issuerURL != expectedIssuer {
		t.Errorf("IssuerURL(CATypeRoot) = %s, want %s", issuerURL, expectedIssuer)
	}

	crlURL := server.CRLURL(tpmtest.CATypeIntermediate)
	expectedCRL := baseURL + "/crl/intermediate"
	if crlURL != expectedCRL {
		t.Errorf("CRLURL(CATypeIntermediate) = %s, want %s", crlURL, expectedCRL)
	}
}

func TestHTTPServer_UninitializedServer(t *testing.T) {
	server := tpmtest.NewHTTPServer()
	defer server.Close()

	// Try to access endpoints before initialization
	resp, err := http.Get(server.IssuerURL(tpmtest.CATypeRoot))
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status code = %d, want %d (ServiceUnavailable)", resp.StatusCode, http.StatusServiceUnavailable)
	}
}

func TestHTTPServer_MethodNotAllowed(t *testing.T) {
	server := tpmtest.NewHTTPServer()
	defer server.Close()

	ca := tpmtest.GetEndorsementCA()
	if err := server.Initialize(ca); err != nil {
		t.Fatalf("failed to initialize HTTP server: %v", err)
	}

	// Try POST instead of GET
	resp, err := http.Post(server.IssuerURL(tpmtest.CATypeRoot), "text/plain", nil)
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status code = %d, want %d (MethodNotAllowed)", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}
