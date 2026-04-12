// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtest

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	crlutil "github.com/loicsikidi/go-tpm-kit/internal/utils/crl"
	"github.com/loicsikidi/go-tpm-kit/tpmcert/ekca"
)

// CAType represents the type of Certificate Authority (Root or Intermediate).
type CAType string

const (
	// CATypeRoot represents a Root Certificate Authority.
	CATypeRoot CAType = "root"
	// CATypeIntermediate represents an Intermediate Certificate Authority.
	CATypeIntermediate CAType = "intermediate"
)

// String returns the string representation of CAType.
func (c CAType) String() string {
	return string(c)
}

// IsValid returns true if the CAType is valid.
func (c CAType) IsValid() bool {
	return c == CATypeRoot || c == CATypeIntermediate
}

// HTTPServer provides HTTP endpoints for serving CA certificates and CRLs.
//
// The server uses a 2-phase initialization:
//  1. NewHTTPServer() creates and starts the server (empty)
//  2. Initialize() populates the server with CA certificates and CRLs
type HTTPServer struct {
	server  *httptest.Server
	handler *httpHandler
}

// httpHandler is the internal HTTP handler with thread-safe mutable state.
type httpHandler struct {
	mu       sync.RWMutex
	rootCert []byte
	intCert  []byte
	rootCRL  []byte
	intCRL   []byte
}

// NewHTTPServer creates and starts a new HTTP server.
//
// The server is created empty and must be initialized with [HTTPServer.Initialize]
// before it can serve certificates and CRLs.
//
// The server should be closed when no longer needed using [HTTPServer.Close].
func NewHTTPServer() *HTTPServer {
	h := &httpHandler{}
	s := httptest.NewServer(h)
	return &HTTPServer{
		server:  s,
		handler: h,
	}
}

// Initialize populates the HTTP server with CA certificates and CRLs.
func (s *HTTPServer) Initialize(ca *ekca.CA) error {
	// TODO: make CRL's validity configurable?
	rootValidity := ca.Root.NotAfter.Sub(ca.Root.NotBefore)
	rootCRL, err := generateEmptyCRL(ca.Root, ca.RootSigner, rootValidity)
	if err != nil {
		return fmt.Errorf("generate root CRL: %w", err)
	}

	intValidity := ca.Intermediate.NotAfter.Sub(ca.Intermediate.NotBefore)
	intCRL, err := generateEmptyCRL(ca.Intermediate, ca.IntSigner, intValidity)
	if err != nil {
		return fmt.Errorf("generate intermediate CRL: %w", err)
	}

	// Store certificates and CRLs
	s.handler.mu.Lock()
	defer s.handler.mu.Unlock()

	s.handler.rootCert = ca.Root.Raw
	s.handler.intCert = ca.Intermediate.Raw
	s.handler.rootCRL = rootCRL
	s.handler.intCRL = intCRL

	return nil
}

// ServeHTTP handles HTTP requests for CA certificates and CRLs.
//
// Supported endpoints:
//   - GET /issuer/root - Returns Root CA certificate (DER format)
//   - GET /issuer/intermediate - Returns Intermediate CA certificate (DER format)
//   - GET /crl/root - Returns Root CA CRL
//   - GET /crl/intermediate - Returns Intermediate CA CRL
func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.Split(path, "/")

	if len(parts) != 2 {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	resourceType := parts[0]
	caType := CAType(parts[1])

	// Validate CAType
	if !caType.IsValid() {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	switch resourceType {
	case "issuer":
		h.serveIssuer(w, caType)
	case "crl":
		h.serveCRL(w, caType)
	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

func (h *httpHandler) serveIssuer(w http.ResponseWriter, caType CAType) {
	var cert []byte
	switch caType {
	case CATypeRoot:
		cert = h.rootCert
	case CATypeIntermediate:
		cert = h.intCert
	default:
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if cert == nil {
		http.Error(w, "Server not initialized", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.WriteHeader(http.StatusOK)
	w.Write(cert) //nolint:errcheck
}

func (h *httpHandler) serveCRL(w http.ResponseWriter, caType CAType) {
	var crl []byte
	switch caType {
	case CATypeRoot:
		crl = h.rootCRL
	case CATypeIntermediate:
		crl = h.intCRL
	default:
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if crl == nil {
		http.Error(w, "Server not initialized", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/pkix-crl")
	w.WriteHeader(http.StatusOK)
	w.Write(crl) //nolint:errcheck
}

// BaseURL returns the base URL of the HTTP server.
func (s *HTTPServer) BaseURL() string {
	return s.server.URL
}

// IssuerURL returns the full URL for the issuer certificate endpoint.
//
// Example: IssuerURL(CATypeRoot) returns "http://127.0.0.1:12345/issuer/root"
func (s *HTTPServer) IssuerURL(caType CAType) string {
	return fmt.Sprintf("%s/issuer/%s", s.server.URL, caType)
}

// CRLURL returns the full URL for the CRL endpoint.
//
// Example: CRLURL(CATypeIntermediate) returns "http://127.0.0.1:12345/crl/intermediate"
func (s *HTTPServer) CRLURL(caType CAType) string {
	return fmt.Sprintf("%s/crl/%s", s.server.URL, caType)
}

// Close stops the HTTP server and releases resources.
func (s *HTTPServer) Close() {
	s.server.Close()
}

// generateEmptyCRL generates an empty Certificate Revocation List (CRL).
//
// The CRL is signed by the specified issuer and is valid for the given duration.
func generateEmptyCRL(issuer *x509.Certificate, signer crypto.Signer, validity time.Duration) ([]byte, error) {
	now := time.Now()
	template := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: now,
		NextUpdate: now.Add(validity),
	}
	return crlutil.MarshalCRL(template, issuer, signer)
}
