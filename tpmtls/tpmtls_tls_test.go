// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtls

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmtest"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
	"github.com/loicsikidi/go-utils/crypto/pkiutil/tinyca"
)

func TestMutualTLS(t *testing.T) {
	tests := []struct {
		name      string
		keyType   tpmutil.KeyType
		keyFamily tpmutil.KeyFamily
	}{
		{
			name:      "RSA2048",
			keyType:   tpmutil.RSA2048,
			keyFamily: tpmutil.RSA,
		},
		{
			name:      "ECDSA_P256",
			keyType:   tpmutil.ECCNISTP256,
			keyFamily: tpmutil.ECC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpm := tpmtest.OpenSimulator(t)
			ca := tinyca.Must()

			srk, err := tpmutil.GetSRKHandle(tpm)
			if err != nil {
				t.Fatalf("GetSRKHandle failed: %v", err)
			}

			template := tpmutil.MustApplicationKeyTemplate(tpmutil.KeyConfig{
				KeyType: tt.keyType,
			})
			keyHandle, err := tpmutil.Create(tpm, tpmutil.CreateConfig{
				ParentHandle: srk,
				InPublic:     template,
				PersistConfig: &tpmutil.PersistConfig{
					PersistentHandle: tpmutil.NewHandle(tpm2.TPMHandle(0x81000100)),
				},
			})
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			cert := createCertificateWithTPMKey(t, ca, tpm, keyHandle)

			signer, err := New(Config{
				TPM:    tpm,
				Handle: keyHandle,
				Cert:   cert,
				Chain:  []*x509.Certificate{ca.Intermediate},
			})
			if err != nil {
				t.Fatalf("NewKey failed: %v", err)
			}
			defer signer.Close()

			clientCert := signer.Certificate()

			server := createMTLSServer(t, ca)
			defer server.Close()

			client := createTLSClient(ca, clientCert)

			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("GET request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("Expected status 200, got %d", resp.StatusCode)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("ReadAll failed: %v", err)
			}

			if string(body) != "OK" {
				t.Fatalf("Expected body 'OK', got %q", string(body))
			}
		})
	}
}

// Helper functions

func createMTLSServer(t *testing.T, ca *tinyca.CA) *httptest.Server {
	t.Helper()

	serverCert, serverKey, err := ca.Generate(tinyca.CertificateRequest{
		Subject: pkix.Name{CommonName: "test-server"},
		IPAddresses: []net.IP{
			net.IPv4(127, 0, 0, 1),
			net.IPv6loopback,
		},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("Generate server certificate failed: %v", err)
	}

	serverTLSCert := tls.Certificate{
		Certificate: [][]byte{serverCert.Raw, ca.Intermediate.Raw},
		PrivateKey:  serverKey,
		Leaf:        serverCert,
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Root)

	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
	}

	server.StartTLS()
	return server
}

func createTLSClient(ca *tinyca.CA, clientCert tls.Certificate) *http.Client {
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Root)

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      certPool,
			},
		},
	}
}
