# tpmtls

Package tpmtls provides TPM-backed signers for mutual TLS (mTLS) authentication.

## Purpose

Enable applications to perform mTLS using TPM-protected keys without exposing private key material. This package assumes the TPM is already onboarded (certificates provisioned).

## Design Principles

- **KISS (Keep It Simple, Stupid)**: Simple API with minimal configuration
- **Easy to use**: Integrates seamlessly with standard Go TLS libraries

## Use Cases

This package supports flexible key and certificate storage configurations:

- **Key storage**: Persistent handle or transient (loaded from blob)
- **Certificate storage**: External (provided as `*x509.Certificate`) or TPM NV index
- **Certificate chain storage** (optional): External (provided as `[]*x509.Certificate`) or TPM NV multi-index

## Example

```go
package main

import (
	"crypto/tls"
	"net/http"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/loicsikidi/go-tpm-kit/tpmtls"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func main() {
	tpm, err := transport.OpenTPM()
	if err != nil {
		panic(err)
	}
	defer tpm.Close()

	// Using persistent key and NV-stored certificate
	signer, err := tpmtls.New(tpmtls.Config{
		TPM:         tpm,
		Handle:      tpmutil.Handle(0x81000001),
		CertNVIndex: tpmutil.Handle(0x1500000),
	})
	if err != nil {
		panic(err)
	}
	defer signer.Close()

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{signer.Certificate()},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Use client for mTLS requests
	_ = client
}
```

## Known Limitations

- No fine-grained authorization management for application keys (assumes no auth)
- TLS keys must be children of the Storage Root Key (SRK)

## Roadmap

- [ ] Authorization management for TLS keys
- [ ] Support for keyfile format ([go-tpm-keyfiles](https://github.com/Foxboron/go-tpm-keyfiles))
- [ ] CLI tool for certificate provisioning (key creation, CSR generation, etc.)
