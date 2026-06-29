// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is a mix of a copy from
//   - https://github.com/loicsikidi/attest/blob/main/endorsement/templates.go
//   - and constants.go (i.e. tpmutil pkg)
//
// to avoid a circular dependency.
package tpmutil

import (
	"github.com/google/go-tpm/tpm2"
)

// Template is an helper struct which provides:
// - the NV index pointing to the EK certificate
// - the public area template for this EK (to recreate the EK public key if needed)
type Template struct {
	// Index is the NV index pointing to the EK certificate.
	Index tpm2.TPMHandle
	// Public is the public area template for this EK
	Public tpm2.TPMTPublic
}

// Type returns the TPM algorithm ID (ECC or RSA) associated with this template.
func (t Template) Type() tpm2.TPMAlgID {
	return t.Public.Type
}

// IsLowRange returns whether this template is for a low-range EK certificate.
func (t Template) IsLowRange() bool {
	switch t.Index {
	case RSACertIndex, ECCCertIndex:
		return true
	default:
		return false
	}
}

// Predefined EK templates.
var (
	TemplateRSA = Template{
		Index:  RSACertIndex,
		Public: RSAEKTemplate,
	}
	TemplateECC = Template{
		Index:  ECCCertIndex,
		Public: ECCEKTemplate,
	}
	TemplateRSA2048 = Template{
		Index:  RSA2048CertIndex,
		Public: RSA2048EKTemplate,
	}
	TemplateECCP256 = Template{
		Index:  ECCP256CertIndex,
		Public: ECCP256EKTemplate,
	}
	TemplateECCP384 = Template{
		Index:  ECCP384CertIndex,
		Public: ECCP384EKTemplate,
	}
	TemplateECCP521 = Template{
		Index:  ECCP521CertIndex,
		Public: ECCP521EKTemplate,
	}
)

var TemplatesByType = map[tpm2.TPMAlgID][]Template{
	tpm2.TPMAlgRSA: {
		TemplateRSA,
		TemplateRSA2048,
	},
	tpm2.TPMAlgECC: {
		TemplateECC,
		TemplateECCP256,
		TemplateECCP384,
		TemplateECCP521,
	},
}

// NV Indices for EK Certificates as per TCG EK Credential Profile v2.6
var (
	// Low-Range RSA 2048
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.4
	RSACertIndex tpm2.TPMHandle = 0x1C00002
	// Low-Range ECC NIST P256
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.4
	ECCCertIndex tpm2.TPMHandle = 0x1C0000A
	// High-Range RSA 2048
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.5
	RSA2048CertIndex tpm2.TPMHandle = 0x01C00012
	// High-Range ECC NIST P256
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.5
	ECCP256CertIndex tpm2.TPMHandle = 0x01C00014
	// ECC NIST P384
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.5
	ECCP384CertIndex tpm2.TPMHandle = 0x01C00016
	// ECC NIST P521
	// Source: TCG EK Credential Profile, v2.6, section 2.2.2.5
	ECCP521CertIndex tpm2.TPMHandle = 0x01C00018
)
