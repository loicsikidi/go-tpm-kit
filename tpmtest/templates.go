// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmtest

import (
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

// Re-export types and variables from tpmutil for convenience.
type Template = tpmutil.Template

var (
	TemplateRSA     = tpmutil.TemplateRSA
	TemplateECC     = tpmutil.TemplateECC
	TemplateRSA2048 = tpmutil.TemplateRSA2048
	TemplateECCP256 = tpmutil.TemplateECCP256
	TemplateECCP384 = tpmutil.TemplateECCP384
	TemplateECCP521 = tpmutil.TemplateECCP521

	TemplatesByType = tpmutil.TemplatesByType

	// NV indices for EK certificates
	RSACertIndex     = tpmutil.RSACertIndex
	ECCCertIndex     = tpmutil.ECCCertIndex
	RSA2048CertIndex = tpmutil.RSA2048CertIndex
	ECCP256CertIndex = tpmutil.ECCP256CertIndex
	ECCP384CertIndex = tpmutil.ECCP384CertIndex
	ECCP521CertIndex = tpmutil.ECCP521CertIndex
)
