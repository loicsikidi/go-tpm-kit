// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ekca provides EK certificate authority infrastructure for testing.
package ekca

import "encoding/asn1"

// Trusted Computing Group (2.23.133) OIDs.
var (
	// OIDTPMManufacturer is the OID for TPM manufacturer directory name attribute.
	OIDTPMManufacturer = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	// OIDTPMModel is the OID for TPM model directory name attribute.
	OIDTPMModel = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	// OIDTPMVersion is the OID for TPM version directory name attribute.
	OIDTPMVersion = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	// OIDTPMSpecification is the OID for TPM specification directory attribute.
	OIDTPMSpecification = asn1.ObjectIdentifier{2, 23, 133, 2, 16}
	// OIDEKCertificate is the OID for EK certificate extended key usage.
	OIDEKCertificate = asn1.ObjectIdentifier{2, 23, 133, 8, 1}
)

// X.509 standard OIDs (2.5.29).
var (
	// OIDSubjectDirectoryAttributes is the OID for subject directory attributes extension.
	OIDSubjectDirectoryAttributes = asn1.ObjectIdentifier{2, 5, 29, 9}
	// OIDSubjectAltName is the OID for subject alternative name extension.
	OIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)
