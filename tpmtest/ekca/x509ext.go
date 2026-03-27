// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ekca

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// SubjectAltName contains TPM-specific directory name attributes.
//
// TPM EK certificates use Subject Alternative Name with directory names
// containing TPM attributes (manufacturer, model, version).
//
// Source: TCG EK Credential Profile, v2.6, section 3.2.1.
type SubjectAltName struct {
	// TPMManufacturer is the TPM manufacturer identifier.
	// Format: "id:" followed by 8-character hex value (e.g., "id:414D4400" for AMD).
	TPMManufacturer string
	// TPMModel is the TPM model identifier.
	TPMModel string
	// TPMVersion is the TPM version identifier.
	// Format: "id:" followed by 8-character hex value (e.g., "id:00000001").
	TPMVersion string
}

// TPMSpecification represents the TPM specification as defined by TCG.
//
//	TPMSpecification ::= SEQUENCE {
//		family UTF8String (SIZE (1..STRMAX)),
//		level INTEGER,
//		revision INTEGER
//	}
//
// Source: TCG EK Credential Profile, v2.6, section 3.2.3.
type TPMSpecification struct {
	Family   string `asn1:"utf8"`
	Level    int
	Revision int
}

// MarshalSubjectAltName converts a [SubjectAltName] struct into a pkix.Extension.
//
// The extension uses DirectoryName (tag 4) to encode TPM attributes as a sequence
// of Relative Distinguished Names (RDNs).
//
// When critical is true, the extension is marked as critical, which is required
// when the certificate Subject field is empty (per X.509 specification).
func MarshalSubjectAltName(san *SubjectAltName, critical bool) (pkix.Extension, error) {
	if san == nil {
		return pkix.Extension{}, fmt.Errorf("SubjectAltName cannot be nil")
	}

	// Build RDN sequence with TPM attributes
	var rdns pkix.RDNSequence
	if san.TPMManufacturer != "" {
		rdns = append(rdns, []pkix.AttributeTypeAndValue{{
			Type:  OIDTPMManufacturer,
			Value: san.TPMManufacturer,
		}})
	}
	if san.TPMModel != "" {
		rdns = append(rdns, []pkix.AttributeTypeAndValue{{
			Type:  OIDTPMModel,
			Value: san.TPMModel,
		}})
	}
	if san.TPMVersion != "" {
		rdns = append(rdns, []pkix.AttributeTypeAndValue{{
			Type:  OIDTPMVersion,
			Value: san.TPMVersion,
		}})
	}

	// Marshal as DirectoryName (tag 4)
	dirNameBytes, err := asn1.MarshalWithParams(rdns, "explicit,tag:4")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal directory name: %w", err)
	}

	// Wrap in GeneralName sequence
	generalNames := []asn1.RawValue{{FullBytes: dirNameBytes}}
	val, err := asn1.Marshal(generalNames)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal general names: %w", err)
	}

	return pkix.Extension{
		Id:       OIDSubjectAltName,
		Critical: critical,
		Value:    val,
	}, nil
}

// MarshalTpmSpecification converts a [TPMSpecification] struct into a pkix.Extension
// containing the Subject Directory Attributes extension with TPM specification.
//
// The TPM specification is encoded as an attribute within the Subject Directory
// Attributes extension as defined by TCG.
func MarshalTpmSpecification(spec *TPMSpecification, critical bool) (pkix.Extension, error) {
	if spec == nil {
		return pkix.Extension{}, fmt.Errorf("TPMSpecification cannot be nil")
	}

	// Marshal TPM specification with explicit tag
	specBytes, err := asn1.MarshalWithParams(*spec, "explicit,tag:0")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal TPM specification: %w", err)
	}

	// Wrap in attribute structure
	attr := struct {
		ID   asn1.ObjectIdentifier
		Data asn1.RawValue `asn1:"set"`
	}{
		ID:   OIDTPMSpecification,
		Data: asn1.RawValue{FullBytes: specBytes},
	}

	// Marshal attribute sequence
	attrs := []any{attr}
	extBytes, err := asn1.Marshal(attrs)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("marshal attributes: %w", err)
	}

	return pkix.Extension{
		Id:       OIDSubjectDirectoryAttributes,
		Critical: critical,
		Value:    extBytes,
	}, nil
}
