// Copyright (c) 2025, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil

import (
	"fmt"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/internal/utils"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
)

type KeyFamily int

const (
	// UnspecifiedKey represents an unknown or unidentified key type.
	UnspecifiedKey KeyFamily = iota
	// RSA key type
	RSA
	// ECC key type
	ECC
)

func (kt KeyFamily) String() string {
	switch kt {
	case RSA:
		return "RSA"
	case ECC:
		return "ECC"
	default:
		return fmt.Sprintf("unknown(%d)", kt)
	}
}

// AlgIDToKeyFamily converts a [tpm2.TPMAlgID] to a [KeyFamily].
//
// Returns [UnspecifiedKey] if the algorithm is not recognized or not a key type.
func AlgIDToKeyFamily(alg tpm2.TPMAlgID) KeyFamily {
	switch alg {
	case tpm2.TPMAlgRSA:
		return RSA
	case tpm2.TPMAlgECC:
		return ECC
	default:
		return UnspecifiedKey
	}
}

// PublicToKeyType converts a [tpm2.TPMTPublic] to a [KeyType].
//
// Returns an error if the key type cannot be determined or is not supported.
func PublicToKeyType(public tpm2.TPMTPublic) (KeyType, error) {
	switch public.Type {
	case tpm2.TPMAlgRSA:
		rsaDetails, err := public.Parameters.RSADetail()
		if err != nil {
			return UnspecifiedAlgo, fmt.Errorf("failed to get RSA details: %w", err)
		}
		switch rsaDetails.KeyBits {
		case 2048:
			return RSA2048, nil
		case 3072:
			return RSA3072, nil
		case 4096:
			return RSA4096, nil
		default:
			return UnspecifiedAlgo, fmt.Errorf("unsupported RSA key size: %d bits", rsaDetails.KeyBits)
		}
	case tpm2.TPMAlgECC:
		eccDetails, err := public.Parameters.ECCDetail()
		if err != nil {
			return UnspecifiedAlgo, fmt.Errorf("failed to get ECC details: %w", err)
		}
		switch eccDetails.CurveID {
		case tpm2.TPMECCNistP256:
			return ECCNISTP256, nil
		case tpm2.TPMECCNistP384:
			return ECCNISTP384, nil
		case tpm2.TPMECCNistP521:
			return ECCNISTP521, nil
		case tpm2.TPMECCSM2P256:
			return ECCSM2P256, nil
		default:
			return UnspecifiedAlgo, fmt.Errorf("unsupported ECC curve: %v", eccDetails.CurveID)
		}
	default:
		return UnspecifiedAlgo, fmt.Errorf("unsupported key algorithm: %v", public.Type)
	}
}

// MustPublicToKeyType is like [PublicToKeyType] but panics if an error occurs.
func MustPublicToKeyType(public tpm2.TPMTPublic) KeyType {
	keyType, err := PublicToKeyType(public)
	if err != nil {
		panic(err)
	}
	return keyType
}

type KeyType int

const (
	// UnspecifiedAlgo represents an unknown or unidentified key algorithm.
	UnspecifiedAlgo KeyType = iota
	// RSA2048 represents RSA algorithm with 2048-bit key size.
	RSA2048
	// RSA3072 represents RSA algorithm with 3072-bit key size.
	RSA3072
	// RSA4096 represents RSA algorithm with 4096-bit key size.
	RSA4096
	// ECCNISTP256 represents ECC algorithm with NIST P-256 curve.
	ECCNISTP256
	// ECCNISTP384 represents ECC algorithm with NIST P-384 curve.
	ECCNISTP384
	// ECCNISTP521 represents ECC algorithm with NIST P-521 curve.
	ECCNISTP521
	// ECCSM2P256 represents ECC algorithm with SM2 P-256 curve.
	ECCSM2P256
)

func (ka KeyType) String() string {
	switch ka {
	case RSA2048:
		return "RSA_2048"
	case RSA3072:
		return "RSA_3072"
	case RSA4096:
		return "RSA_4096"
	case ECCNISTP256:
		return "ECC_NIST_P256"
	case ECCNISTP384:
		return "ECC_NIST_P384"
	case ECCNISTP521:
		return "ECC_NIST_P521"
	case ECCSM2P256:
		return "ECC_SM2_P256"
	default:
		return fmt.Sprintf("unknown(%d)", ka)
	}
}

func (ka KeyType) Check() error {
	if strings.HasPrefix(ka.String(), "unknown") {
		return fmt.Errorf("unknown key type: %s", ka.String())
	}
	return nil
}

type info struct {
	family  KeyFamily
	hashAlg tpm2.TPMIAlgHash
	size    int              // specific to RSA key
	curveID tpm2.TPMECCCurve // specific to ECC key
}

var mapKtyToInfo = map[KeyType]info{
	RSA2048:     {family: RSA, hashAlg: tpm2.TPMAlgSHA256, size: 2048},
	RSA3072:     {family: RSA, hashAlg: tpm2.TPMAlgSHA384, size: 3072},
	RSA4096:     {family: RSA, hashAlg: tpm2.TPMAlgSHA512, size: 4096},
	ECCNISTP256: {family: ECC, hashAlg: tpm2.TPMAlgSHA256, curveID: tpm2.TPMECCNistP256},
	ECCNISTP384: {family: ECC, hashAlg: tpm2.TPMAlgSHA384, curveID: tpm2.TPMECCNistP384},
	ECCNISTP521: {family: ECC, hashAlg: tpm2.TPMAlgSHA512, curveID: tpm2.TPMECCNistP521},
	ECCSM2P256:  {family: ECC, hashAlg: tpm2.TPMAlgSHA256, curveID: tpm2.TPMECCSM2P256},
}

// NewApplicationKeyTemplate creates a new TPM public key template for application keys.
func NewApplicationKeyTemplate(optionalConfig ...KeyConfig) (tpm2.TPMTPublic, error) {
	cfg := utils.OptionalArg(optionalConfig)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return tpm2.TPMTPublic{}, err
	}
	return newKeyTemplate(cfg, map[KeyFamily]tpm2.TPMTPublic{RSA: rsaSigningAppKeyTemplate, ECC: eccSigningAppKeyTemplate})
}

// MustApplicationKeyTemplate is like [NewApplicationKeyTemplate] but panics if an error occurs.
func MustApplicationKeyTemplate(optionalConfig ...KeyConfig) tpm2.TPMTPublic {
	template, err := NewApplicationKeyTemplate(optionalConfig...)
	if err != nil {
		panic(err)
	}
	return template
}

// NewAKTemplate creates a new TPM public key template for Attestation Keys (AK).
//
// For RSA AKs, if no scheme is specified (TPMAlgNull), TPMAlgRSASSA is used by default
// since restricted signing keys require a specific signature scheme.
func NewAKTemplate(optionalConfig ...KeyConfig) (tpm2.TPMTPublic, error) {
	cfg := utils.OptionalArg(optionalConfig)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return tpm2.TPMTPublic{}, err
	}

	// For RSA AKs, use RSASSA scheme by default if not specified
	// Restricted signing keys (AKs) require a specific signature scheme
	// Note: The zero value of tpm2.TPMAlgID is 0, not tpm2.TPMAlgNull (0x0010)
	info := mapKtyToInfo[cfg.KeyType]
	if info.family == RSA && (cfg.Scheme == 0 || cfg.Scheme == tpm2.TPMAlgNull) {
		cfg.Scheme = tpm2.TPMAlgRSASSA
	}

	return newKeyTemplate(cfg, map[KeyFamily]tpm2.TPMTPublic{RSA: rsaAKTemplate, ECC: eccAKTemplate})
}

// MustAKTemplate is like [NewAKTemplate] but panics if an error occurs.
func MustAKTemplate(optionalConfig ...KeyConfig) tpm2.TPMTPublic {
	template, err := NewAKTemplate(optionalConfig...)
	if err != nil {
		panic(err)
	}
	return template
}

// newKeyTemplate creates a new TPM public key template based on the provided configuration and base templates.
func newKeyTemplate(cfg KeyConfig, baseTemplates map[KeyFamily]tpm2.TPMTPublic) (tpm2.TPMTPublic, error) {
	nilPublic := tpm2.TPMTPublic{}
	info := mapKtyToInfo[cfg.KeyType]
	template := baseTemplates[info.family]
	switch info.family {
	case RSA:
		template.NameAlg = info.hashAlg
		// Use the scheme from the config, defaulting to TPMAlgNull if not specified
		params, err := tpmcrypto.NewRSASigKeyParameters(info.size, cfg.Scheme)
		if err != nil {
			return nilPublic, err
		}
		template.Parameters = *params
	case ECC:
		template.NameAlg = info.hashAlg
		params, err := tpmcrypto.NewECCSigKeyParameters(info.curveID)
		if err != nil {
			return nilPublic, err
		}
		template.Parameters = *params
		unique, err := tpmcrypto.NewECCKeyUnique(info.curveID)
		if err != nil {
			return nilPublic, err
		}
		template.Unique = *unique
	}

	return template, nil
}
