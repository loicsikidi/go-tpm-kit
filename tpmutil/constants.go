// Copyright (c) 2025, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil

import "github.com/google/go-tpm/tpm2"

// Policy buffers from TCG EK Credential Profile.
//
// These are used as AuthPolicy values in various EK templates.
var (
	// PolicyA SHA256 digest
	// Source: TCG EK Credential Profile, v2.6
	policyASHA256 = []byte{
		0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
		0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
		0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
		0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
		0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
		0x69, 0xAA,
	}
	// PolicyA SHA384 digest
	// Source: TCG EK Credential Profile, v2.6
	policyASHA384 = []byte{
		0x8B, 0xBF, 0x22, 0x66, 0x53, 0x7C,
		0x17, 0x1C, 0xB5, 0x6E, 0x40, 0x3C,
		0x4D, 0xC1, 0xD4, 0xB6, 0x4F, 0x43,
		0x26, 0x11, 0xDC, 0x38, 0x6E, 0x6F,
		0x53, 0x20, 0x50, 0xC3, 0x27, 0x8C,
		0x93, 0x0E, 0x14, 0x3E, 0x8B, 0xB1,
		0x13, 0x38, 0x24, 0xCC, 0xB4, 0x31,
		0x05, 0x38, 0x71, 0xC6, 0xDB, 0x53,
	}
	// PolicyA SHA512 digest
	// Source: TCG EK Credential Profile, v2.6
	policyASHA512 = []byte{
		0x1E, 0x3B, 0x76, 0x50, 0x2C, 0x8A,
		0x14, 0x25, 0xAA, 0x0B, 0x7B, 0x3F,
		0xC6, 0x46, 0xA1, 0xB0, 0xFA, 0xE0,
		0x63, 0xB0, 0x3B, 0x53, 0x68, 0xF9,
		0xC4, 0xCD, 0xDE, 0xCA, 0xFF, 0x08,
		0x91, 0xDD, 0x68, 0x2B, 0xAC, 0x1A,
		0x85, 0xD4, 0xD8, 0x32, 0xB7, 0x81,
		0xEA, 0x45, 0x19, 0x15, 0xDE, 0x5F,
		0xC5, 0xBF, 0x0D, 0xC4, 0xA1, 0x91,
		0x7C, 0xD4, 0x2F, 0xA0, 0x41, 0xE3,
		0xF9, 0x98, 0xE0, 0xEE,
	}
	// PolicyA SM3-256 digest
	// Source: TCG EK Credential Profile, v2.6
	policyASM3256 = []byte{
		0xC6, 0x7F, 0x7D, 0x35, 0xF6, 0x6F,
		0x3B, 0xEC, 0x13, 0xC8, 0x9F, 0xE8,
		0x98, 0x92, 0x1C, 0x65, 0x1B, 0x0C,
		0xB5, 0xA3, 0x8A, 0x92, 0x69, 0x0A,
		0x62, 0xA4, 0x3C, 0x00, 0x12, 0xE4,
		0xFB, 0x8B,
	}

	// PolicyB SHA256 digest
	// Source: TCG EK Credential Profile, v2.6
	policyBSHA256 = []byte{
		0xCA, 0x3D, 0x0A, 0x99, 0xA2, 0xB9,
		0x39, 0x06, 0xF7, 0xA3, 0x34, 0x24,
		0x14, 0xEF, 0xCF, 0xB3, 0xA3, 0x85,
		0xD4, 0x4C, 0xD1, 0xFD, 0x45, 0x90,
		0x89, 0xD1, 0x9B, 0x50, 0x71, 0xC0,
		0xB7, 0xA0,
	}
	// PolicyB SHA384 digest
	// Source: TCG EK Credential Profile, v2.6
	policyBSHA384 = []byte{
		0xB2, 0x6E, 0x7D, 0x28, 0xD1, 0x1A,
		0x50, 0xBC, 0x53, 0xD8, 0x82, 0xBC,
		0xF5, 0xFD, 0x3A, 0x1A, 0x07, 0x41,
		0x48, 0xBB, 0x35, 0xD3, 0xB4, 0xE4,
		0xCB, 0x1C, 0x0A, 0xD9, 0xBD, 0xE4,
		0x19, 0xCA, 0xCB, 0x47, 0xBA, 0x09,
		0x69, 0x96, 0x46, 0x15, 0x0F, 0x9F,
		0xC0, 0x00, 0xF3, 0xF8, 0x0E, 0x12,
	}
	// PolicyB SHA512 digest
	// Source: TCG EK Credential Profile, v2.6
	policyBSHA512 = []byte{
		0xB8, 0x22, 0x1C, 0xA6, 0x9E, 0x85,
		0x50, 0xA4, 0x91, 0x4D, 0xE3, 0xFA,
		0xA6, 0xA1, 0x8C, 0x07, 0x2C, 0xC0,
		0x12, 0x08, 0x07, 0x3A, 0x92, 0x8D,
		0x5D, 0x66, 0xD5, 0x9E, 0xF7, 0x9E,
		0x49, 0xA4, 0x29, 0xC4, 0x1A, 0x6B,
		0x26, 0x95, 0x71, 0xD5, 0x7E, 0xDB,
		0x25, 0xFB, 0xDB, 0x18, 0x38, 0x42,
		0x56, 0x08, 0xB4, 0x13, 0xCD, 0x61,
		0x6A, 0x5F, 0x6D, 0xB5, 0xB6, 0x07,
		0x1A, 0xF9, 0x9B, 0xEA,
	}
	// PolicyB SM3-256 digest
	// Source: TCG EK Credential Profile, v2.6
	policyBSM3256 = []byte{
		0x16, 0x78, 0x60, 0xA3, 0x5F, 0x2C,
		0x5C, 0x35, 0x67, 0xF9, 0xC9, 0x27,
		0xAC, 0x56, 0xC0, 0x32, 0xF3, 0xB3,
		0xA6, 0x46, 0x2F, 0x8D, 0x03, 0x79,
		0x98, 0xE7, 0xA1, 0x0F, 0x77, 0xFA,
		0x45, 0x4A,
	}

	// PolicyC SHA256 digest
	// Source: TCG EK Credential Profile, v2.6
	policyCSHA256 = []byte{
		0x37, 0x67, 0xE2, 0xED, 0xD4, 0x3F,
		0xF4, 0x5A, 0x3A, 0x7E, 0x1E, 0xAE,
		0xFC, 0xEF, 0x78, 0x64, 0x3D, 0xCA,
		0x96, 0x46, 0x32, 0xE7, 0xAA, 0xD8,
		0x2C, 0x67, 0x3A, 0x30, 0xD8, 0x63,
		0x3F, 0xDE,
	}
	// PolicyC SHA384 digest
	// Source: TCG EK Credential Profile, v2.6
	policyCSHA384 = []byte{
		0xD6, 0x03, 0x2C, 0xE6, 0x1F, 0x2F,
		0xB3, 0xC2, 0x40, 0xEB, 0x3C, 0xF6,
		0xA3, 0x32, 0x37, 0xEF, 0x2B, 0x6A,
		0x16, 0xF4, 0x29, 0x3C, 0x22, 0xB4,
		0x55, 0xE2, 0x61, 0xCF, 0xFD, 0x21,
		0x7A, 0xD5, 0xB4, 0x94, 0x7C, 0x2D,
		0x73, 0xE6, 0x30, 0x05, 0xEE, 0xD2,
		0xDC, 0x2B, 0x35, 0x93, 0xD1, 0x65,
	}
	// PolicyC SHA512 digest
	// Source: TCG EK Credential Profile, v2.6
	policyCSHA512 = []byte{
		0x58, 0x9E, 0xE1, 0xE1, 0x46, 0x54,
		0x47, 0x16, 0xE8, 0xDE, 0xAF, 0xE6,
		0xDB, 0x24, 0x7B, 0x01, 0xB8, 0x1E,
		0x9F, 0x9C, 0x7D, 0xD1, 0x6B, 0x81,
		0x4A, 0xA1, 0x59, 0x13, 0x87, 0x49,
		0x10, 0x5F, 0xBA, 0x53, 0x88, 0xDD,
		0x1D, 0xEA, 0x70, 0x2F, 0x35, 0x24,
		0x0C, 0x18, 0x49, 0x33, 0x12, 0x1E,
		0x2C, 0x61, 0xB8, 0xF5, 0x0D, 0x3E,
		0xF9, 0x13, 0x93, 0xA4, 0x9A, 0x38,
		0xC3, 0xF7, 0x3F, 0xC8,
	}
	// PolicyC SM3-256 digest
	// Source: TCG EK Credential Profile, v2.6
	policyCSM3256 = []byte{
		0x2D, 0x4E, 0x81, 0x57, 0x8C, 0x35,
		0x31, 0xD9, 0xBD, 0x1C, 0xDD, 0x7D,
		0x02, 0xBA, 0x29, 0x8D, 0x56, 0x99,
		0xA3, 0xE3, 0x9F, 0xC3, 0x55, 0x1B,
		0xFE, 0xFF, 0xCF, 0x13, 0x2B, 0x49,
		0xE1, 0x1D,
	}
)

// Predefined handles defined by TCG specifications.
var (
	// SRK handle
	//
	// Source: TCG TPM v2.0 Provisioning Guidance v1.0, rev1.0, section 7.7
	SRKHandle tpm2.TPMHandle = 0x81000001

	// RSA EK handle
	//
	// Source: TCG TPM v2.0 Provisioning Guidance v1.0, rev1.0, section 7.8
	RSAEKHandle tpm2.TPMHandle = 0x81010001
	// ECC EK handle
	//
	// Note: unfortunately TCG TPM v2.0 Provisioning Guidance v1.0, rev1.0, section 7.8
	// does not specify a specific handle for ECC key.
	// However, various TPM2 tools (e.g., go-tpm-tools) use the following handle
	// as the de-facto standard. I've also confirmed with my own TPM (Nuvoton) that the
	// ECC EK is indeed pre-provisioned at this handle.
	//
	// Sources:
	//   - https://docs.kernel.org/security/tpm/tpm-security.html
	//   - https://chromium.googlesource.com/chromiumos/platform2/+/main/vtpm/README.md#glinux-profile
	ECCEKHandle tpm2.TPMHandle = 0x81010002
)

// ReservedHandles contains all TPM handles that are reserved by the TCG specifications.
var ReservedHandles = []tpm2.TPMHandle{
	SRKHandle,
	RSAEKHandle,
	ECCEKHandle,
}

// Predefined templates (public area) from TCG specifications.
var (
	// RSASRKTemplate contains the TCG reference RSA-2048 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	RSASRKTemplate = tpm2.RSASRKTemplate
	// ECCSRKTemplate contains the TCG reference ECC-P256 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	ECCSRKTemplate = tpm2.ECCSRKTemplate
	// Low-Range RSA 2048 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.3.3
	RSAEKTemplate = tpm2.RSAEKTemplate
	// Low-Range ECC P256 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.3.4
	ECCEKTemplate = tpm2.ECCEKTemplate
	// High-Range RSA 2048 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.1
	RSA2048EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: policyBSHA256,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 2048,
			},
		),
	}
	// High-Range ECC P256 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.2
	ECCP256EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: policyBSHA256,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
	}
	// High-Range ECC P384 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.3
	ECCP384EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA384,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: policyBSHA384,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(256),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP384,
			},
		),
	}
	// High-Range ECC P521 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.4
	ECCP521EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA512,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: policyBSHA512,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(256),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCNistP521,
			},
		),
	}
	// High-Range ECC SM2 P256 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.5
	ECCSM2P256EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSM3256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: policyBSM3256,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgSM4,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgSM4,
						tpm2.TPMKeyBits(128),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgSM4,
						tpm2.TPMAlgCFB,
					),
				},
				CurveID: tpm2.TPMECCSM2P256,
			},
		),
	}
	// High-Range RSA 3072 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.6
	RSA3072EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA384,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: policyBSHA384,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(256),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 3072,
			},
		),
	}
	// High-Range RSA 4096 EK template (storage)
	// Source: TCG EK Credential Profile, v2.6, section B.4.4.7
	RSA4096EKTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA384,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      true,
			FirmwareLimited:      false,
			NoDA:                 false,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			Buffer: policyBSHA384,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits: tpm2.NewTPMUSymKeyBits(
						tpm2.TPMAlgAES,
						tpm2.TPMKeyBits(256),
					),
					Mode: tpm2.NewTPMUSymMode(
						tpm2.TPMAlgAES,
						tpm2.TPMAlgCFB,
					),
				},
				KeyBits: 4096,
			},
		),
	}
)

// Predefined private templates (public area) for application keys and attestation
// keys (AK).
//
// These templates are used by [NewApplicationKeyTemplate] and [NewAKTemplate] to produce
// templates depending on the key type.
var (
	eccSigningAppKeyTemplate = tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           false,
			Decrypt:              false,
			SignEncrypt:          true,
		},
	}
	rsaSigningAppKeyTemplate = tpm2.TPMTPublic{
		Type: tpm2.TPMAlgRSA,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           false,
			Decrypt:              true,
			SignEncrypt:          true,
		},
	}
	eccAKTemplate = tpm2.TPMTPublic{
		Type: tpm2.TPMAlgECC,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              false,
			SignEncrypt:          true,
		},
	}
	rsaAKTemplate = tpm2.TPMTPublic{
		Type: tpm2.TPMAlgRSA,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              false,
			SignEncrypt:          true,
		},
	}
)
