package tpmutil

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
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
