package tpmutil

import "fmt"

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
