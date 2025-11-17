package tpmutil

import "fmt"

type KeyType int

const (
	// UnspecifiedKey represents an unknown or unidentified key type.
	UnspecifiedKey KeyType = iota
	// RSA key type
	RSA
	// ECC key type
	ECC
)

func (kt KeyType) String() string {
	switch kt {
	case RSA:
		return "RSA"
	case ECC:
		return "ECC"
	default:
		return fmt.Sprintf("unknown(%d)", kt)
	}
}
