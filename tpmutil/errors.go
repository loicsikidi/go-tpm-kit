package tpmutil

import (
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

var (
	ErrMissingTpm       = errors.New("missing TPM transport")
	ErrDigestNotSafe    = errors.New("digest considered unsafe for signing by the TPM")
	ErrInvalidBlockSize = errors.New("blockSize must be positive")
	ErrDataTooLarge     = errors.New("data size exceeds maximum NV index size")
	ErrMissingHandle    = errors.New("keyHandle is required")
	ErrMissingData      = errors.New("data is required")
	ErrMissingPublicKey = errors.New("publicKey is required")
	ErrMissingIndex     = errors.New("index is required")
)

// ErrHandleNotFound indicates that a handle was not found at the specified address.
type ErrHandleNotFound struct {
	Handle tpm2.TPMHandle
	Err    error
}

func (e *ErrHandleNotFound) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("handle not found at address 0x%x: %v", e.Handle, e.Err)
	}
	return fmt.Sprintf("handle not found at address 0x%x", e.Handle)
}

func (e *ErrHandleNotFound) Unwrap() error {
	return e.Err
}
