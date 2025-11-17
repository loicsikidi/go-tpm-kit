package tpmutil

import "errors"

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
