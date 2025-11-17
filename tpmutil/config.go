package tpmutil

import (
	"crypto"

	"github.com/google/go-tpm/tpm2"
	tpmkit "github.com/loicsikidi/go-tpm-kit"
)

// HashConfig holds configuration for TPM hash operations.
type HashConfig struct {
	// Hierarchy specifies which TPM hierarchy to use for hashing.
	//
	// Defaut: [tpm2.TPMRHOwner].
	Hierarchy tpm2.TPMHandle
	// Password for the hierarchy.
	//
	// Defaut: empty string.
	Password string // TODO(lsikidi): can it be replaced with tpm2.Session?
	// BlockSize for sequential hash operations.
	//
	// Defaut: maxBufferSize (1024 bytes).
	BlockSize int
	// HashAlg specifies the hash algorithm to use.
	//
	// Defaut: crypto.SHA256
	HashAlg crypto.Hash
	// Data to be hashed.
	Data []byte
}

// CheckAndSetDefault validates and sets default values for HashConfig.
func (c *HashConfig) CheckAndSetDefault() error {
	if c.BlockSize < 0 {
		return ErrInvalidBlockSize
	}
	if c.BlockSize == 0 || c.BlockSize > maxBufferSize {
		c.BlockSize = maxBufferSize
	}
	if c.Hierarchy == 0 {
		c.Hierarchy = tpm2.TPMRHOwner
	}
	if c.HashAlg == 0 {
		c.HashAlg = crypto.SHA256
	}
	if len(c.Data) == 0 {
		return ErrMissingData
	}
	return nil
}

// SignConfig holds configuration for TPM signing operations.
type SignConfig struct {
	// KeyHandle to the signing key.
	KeyHandle Handle
	// Digest to sign.
	Digest []byte
	// PublicKey for scheme determination.
	PublicKey crypto.PublicKey
	// SignerOpts for signing options (hash algorithm, etc.).
	//
	// Default: crypto.SHA256
	SignerOpts crypto.SignerOpts
	// Validation ticket from TPM hash operation.
	//
	// Note: use [NullTicket] for external data.
	Validation tpm2.TPMTTKHashCheck
}

// CheckAndSetDefault validates and sets default values for SignConfig.
func (c *SignConfig) CheckAndSetDefault() error {
	if c.KeyHandle == nil {
		return ErrMissingHandle
	}
	if len(c.Digest) == 0 {
		return ErrMissingData
	}
	if c.PublicKey == nil {
		return ErrMissingPublicKey
	}
	if c.SignerOpts == nil {
		c.SignerOpts = crypto.SHA256
	}
	return nil
}

// NVReadConfig holds configuration for TPM NV read operations.
type NVReadConfig struct {
	// Index is the NV index to read from.
	Index tpm2.TPMHandle
	// Hierarchy specifies which TPM hierarchy to use.
	//
	// Default: [tpm2.TPMRHOwner].
	Hierarchy tpm2.TPMHandle
	// Auth is the authorization session.
	//
	// Default: [NoAuth].
	Auth tpm2.Session
	// BlockSize for sequential read operations.
	//
	// Default: maxBufferSize (1024 bytes).
	BlockSize int
}

// CheckAndSetDefault validates and sets default values for NVReadConfig.
func (c *NVReadConfig) CheckAndSetDefault() error {
	if c.Index == 0 {
		return ErrMissingIndex
	}
	if c.BlockSize < 0 {
		return ErrInvalidBlockSize
	}
	if c.BlockSize == 0 || c.BlockSize > maxBufferSize {
		c.BlockSize = maxBufferSize
	}
	if c.Hierarchy == 0 {
		c.Hierarchy = tpm2.TPMRHOwner
	}
	if c.Auth == nil {
		c.Auth = NoAuth
	}
	return nil
}

// NVWriteConfig holds configuration for TPM NV write operations.
type NVWriteConfig struct {
	// Index is the NV index to write to.
	Index tpm2.TPMHandle
	// Data to write.
	Data []byte
	// Hierarchy specifies which TPM hierarchy to use.
	//
	// Default: [tpm2.TPMRHOwner].
	Hierarchy tpm2.TPMHandle
	// Auth is the authorization session.
	//
	// Default: [NoAuth].
	Auth tpm2.Session
	// Attributes specifies NV attributes.
	//
	// Default: defaultNVAttributes.
	Attributes tpm2.TPMANV
}

// CheckAndSetDefault validates and sets default values for NVWriteConfig.
func (c *NVWriteConfig) CheckAndSetDefault() error {
	if c.Index == 0 {
		return ErrMissingIndex
	}
	if len(c.Data) == 0 {
		return ErrMissingData
	}
	if c.Hierarchy == 0 {
		c.Hierarchy = tpm2.TPMRHOwner
	}
	if c.Auth == nil {
		c.Auth = NoAuth
	}
	// Check if Attributes is the zero value
	if c.Attributes == (tpm2.TPMANV{}) {
		c.Attributes = defaultNVAttributes
	}
	return nil
}

type ParentConfig struct {
	// ParentHandle is the handle of the parent key.
	//
	// Default: [tpmkit.SRKHandle].
	Handle Handle
	// KeyType is the type of the key to be created under the parent.
	//
	// Default: [ECC] (to save key generation time).
	KeyType KeyType
	// Hierarchy specifies which TPM hierarchy to use.
	//
	// Default: [tpm2.TPMRHOwner].
	Hierarchy tpm2.TPMHandle
	// Auth is the authorization session for the parent key.
	//
	// Default: [NoAuth].
	Auth tpm2.Session
}

// CheckAndSetDefault validates and sets default values for NVWriteConfig.
func (c *ParentConfig) CheckAndSetDefault() error {
	if c.Handle == nil {
		c.Handle = NewHandle(tpmkit.SRKHandle)
	}
	if c.KeyType == 0 {
		c.KeyType = ECC
	}
	if c.Hierarchy == 0 {
		c.Hierarchy = tpm2.TPMRHOwner
	}
	if c.Auth == nil {
		c.Auth = NoAuth
	}
	return nil
}
