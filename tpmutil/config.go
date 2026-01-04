package tpmutil

import (
	"crypto"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	tpmkit "github.com/loicsikidi/go-tpm-kit"
)

// HashConfig holds configuration for TPM hash operations.
type HashConfig struct {
	// Hierarchy specifies which TPM hierarchy to use for hashing.
	//
	// Defaut: [tpm2.TPMRHOwner].
	Hierarchy tpm2.TPMHandle
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
	// KeyFamily is the type of the key to be created under the parent.
	//
	// Default: [ECC] (to save key generation time).
	KeyFamily KeyFamily
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
	if c.KeyFamily == 0 {
		c.KeyFamily = ECC
	}
	if c.Hierarchy == 0 {
		c.Hierarchy = tpm2.TPMRHOwner
	}
	if c.Auth == nil {
		c.Auth = NoAuth
	}
	return nil
}

type EKParentConfig struct {
	// KeyFamily is the type of the key to be created under the parent.
	//
	// Default: [ECC].
	KeyFamily KeyFamily
	// Handle is the handle of the parent key.
	//
	// Default: [RSAEKHandle] or [ECCEKHandle] based on KeyFamily.
	Handle Handle
	// Hierarchy specifies which TPM hierarchy to use.
	//
	// Default: [tpm2.TPMRHEndorsement].
	Hierarchy tpm2.TPMHandle
	// Auth is the authorization session for the parent key.
	//
	// Default: [NoAuth].
	Auth tpm2.Session
	// Transient key handle represents the current EK key
	// that we want to persist.
	//
	// If nil, a new key will be created based on KeyType and IsLowRange.
	// Default: nil
	TransientKey Handle
	// KeyType specifies the type of EK to create if TransientKey is nil.
	//
	// Default: 0
	KeyType KeyType
	// IsLowRange indicates whether to use low-range templates for EK creation
	// if TransientKey is nil.
	//
	// Note: this field is taken into account only if KeyType is RSA2048 or ECCNISTP256.
	IsLowRange bool
	// Force indicates whether to evict an existing key at the target handle
	// before persisting the new key.
	//
	// Default: false
	Force bool
}

func (c *EKParentConfig) CheckAndSetDefault() error {
	if c.KeyFamily == 0 {
		c.KeyFamily = ECC
	}
	if c.Handle == nil {
		if c.KeyFamily == RSA {
			c.Handle = NewHandle(RSAEKHandle)
		}
		if c.KeyFamily == ECC {
			c.Handle = NewHandle(ECCEKHandle)
		}

	}
	if c.Hierarchy == 0 {
		c.Hierarchy = tpm2.TPMRHEndorsement
	}
	if c.Auth == nil {
		c.Auth = NoAuth
	}
	if c.TransientKey != nil {
		if c.TransientKey.Type() != TransientHandle {
			return fmt.Errorf("invalid value: 'TransientKey' must be a transient TPM handle (got %v)", c.TransientKey.Type())
		}
		if c.KeyType == UnspecifiedAlgo {
			return fmt.Errorf("invalid value: 'KeyType' must be specified (got %v)", c.KeyType)
		}
		if len(c.TransientKey.Name().Buffer) == 0 {
			return fmt.Errorf("invalid value: 'TransientKey' must have a valid Name")
		}
	}
	return nil
}

// CreatePrimaryConfig holds configuration for TPM CreatePrimary operations.
type CreatePrimaryConfig struct {
	// InPublic specifies the key template to use.
	//
	// Required.
	InPublic tpm2.TPMTPublic
	// PrimaryHandle specifies which hierarchy to create the primary key under.
	//
	// Default: [tpm2.TPMRHOwner].
	PrimaryHandle tpm2.TPMHandle
	// Auth is the authorization session for the hierarchy.
	//
	// Default: [NoAuth].
	Auth tpm2.Session
	// UserAuth is the user authorization value for the created primary object.
	//
	// Default: nil.
	UserAuth []byte
	// SealingData is the sensitive data associated with the created primary object.
	//
	// This field can be provided when you want to seal data with the created primary object.
	//
	// Note: this field is accepted if the InPublic is of type [tpm2.TPMAlgKeyedHash].
	//
	// Default: nil.
	SealingData []byte
}

// CheckAndSetDefault validates and sets default values for CreatePrimaryConfig.
func (c *CreatePrimaryConfig) CheckAndSetDefault() error {
	if c.PrimaryHandle == 0 {
		c.PrimaryHandle = tpm2.TPMRHOwner
	}
	if c.Auth == nil {
		c.Auth = NoAuth
	}
	if len(c.SealingData) > 0 {
		if c.InPublic.Type != tpm2.TPMAlgKeyedHash {
			return fmt.Errorf("invalid input: SealingData can only be provided if InPublic.Type is TPMAlgKeyedHash")
		}
		if c.InPublic.ObjectAttributes.SensitiveDataOrigin {
			return fmt.Errorf("invalid input: SealingData cannot be provided if InPublic.ObjectAttributes.SensitiveDataOrigin is set")
		}
	}
	return nil
}

// CreateConfig holds configuration for TPM Create operations.
type CreateConfig struct {
	// ParentHandle is the handle of the parent key.
	//
	// Required.
	ParentHandle Handle
	// ParentAuth is the authorization session for the parent key.
	//
	// Default: [NoAuth].
	ParentAuth tpm2.Session
	// InPublic specifies the key template to use for the created object.
	//
	// Required.
	InPublic tpm2.TPMTPublic
	// UserAuth is the user authorization value for the created object.
	//
	// Default: nil.
	UserAuth []byte
	// SealingData is the sensitive data associated with the created object.
	//
	// This field can be provided when you want to seal data with the created object.
	//
	// Note: this field is accepted if the InPublic is of type [tpm2.TPMAlgKeyedHash].
	//
	// Default: nil.
	SealingData []byte
}

// CheckAndSetDefault validates and sets default values for CreateConfig.
func (c *CreateConfig) CheckAndSetDefault() error {
	if c.ParentHandle == nil {
		return ErrMissingHandle
	}
	if c.ParentAuth == nil {
		c.ParentAuth = NoAuth
	}
	if len(c.SealingData) > 0 {
		if c.InPublic.Type != tpm2.TPMAlgKeyedHash {
			return fmt.Errorf("invalid input: SealingData can only be provided if InPublic.Type is TPMAlgKeyedHash")
		}
		if c.InPublic.ObjectAttributes.SensitiveDataOrigin {
			return fmt.Errorf("invalid input: SealingData cannot be provided if InPublic.ObjectAttributes.SensitiveDataOrigin is set")
		}
	}
	return nil
}

// LoadConfig holds configuration for TPM Load operations.
type LoadConfig struct {
	// ParentHandle is the handle of the parent key.
	//
	// Required.
	ParentHandle Handle
	// InPrivate is the encrypted private portion of the object.
	//
	// Required.
	InPrivate tpm2.TPM2BPrivate
	// InPublic is the public portion of the object.
	//
	// Required.
	InPublic tpm2.TPM2BPublic
	// Auth is the authorization session for the parent key.
	//
	// Default: [NoAuth].
	Auth tpm2.Session
}

// CheckAndSetDefault validates and sets default values for LoadConfig.
func (c *LoadConfig) CheckAndSetDefault() error {
	if c.ParentHandle == nil {
		return ErrMissingHandle
	}
	if len(c.InPrivate.Buffer) == 0 {
		return fmt.Errorf("InPrivate is required")
	}
	if c.Auth == nil {
		c.Auth = NoAuth
	}
	return nil
}

// SymEncryptDecryptConfig holds configuration for TPM symmetric encryption/decryption operations.
type SymEncryptDecryptConfig struct {
	// KeyHandle is the handle to the symmetric key.
	//
	// Required.
	KeyHandle Handle
	// Auth is the authorization session for the key.
	//
	// Default: [NoAuth].
	Auth tpm2.Session
	// Data to encrypt or decrypt.
	//
	// Required.
	Data []byte
	// IV is the initialization vector.
	//
	// Required.
	IV []byte
	// Mode specifies the symmetric mode to use.
	//
	// Default: [tpm2.TPMAlgCFB].
	Mode tpm2.TPMAlgID
	// Decrypt indicates whether to decrypt (true) or encrypt (false).
	//
	// Default: false (encrypt).
	Decrypt bool
	// BlockSize for paginated operations.
	//
	// Default: maxBufferSize (1024 bytes).
	BlockSize int
}

// CheckAndSetDefault validates and sets default values for SymEncryptDecryptConfig.
func (c *SymEncryptDecryptConfig) CheckAndSetDefault() error {
	if c.KeyHandle == nil {
		return ErrMissingHandle
	}
	if len(c.Data) == 0 {
		return ErrMissingData
	}
	if len(c.IV) == 0 {
		return fmt.Errorf("invalid input: IV is required")
	}
	if c.Auth == nil {
		c.Auth = NoAuth
	}
	if c.Mode == 0 {
		c.Mode = tpm2.TPMAlgCFB
	}
	if c.BlockSize < 0 {
		return ErrInvalidBlockSize
	}
	if c.BlockSize == 0 || c.BlockSize > maxBufferSize {
		c.BlockSize = maxBufferSize
	}
	return nil
}

// HmacConfig holds configuration for TPM HMAC operations.
type HmacConfig struct {
	// KeyHandle is the handle to the HMAC key.
	//
	// Required.
	KeyHandle Handle
	// Auth is the authorization session for the key.
	//
	// Default: [NoAuth].
	Auth tpm2.Session
	// BlockSize for sequential HMAC operations.
	//
	// Default: maxBufferSize (1024 bytes).
	BlockSize int
	// HashAlg specifies the hash algorithm to use for HMAC.
	//
	// Default: [tpm2.TPMAlgNull] (uses the key's algorithm).
	HashAlg tpm2.TPMAlgID
	// Data to be HMACed.
	//
	// Required.
	Data []byte
	// Hierarchy specifies which TPM hierarchy to use for completing the sequence.
	//
	// Default: [tpm2.TPMRHOwner].
	Hierarchy tpm2.TPMHandle
}

// CheckAndSetDefault validates and sets default values for HmacConfig.
func (c *HmacConfig) CheckAndSetDefault() error {
	if c.KeyHandle == nil {
		return ErrMissingHandle
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
	if len(c.Data) == 0 {
		return ErrMissingData
	}
	return nil
}
