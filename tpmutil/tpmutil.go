package tpmutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpmkit "github.com/loicsikidi/go-tpm-kit"
	"github.com/loicsikidi/go-tpm-kit/internal/utils"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
)

var (
	NoAuth     = tpm2.PasswordAuth(nil)
	NullTicket = tpm2.TPMTTKHashCheck{
		Tag:       tpm2.TPMSTHashCheck,
		Hierarchy: tpm2.TPMRHNull,
	}
	defaultNVAttributes = tpm2.TPMANV{
		AuthRead:   true,
		NT:         tpm2.TPMNTOrdinary,
		OwnerRead:  true,
		OwnerWrite: true,
		PolicyRead: true,
		NoDA:       true,
	}
)

const (
	maxBufferSize = tpmkit.MaxBufferSize
	maxNVSize     = 2048
	maxIndexCount = 256
)

// NVRead reads data from a non-volatile storage (NV) index.
//
// By default, data is read from a single NV index.
// When [NVReadConfig.MultiIndex] is true, data is read from successive NV indices
// starting from the base index. This should be used when reading data that was
// written with [NVWriteConfig.MultiIndex] enabled.
//
// Examples:
//
//	// Read from a single NV index
//	data, err := tpmutil.NVRead(tpm, &tpmutil.NVReadConfig{
//		Index:     0x01500000,
//		Hierarchy: tpm2.TPMRHOwner,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Read %d bytes from NV index\n", len(data))
//
//	// Read data that was written across multiple NV indices
//	// This will read from 0x01500000, 0x01500001, 0x01500002, etc.
//	// until all data has been retrieved
//	data, err = tpmutil.NVRead(tpm, &tpmutil.NVReadConfig{
//		Index:      0x01500000,
//		Hierarchy:  tpm2.TPMRHOwner,
//		MultiIndex: true,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Note: If cfg is nil, default configuration is used.
func NVRead(t transport.TPM, optionalCfg ...NVReadConfig) ([]byte, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}
	return nvRead(t, cfg.Hierarchy, cfg.Index, cfg.Auth, cfg.BlockSize, cfg.MultiIndex)
}

func nvRead(t transport.TPM, hierarchy, index tpm2.TPMHandle, auth tpm2.Session, blockSize int, multiIndex bool) ([]byte, error) {
	if !multiIndex {
		return nvReadSingleIndex(t, hierarchy, index, auth, blockSize)
	}

	// Multi-index read: read from successive indices until we encounter a non-existent index
	var allData []byte
	chunkIdx := 0

	for {
		// defensive approach to avoid infinite loop or excessive indices
		if chunkIdx >= maxIndexCount {
			return nil, ErrDataTooLarge
		}

		currentIndex := tpm2.TPMHandle(uint32(index) + uint32(chunkIdx))

		// Try to read the current index
		chunkData, err := nvReadSingleIndex(t, hierarchy, currentIndex, auth, blockSize)
		if err != nil {
			// If we get an error on the first index, propagate it
			if chunkIdx == 0 {
				return nil, err
			}
			// Otherwise, we've reached the end of the multi-index data
			break
		}

		allData = append(allData, chunkData...)
		chunkIdx++
	}

	return allData, nil
}

func nvReadSingleIndex(t transport.TPM, hierarchy, index tpm2.TPMHandle, auth tpm2.Session, blockSize int) ([]byte, error) {
	readPubRsp, err := tpm2.NVReadPublic{
		NVIndex: index,
	}.Execute(t)
	if err != nil {
		return nil, err
	}

	pub, err := readPubRsp.NVPublic.Contents()
	if err != nil {
		return nil, err
	}

	outBuff := make([]byte, 0, int(pub.DataSize))
	offset := uint16(0)
	for len(outBuff) < int(pub.DataSize) {
		readSize := blockSize
		if readSize > (int(pub.DataSize) - len(outBuff)) {
			readSize = int(pub.DataSize) - len(outBuff)
		}

		readRsp, err := tpm2.NVRead{
			AuthHandle: ToAuthHandle(NewHandle(hierarchy), auth),
			NVIndex: tpm2.NamedHandle{
				Handle: index,
				Name:   readPubRsp.NVName,
			},
			Size:   uint16(readSize),
			Offset: offset,
		}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("running NV_Read command (cursor=%d,size=%d): %w", len(outBuff), readSize, err)
		}

		outBuff = append(outBuff, readRsp.Data.Buffer...)
		offset += uint16(readSize)
	}
	return outBuff, nil
}

// NVWrite writes data to a non-volatile storage (NV) index.
//
// By default, data is limited to 2048 bytes on a single NV index.
// When [NVWriteConfig.MultiIndex] is true, larger data is automatically split
// into 2048-byte chunks and written to successive NV indices.
//
// The maximum number of indices that can be used is 256, which limits the total
// data size to 524,288 bytes (512 KB) when using multi-index mode. If the data
// size exceeds this limit, [ErrDataTooLarge] is returned.
//
// Examples:
//
//	// Write data to a single NV index (≤2048 bytes)
//	data := []byte("secret data")
//	err := tpmutil.NVWrite(tpm, &tpmutil.NVWriteConfig{
//		Index:     0x01500000,
//		Data:      data,
//		Hierarchy: tpm2.TPMRHOwner,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Write large data across multiple NV indices
//	// Data of 4196 bytes (2×2048 + 100) will be split into 3 chunks:
//	// - 2048 bytes at index 0x01500000
//	// - 2048 bytes at index 0x01500001
//	// - 100 bytes at index 0x01500002
//	largeData := make([]byte, 4196)
//	err = tpmutil.NVWrite(tpm, &tpmutil.NVWriteConfig{
//		Index:      0x01500000,
//		Data:       largeData,
//		Hierarchy:  tpm2.TPMRHOwner,
//		MultiIndex: true,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Note: If cfg is nil, default configuration is used.
func NVWrite(t transport.TPM, optionalCfg ...NVWriteConfig) error {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return err
	}
	return nvWrite(t, cfg.Hierarchy, cfg.Index, cfg.Auth, cfg.Data, cfg.Attributes, cfg.MultiIndex)
}

func nvWrite(t transport.TPM, hierarchy, index tpm2.TPMHandle, auth tpm2.Session, data []byte, attributes tpm2.TPMANV, multiIndex bool) error {
	// Validate data size based on multiIndex setting
	if !multiIndex && len(data) > maxNVSize {
		return ErrDataTooLarge
	}

	if auth == nil {
		auth = NoAuth
	}

	// Calculate chunks for multi-index write
	var chunks [][]byte
	if multiIndex && len(data) > maxNVSize {
		// Split data into chunks of maxNVSize
		for i := 0; i < len(data); i += maxNVSize {
			end := min(i+maxNVSize, len(data))
			chunks = append(chunks, data[i:end])
		}
	} else {
		// Single index write
		chunks = [][]byte{data}
	}

	// Write each chunk to successive NV indices
	for chunkIdx, chunk := range chunks {
		currentIndex := tpm2.TPMHandle(uint32(index) + uint32(chunkIdx))

		defs := tpm2.NVDefineSpace{
			AuthHandle: ToAuthHandle(NewHandle(hierarchy), auth),
			PublicInfo: tpm2.New2B(
				tpm2.TPMSNVPublic{
					NVIndex:    currentIndex,
					NameAlg:    tpm2.TPMAlgSHA256,
					Attributes: attributes,
					DataSize:   uint16(len(chunk)),
				}),
		}
		if _, err := defs.Execute(t); err != nil {
			return fmt.Errorf("defining NV space at index 0x%x (chunk %d/%d): %w", currentIndex, chunkIdx+1, len(chunks), err)
		}

		pub, err := defs.PublicInfo.Contents()
		if err != nil {
			return err
		}

		nvName, err := tpm2.NVName(pub)
		if err != nil {
			return err
		}

		// Write chunk data with pagination
		var offset uint16
		for offset < uint16(len(chunk)) {
			end := min(int(offset+maxBufferSize), len(chunk))

			write := tpm2.NVWrite{
				AuthHandle: ToAuthHandle(NewHandle(hierarchy), auth),
				NVIndex: tpm2.NamedHandle{
					Handle: pub.NVIndex,
					Name:   *nvName,
				},
				Data: tpm2.TPM2BMaxNVBuffer{
					Buffer: chunk[int(offset):end],
				},
				Offset: offset,
			}
			if _, err := write.Execute(t); err != nil {
				return fmt.Errorf("running NV_Write command at index 0x%x (chunk %d/%d, offset=%d): %w", currentIndex, chunkIdx+1, len(chunks), offset, err)
			}
			offset += maxBufferSize
		}
	}

	return nil
}

// HashResult contains the result of a TPM hash operation.
type HashResult struct {
	// Digest is the computed hash digest.
	Digest []byte
	// Validation is the ticket returned by the TPM.
	Validation tpm2.TPMTTKHashCheck
}

// Hash hashes data using the TPM with the provided configuration.
//
// Note: If cfg is nil, default configuration is used.
//
// Example:
//
//	// Hash data using TPM with SHA256
//	result, err := tpmutil.Hash(tpm, &tpmutil.HashConfig{
//		Data:      []byte("data to hash"),
//		HashAlg:   crypto.SHA256,
//		Hierarchy: tpm2.TPMRHOwner,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Digest: %x\n", result.Digest)
func Hash(t transport.TPM, optionalCfg ...HashConfig) (*HashResult, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}
	digest, validation, err := hash(t, cfg.Hierarchy, cfg.BlockSize, cfg.Data, cfg.HashAlg)
	if err != nil {
		return nil, err
	}
	return &HashResult{
		Digest:     digest,
		Validation: validation,
	}, nil
}

func hash(t transport.TPM, hierarchy tpm2.TPMHandle, blockSize int, data []byte, h crypto.Hash) ([]byte, tpm2.TPMTTKHashCheck, error) {
	nilTicket := tpm2.TPMTTKHashCheck{}

	// Generate an ephemeral authorization for the sequence
	sequenceAuth := MustGenerateRnd(32)

	alg, err := tpmcrypto.HashToAlgorithm(h)
	if err != nil {
		return nil, nilTicket, err
	}

	hashSequenceStart := tpm2.HashSequenceStart{
		Auth: tpm2.TPM2BAuth{
			Buffer: sequenceAuth,
		},
		HashAlg: alg,
	}

	rspHSS, err := hashSequenceStart.Execute(t)
	if err != nil {
		return nil, nilTicket, fmt.Errorf("HashSequenceStart failed: %w", err)
	}

	authHandle := ToAuthHandle(NewHandle(&tpm2.NamedHandle{
		Handle: rspHSS.SequenceHandle,
		Name: tpm2.TPM2BName{
			Buffer: sequenceAuth,
		},
	}), tpm2.PasswordAuth(sequenceAuth))

	for len(data) > blockSize {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:blockSize],
			},
		}
		_, err = sequenceUpdate.Execute(t)
		if err != nil {
			return nil, nilTicket, fmt.Errorf("SequenceUpdate failed: %w", err)
		}

		data = data[blockSize:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: hierarchy,
	}

	rspSC, err := sequenceComplete.Execute(t)
	if err != nil {
		return nil, nilTicket, fmt.Errorf("SequenceComplete failed: %w", err)
	}

	if hierarchy != tpm2.TPMRHNull && rspSC.Validation.Hierarchy == tpm2.TPMRHNull {
		return nil, nilTicket, ErrDigestNotSafe
	}

	return rspSC.Result.Buffer, rspSC.Validation, nil
}

// Hmac computes HMAC using the TPM with the provided configuration.
//
// Example:
//
//	// Compute HMAC with a TPM key
//	result, err := tpmutil.Hmac(tpm, &tpmutil.HmacConfig{
//		KeyHandle: hmacKeyHandle,
//		Data:      []byte("data to authenticate"),
//		Auth:      tpm2.PasswordAuth([]byte("keypassword")),
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("HMAC: %x\n", result.Digest)
//
// Note: If cfg is nil, default configuration is used.
func Hmac(t transport.TPM, optionalCfg ...HmacConfig) ([]byte, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}
	return hmac(t, cfg.KeyHandle, cfg.Auth, cfg.BlockSize, cfg.Data, cfg.HashAlg, cfg.Hierarchy)
}

func hmac(t transport.TPM, keyHandle Handle, auth tpm2.Session, blockSize int, data []byte, hashAlg tpm2.TPMAlgID, hierarchy tpm2.TPMHandle) ([]byte, error) {
	// Generate an ephemeral authorization for the sequence
	sequenceAuth := MustGenerateRnd(32)

	hmacStart := tpm2.HmacStart{
		Handle: ToAuthHandle(keyHandle, auth),
		Auth: tpm2.TPM2BAuth{
			Buffer: sequenceAuth,
		},
		HashAlg: hashAlg,
	}

	rspHS, err := hmacStart.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("HmacStart failed: %w", err)
	}

	authHandle := ToAuthHandle(NewHandle(&tpm2.NamedHandle{
		Handle: rspHS.SequenceHandle,
		Name: tpm2.TPM2BName{
			Buffer: sequenceAuth,
		},
	}), tpm2.PasswordAuth(sequenceAuth))

	for len(data) > blockSize {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:blockSize],
			},
		}
		_, err = sequenceUpdate.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("SequenceUpdate failed: %w", err)
		}

		data = data[blockSize:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: hierarchy,
	}

	rspSC, err := sequenceComplete.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("SequenceComplete failed: %w", err)
	}

	return rspSC.Result.Buffer, nil
}

// Sign signs a digest using the TPM with the provided configuration.
//
// Note: If cfg is nil, default configuration is used.
//
// Example:
//
//	// Sign a digest with a TPM key
//	digest := []byte{0x01, 0x02, 0x03}
//	signature, err := tpmutil.Sign(tpm, &tpmutil.SignConfig{
//		KeyHandle:  keyHandle,
//		Digest:     digest,
//		PublicKey:  publicKey,
//		SignerOpts: crypto.SHA256,
//		Validation: tpmutil.NullTicket,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Signature: %x\n", signature)
func Sign(t transport.TPM, optionalCfg ...SignConfig) ([]byte, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}

	sigScheme, err := tpmcrypto.GetSigSchemeFromPublicKey(cfg.PublicKey, cfg.SignerOpts)
	if err != nil {
		return nil, fmt.Errorf("GetSigSchemeFromPublicKey failed: %w", err)
	}

	signCmd := tpm2.Sign{
		KeyHandle:  cfg.KeyHandle,
		Digest:     tpm2.TPM2BDigest{Buffer: cfg.Digest},
		InScheme:   sigScheme,
		Validation: cfg.Validation,
	}

	rspSign, err := signCmd.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("Sign failed: %w", err)
	}

	switch cfg.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return formatECDSASignature(rspSign.Signature)
	case *rsa.PublicKey:
		return formatRSASignature(rspSign.Signature, sigScheme.Scheme)
	}
	return nil, fmt.Errorf("unsupported signing key type: %T", cfg.PublicKey)
}

func formatECDSASignature(sig tpm2.TPMTSignature) ([]byte, error) {
	eccSig, err := sig.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("failed to get ECDSA signature: %w", err)
	}

	r := new(big.Int).SetBytes(eccSig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(eccSig.SignatureS.Buffer)

	der, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{r, s})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA signature: %w", err)
	}
	return der, nil
}

func formatRSASignature(sig tpm2.TPMTSignature, alg tpm2.TPMAlgID) ([]byte, error) {
	switch alg {
	case tpm2.TPMAlgRSASSA:
		rsaSig, err := sig.Signature.RSASSA()
		if err != nil {
			return nil, fmt.Errorf("failed to get RSASSA signature: %w", err)
		}
		return rsaSig.Sig.Buffer, nil
	case tpm2.TPMAlgRSAPSS:
		rsaSig, err := sig.Signature.RSAPSS()
		if err != nil {
			return nil, fmt.Errorf("failed to get RSAPSS signature: %w", err)
		}
		return rsaSig.Sig.Buffer, nil
	default:
		return nil, fmt.Errorf("unsupported RSA signature algorithm: %#x", alg)
	}
}

// GetSKRHandle retrieves or creates the Storage Root Key (SRK) handle based on the provided configuration.
//
// Example:
//
//	// Get or create an ECC SRK at the default persistent handle
//	srkHandle, err := tpmutil.GetSKRHandle(tpm, &tpmutil.ParentConfig{
//		KeyType:   tpmutil.ECC,
//		Hierarchy: tpm2.TPMRHOwner,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("SRK handle: 0x%x\n", srkHandle.Handle())
//
// Note: If cfg is nil, default configuration is used.
func GetSKRHandle(t transport.TPM, optionalCfg ...ParentConfig) (Handle, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}

	readPublicRsp, err := tpm2.ReadPublic{
		ObjectHandle: cfg.Handle.Handle(),
	}.Execute(t)
	if err == nil {
		// Found the persistent handle, assume it's the key we want.
		h := &tpm2.NamedHandle{Name: readPublicRsp.Name, Handle: cfg.Handle.Handle()}
		return NewHandle(h), nil
	}

	rerr := err // Preserve this failure for later logging, if needed

	var srkTemplate tpm2.TPMTPublic
	switch cfg.KeyFamily {
	case RSA:
		srkTemplate = RSASRKTemplate
	case ECC:
		srkTemplate = ECCSRKTemplate
	default:
		return nil, fmt.Errorf("unsupported SRK KeyType: %v", cfg.KeyFamily)
	}

	srkHandle, err := CreatePrimary(t, CreatePrimaryConfig{
		InPublic:      srkTemplate,
		PrimaryHandle: cfg.Hierarchy,
		Auth:          cfg.Auth,
	})
	if err != nil {
		return nil, fmt.Errorf("ReadPublic failed (%v), and then CreatePrimary failed: %v", rerr, err)
	}
	defer srkHandle.Close() //nolint:errcheck

	// Make the SRK persistent at the desired handle.
	persistedHandle, err := Persist(t, PersistConfig{
		Hierarchy:        cfg.Hierarchy,
		Auth:             cfg.Auth,
		TransientHandle:  srkHandle,
		PersistentHandle: cfg.Handle,
	})
	if err != nil {
		return nil, fmt.Errorf("ReadPublic failed (%v), and then Persist failed: %v", rerr, err)
	}

	return persistedHandle, nil
}

// GetEKHandle retrieves the Endorsement Key (EK) handle from the TPM.
// Unlike [GetSKRHandle], this function does not create the EK if it doesn't exist.
//
// Example:
//
//	// Get RSA EK at the default persistent handle
//	ekHandle, err := tpmutil.GetEKHandle(tpm, &tpmutil.EKParentConfig{
//		KeyFamily: tpmutil.RSA,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("EK handle: 0x%x\n", ekHandle.Handle())
//
// Note: If cfg is nil, default configuration is used (RSA EK at handle 0x81010001).
func GetEKHandle(t transport.TPM, optionalCfg ...EKParentConfig) (Handle, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}

	readPublicRsp, err := tpm2.ReadPublic{
		ObjectHandle: cfg.Handle.Handle(),
	}.Execute(t)
	if err != nil {
		return nil, &ErrHandleNotFound{
			Handle: cfg.Handle.Handle(),
			Err:    err,
		}
	}

	h := &tpm2.NamedHandle{Name: readPublicRsp.Name, Handle: cfg.Handle.Handle()}
	return NewHandle(h), nil
}

// getEKTemplate returns the appropriate EK template based on KeyType and IsLowRange.
func getEKTemplate(keyType KeyType, isLowRange bool) (tpm2.TPMTPublic, error) {
	switch keyType {
	case RSA2048:
		if isLowRange {
			return RSAEKTemplate, nil
		}
		return RSA2048EKTemplate, nil
	case RSA3072:
		return RSA3072EKTemplate, nil
	case RSA4096:
		return RSA4096EKTemplate, nil
	case ECCNISTP256:
		if isLowRange {
			return ECCEKTemplate, nil
		}
		return ECCP256EKTemplate, nil
	case ECCNISTP384:
		return ECCP384EKTemplate, nil
	case ECCNISTP521:
		return ECCP521EKTemplate, nil
	case ECCSM2P256:
		return ECCSM2P256EKTemplate, nil
	default:
		return tpm2.TPMTPublic{}, fmt.Errorf("unsupported EK KeyType: %v", keyType)
	}
}

// PersistEK persists an Endorsement Key (EK) to the TPM at the configured handle.
//
// If cfg.TransientKey is nil, a new transient EK is created based on cfg.KeyType
// and cfg.IsLowRange. Otherwise, the provided transient key is persisted.
//
// Example:
//
//	// Create and persist a new RSA EK
//	ekHandle, err := tpmutil.PersistEK(tpm, &tpmutil.EKParentConfig{
//		KeyFamily:  tpmutil.RSA,
//		KeyType:    tpmutil.RSA2048,
//		IsLowRange: true,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Persisted EK at handle: 0x%x\n", ekHandle.Handle())
//
// Note: If cfg is nil, default configuration is used.
func PersistEK(t transport.TPM, optionalCfg ...EKParentConfig) (Handle, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}

	var transientHandle Handle

	if cfg.TransientKey == nil {
		template, err := getEKTemplate(cfg.KeyType, cfg.IsLowRange)
		if err != nil {
			return nil, err
		}

		ekHandle, err := CreatePrimary(t, CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			InPublic:      template,
			Auth:          cfg.Auth,
		})
		if err != nil {
			return nil, fmt.Errorf("CreatePrimary failed: %w", err)
		}
		defer ekHandle.Close() //nolint:errcheck

		transientHandle = ekHandle
	} else {
		// Use the provided transient key
		transientHandle = cfg.TransientKey
	}

	// Persist the transient key
	persistedHandle, err := Persist(t, PersistConfig{
		Hierarchy:        tpm2.TPMRHOwner,
		Auth:             NoAuth,
		TransientHandle:  transientHandle,
		PersistentHandle: cfg.Handle,
		Force:            cfg.Force,
	})
	if err != nil {
		return nil, fmt.Errorf("Persist failed: %w", err)
	}

	return persistedHandle, nil
}

// Persist makes a transient object persistent at the specified handle.
//
// This function wraps the TPM2_EvictControl command to persist a transient object
// to a persistent handle in the TPM's non-volatile storage.
//
// If Force is true, the existing key is evicted before persisting the new one.
//
// Example:
//
//	// Create a transient primary key
//	eccTemplate := tpmutil.ECCSRKTemplate
//	transientHandle, err := tpmutil.CreatePrimary(tpm, tpmutil.CreatePrimaryConfig{
//		PrimaryHandle: tpm2.TPMRHOwner,
//		InPublic:      eccTemplate,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer transientHandle.Close()
//
//	// Persist the transient key
//	persistentHandle, err := tpmutil.Persist(tpm, tpmutil.PersistConfig{
//		TransientHandle:  transientHandle,
//		PersistentHandle: tpmutil.NewHandle(tpmkit.SRKHandle),
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Persisted handle: 0x%x\n", persistentHandle.Handle())
//
// Note: If cfg is nil, default configuration is used.
func Persist(t transport.TPM, optionalCfg ...PersistConfig) (Handle, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}

	// Check if a key already exists at the target handle
	readPublicRsp, err := tpm2.ReadPublic{
		ObjectHandle: cfg.PersistentHandle.Handle(),
	}.Execute(t)
	if err == nil {
		// Key exists at the target handle
		if !cfg.Force {
			return nil, fmt.Errorf("key already exists at handle 0x%x (use Force to overwrite)", cfg.PersistentHandle.Handle())
		}

		// Remove the existing key
		existingHandle := NewHandle(&tpm2.NamedHandle{
			Handle: cfg.PersistentHandle.Handle(),
			Name:   readPublicRsp.Name,
		})
		_, evictErr := tpm2.EvictControl{
			Auth:             ToAuthHandle(NewHandle(cfg.Hierarchy), cfg.Auth),
			ObjectHandle:     existingHandle,
			PersistentHandle: cfg.PersistentHandle.Handle(),
		}.Execute(t)
		if evictErr != nil {
			return nil, fmt.Errorf("failed to evict existing key at handle 0x%x: %w", cfg.PersistentHandle.Handle(), evictErr)
		}
	}

	_, err = tpm2.EvictControl{
		Auth:             ToAuthHandle(NewHandle(cfg.Hierarchy), cfg.Auth),
		ObjectHandle:     cfg.TransientHandle,
		PersistentHandle: cfg.PersistentHandle.Handle(),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("EvictControl failed: %w", err)
	}

	// Return the persistent handle
	persistedHandle := NewHandle(&tpm2.NamedHandle{
		Handle: cfg.PersistentHandle.Handle(),
		Name:   cfg.TransientHandle.Name(),
	})

	return persistedHandle, nil
}

// CreatePrimary creates a primary key in the TPM and returns a [HandleCloser].
//
// Example:
//
//	// Create an ECC primary key in the owner hierarchy
//	eccTemplate := tpmutil.ECCSRKTemplate
//	primaryHandle, err := tpmutil.CreatePrimary(tpm, &tpmutil.CreatePrimaryConfig{
//		PrimaryHandle: tpm2.TPMRHOwner,
//		Template:      &eccTemplate,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer primaryHandle.Close()
//
// Note: If cfg is nil, default configuration is used.
func CreatePrimary(t transport.TPM, optionalCfg ...CreatePrimaryConfig) (HandleCloser, error) {
	rsp, closer, err := CreatePrimaryWithResult(t, optionalCfg...)
	if err != nil {
		return nil, err
	}

	public, err := rsp.OutPublic.Contents()
	if err != nil {
		// Close the handle before returning the error
		_ = closer()
		return nil, err
	}

	h := &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}
	hc := &tpmHandle{
		handle: h,
		tpm:    t,
		public: public,
	}
	return hc, nil
}

// CreatePrimaryWithResult creates a primary key in the TPM and returns the result along with a closer function.
//
// Example:
//
//	// Create an RSA primary key and get the full response
//	rsaTemplate := tpm2.RSASRKTemplate
//	result, closer, err := tpmutil.CreatePrimaryWithResult(tpm, &tpmutil.CreatePrimaryConfig{
//		PrimaryHandle: tpm2.TPMRHOwner,
//		Template:      &rsaTemplate,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer closer()
//
// Note: If cfg is nil, default configuration is used.
func CreatePrimaryWithResult(t transport.TPM, optionalCfg ...CreatePrimaryConfig) (*CreatePrimaryResult, func() error, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, nil, err
	}

	cmd := tpm2.CreatePrimary{
		PrimaryHandle: ToAuthHandle(NewHandle(cfg.PrimaryHandle), cfg.Auth),
		InSensitive:   toTPM2BSensitiveCreate(cfg.UserAuth, cfg.SealingData),
		InPublic:      tpm2.New2B(cfg.InPublic),
	}

	rsp, err := cmd.Execute(t)
	if err != nil {
		return nil, nil, err
	}

	result := &CreatePrimaryResult{
		ObjectHandle:   rsp.ObjectHandle,
		OutPublic:      rsp.OutPublic,
		CreationData:   rsp.CreationData,
		CreationHash:   rsp.CreationHash,
		CreationTicket: rsp.CreationTicket,
		Name:           rsp.Name,
	}

	closer := func() error {
		_, err := (&tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}).Execute(t)
		return err
	}
	return result, closer, nil
}

// Load loads a key into the TPM and returns a [HandleCloser].
//
// Example:
//
//	// Load a previously created key into the TPM
//	keyHandle, err := tpmutil.Load(tpm, &tpmutil.LoadConfig{
//		ParentHandle: srkHandle,
//		InPrivate:    createRsp.OutPrivate,
//		InPublic:     createRsp.OutPublic,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer keyHandle.Close()
//
// Note: If cfg is nil, default configuration is used.
func Load(t transport.TPM, optionalCfg ...LoadConfig) (HandleCloser, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}

	cmd := tpm2.Load{
		ParentHandle: ToAuthHandle(cfg.ParentHandle, cfg.Auth),
		InPrivate:    cfg.InPrivate,
		InPublic:     cfg.InPublic,
	}

	rsp, err := cmd.Execute(t)
	if err != nil {
		return nil, err
	}

	public, err := cfg.InPublic.Contents()
	if err != nil {
		return nil, err
	}

	h := &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}
	hc := &tpmHandle{
		handle: h,
		tpm:    t,
		public: public,
	}
	return hc, nil
}

// Create creates a child key under a parent key in the TPM and loads it.
//
// This is a convenience function that combines [CreateWithResult] and [Load].
// Use [CreateWithResult] if you need the encrypted private/public portions
// for later use without loading the key immediately.
//
// Example:
//
//	// Create a child key under an existing parent
//	srkHandle, err := tpmutil.GetSKRHandle(tpm)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	eccTemplate := tpmutil.ECCSRKTemplate
//	keyHandle, err := tpmutil.Create(tpm, tpmutil.CreateConfig{
//		ParentHandle: srkHandle,
//		Template:     eccTemplate,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer keyHandle.Close()
//
// Note: If cfg is nil, default configuration is used.
func Create(t transport.TPM, optionalCfg ...CreateConfig) (HandleCloser, error) {
	cfg := utils.OptionalArg(optionalCfg) // cfg will be checked in CreateWithResult

	result, err := CreateWithResult(t, cfg)
	if err != nil {
		return nil, err
	}

	return Load(t, LoadConfig{
		ParentHandle: cfg.ParentHandle,
		InPrivate:    result.OutPrivate,
		InPublic:     result.OutPublic,
		Auth:         cfg.ParentAuth,
	})
}

// CreateWithResult creates a child key under a parent key in the TPM and returns the result.
//
// This function returns the encrypted private and public portions that can later be loaded with [Load].
//
// Use this function if you need to marshal the created key material for storage or transmission.
// For direct loading, use [Create] instead.
//
// Example:
//
//	// CreateWithResult a child key under an existing parent
//	srkHandle, err := tpmutil.GetSKRHandle(tpm)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	eccTemplate := tpmutil.ECCSRKTemplate
//	result, err := tpmutil.CreateWithResult(tpm, &tpmutil.CreateConfig{
//		ParentHandle: srkHandle,
//		Template:     &eccTemplate,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// marshal the result in order to store or transmit it
//	b, err := result.Marshal()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Later, load the created key
//	keyHandle, err := tpmutil.Load(tpm, &tpmutil.LoadConfig{
//		ParentHandle: srkHandle,
//		InPrivate:    result.OutPrivate,
//		InPublic:     result.OutPublic,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer keyHandle.Close()
//
// Note: If cfg is nil, default configuration is used.
func CreateWithResult(t transport.TPM, optionalCfg ...CreateConfig) (*CreateResult, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}

	cmd := tpm2.Create{
		ParentHandle: ToAuthHandle(cfg.ParentHandle, cfg.ParentAuth),
		InSensitive:  toTPM2BSensitiveCreate(cfg.UserAuth, cfg.SealingData),
		InPublic:     tpm2.New2B(cfg.InPublic),
	}

	rsp, err := cmd.Execute(t)
	if err != nil {
		return nil, err
	}

	return &CreateResult{
		OutPrivate:     rsp.OutPrivate,
		OutPublic:      rsp.OutPublic,
		CreationData:   rsp.CreationData,
		CreationHash:   rsp.CreationHash,
		CreationTicket: rsp.CreationTicket,
	}, nil
}

// GenerateRnd generates a random byte slice of the specified size.
//
// The size should match the cipher's block size requirement.
//
// This function can be used to generate a random IV (initialization vector) for encryption.
// For AES, this is typically 16 bytes (128 bits).
//
// Example:
//
//	// Generate random bytes (16 bytes)
//	iv, err := tpmutil.GenerateRnd(16)
//	if err != nil {
//		log.Fatal(err)
//	}
func GenerateRnd(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid size: %d (must be positive)", size)
	}
	iv := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}
	return iv, nil
}

// MustGenerateRnd generates a random byte slice of the specified size.
// It panics if an error occurs.
//
// This function is useful for testing or when you are certain the size is valid.
//
// Example:
//
//	// Generate random bytes (16 bytes)
//	rnd := tpmutil.MustGenerateRnd(16)
func MustGenerateRnd(size int) []byte {
	b, err := GenerateRnd(size)
	if err != nil {
		panic(fmt.Sprintf("MustGenerateRnd: %v", err))
	}
	return b
}

// SymEncryptDecrypt encrypts or decrypts data using TPM symmetric key with pagination support.
//
// This function handles large data by automatically paginating it into chunks that fit within
// the TPM's buffer size limit. The IV is updated after each block to maintain cipher state.
//
// Example:
//
//	// Generate IV
//	iv := tpmutil.MustGenerateIV(16)
//
//	// Encrypt data
//	encrypted, err := tpmutil.SymEncryptDecrypt(tpm, &tpmutil.SymEncryptDecryptConfig{
//		KeyHandle: keyHandle,
//		Data:      []byte("secret message"),
//		IV:        iv,
//		Mode:      tpm2.TPMAlgCFB,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Decrypt data
//	decrypted, err := tpmutil.SymEncryptDecrypt(tpm, &tpmutil.SymEncryptDecryptConfig{
//		KeyHandle: keyHandle,
//		Data:      encrypted,
//		IV:        iv,
//		Mode:      tpm2.TPMAlgCFB,
//		Decrypt:   true,
//	})
//
// Note: If cfg is nil, default configuration is used.
func SymEncryptDecrypt(t transport.TPM, optionalCfg ...SymEncryptDecryptConfig) ([]byte, error) {
	cfg := utils.OptionalArg(optionalCfg)
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}
	return symEncryptDecrypt(t, cfg.KeyHandle, cfg.Auth, cfg.IV, cfg.Data, cfg.Mode, cfg.Decrypt, cfg.BlockSize)
}

func symEncryptDecrypt(t transport.TPM, keyHandle Handle, auth tpm2.Session, iv, data []byte, mode tpm2.TPMAlgID, decrypt bool, blockSize int) ([]byte, error) {
	var out, block []byte
	currentIV := slices.Clone(iv)

	for rest := data; len(rest) > 0; {
		if len(rest) > blockSize {
			block, rest = rest[:blockSize], rest[blockSize:]
		} else {
			block, rest = rest, nil
		}

		r, err := tpm2.EncryptDecrypt2{
			KeyHandle: ToAuthHandle(keyHandle, auth),
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    mode,
			Decrypt: decrypt,
			IV: tpm2.TPM2BIV{
				Buffer: currentIV,
			},
		}.Execute(t)
		if err != nil {
			return nil, fmt.Errorf("EncryptDecrypt2 failed (processed=%d bytes): %w", len(out), err)
		}

		block = r.OutData.Buffer
		currentIV = r.IV.Buffer
		out = append(out, block...)
	}
	return out, nil
}

// toTPM2BSensitiveCreate converts userAuth and data into a TPM2BSensitiveCreate structure.
func toTPM2BSensitiveCreate(userAuth, data []byte) tpm2.TPM2BSensitiveCreate {
	sensitive := tpm2.TPM2BSensitiveCreate{
		Sensitive: &tpm2.TPMSSensitiveCreate{},
	}
	if len(userAuth) > 0 {
		sensitive.Sensitive.UserAuth = tpm2.TPM2BAuth{
			Buffer: userAuth,
		}
	}
	if len(data) > 0 {
		sensitive.Sensitive.Data = tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
			Buffer: data,
		})
	}
	return sensitive
}
