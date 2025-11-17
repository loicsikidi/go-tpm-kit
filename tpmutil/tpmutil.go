package tpmutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpmkit "github.com/loicsikidi/go-tpm-kit"
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

const maxBufferSize = tpmkit.MaxBufferSize

// NVRead reads data from a non-volatile storage (NV) index.
//
// Example:
//
//	// Read from NV index 0x01500000
//	data, err := tpmutil.NVRead(tpm, &tpmutil.NVReadConfig{
//		Index:     0x01500000,
//		Hierarchy: tpm2.TPMRHOwner,
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Read %d bytes from NV index\n", len(data))
//
// Note: If cfg is nil, default configuration is used.
func NVRead(t transport.TPM, cfg *NVReadConfig) ([]byte, error) {
	if cfg == nil {
		cfg = &NVReadConfig{}
	}
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}
	return nvRead(t, cfg.Hierarchy, cfg.Index, cfg.Auth, cfg.BlockSize)
}

func nvRead(t transport.TPM, hierarchy, index tpm2.TPMHandle, auth tpm2.Session, blockSize int) ([]byte, error) {
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
			AuthHandle: tpm2.AuthHandle{
				Handle: hierarchy,
				Auth:   auth,
			},
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
// Example:
//
//	// Write data to NV index 0x01500000
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
// Note: If cfg is nil, default configuration is used.
func NVWrite(t transport.TPM, cfg *NVWriteConfig) error {
	if cfg == nil {
		cfg = &NVWriteConfig{}
	}
	if err := cfg.CheckAndSetDefault(); err != nil {
		return err
	}
	return nvWrite(t, cfg.Hierarchy, cfg.Index, cfg.Auth, cfg.Data, cfg.Attributes)
}

func nvWrite(t transport.TPM, hierarchy, index tpm2.TPMHandle, auth tpm2.Session, data []byte, attributes tpm2.TPMANV) error {
	const maxNVSize = 2048
	if len(data) > maxNVSize {
		return ErrDataTooLarge
	}

	if auth == nil {
		auth = NoAuth
	}

	defs := tpm2.NVDefineSpace{
		AuthHandle: tpm2.AuthHandle{
			Handle: hierarchy,
			Auth:   auth,
		},
		PublicInfo: tpm2.New2B(
			tpm2.TPMSNVPublic{
				NVIndex:    index,
				NameAlg:    tpm2.TPMAlgSHA256,
				Attributes: attributes,
				DataSize:   uint16(len(data)),
			}),
	}
	if _, err := defs.Execute(t); err != nil {
		return err
	}

	pub, err := defs.PublicInfo.Contents()
	if err != nil {
		return err
	}

	nvName, err := tpm2.NVName(pub)
	if err != nil {
		return err
	}

	var offset uint16
	for offset < uint16(len(data)) {
		end := min(int(offset+maxBufferSize), len(data))

		write := tpm2.NVWrite{
			AuthHandle: tpm2.AuthHandle{
				Handle: hierarchy,
				Auth:   auth,
			},
			NVIndex: tpm2.NamedHandle{
				Handle: pub.NVIndex,
				Name:   *nvName,
			},
			Data: tpm2.TPM2BMaxNVBuffer{
				Buffer: data[int(offset):end],
			},
			Offset: offset,
		}
		if _, err := write.Execute(t); err != nil {
			return fmt.Errorf("running NV_Write command (offset=%d,size=%d): %w", offset, len(data), err)
		}
		offset += maxBufferSize
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
func Hash(t transport.TPM, cfg *HashConfig) (*HashResult, error) {
	if cfg == nil {
		cfg = &HashConfig{}
	}
	if err := cfg.CheckAndSetDefault(); err != nil {
		return nil, err
	}
	digest, validation, err := hash(t, cfg.Hierarchy, cfg.Password, cfg.BlockSize, cfg.Data, cfg.HashAlg)
	if err != nil {
		return nil, err
	}
	return &HashResult{
		Digest:     digest,
		Validation: validation,
	}, nil
}

func hash(t transport.TPM, hierarchy tpm2.TPMHandle, password string, blockSize int, data []byte, h crypto.Hash) ([]byte, tpm2.TPMTTKHashCheck, error) {
	nilTicket := tpm2.TPMTTKHashCheck{}

	auth := []byte(password)
	alg, err := tpmcrypto.HashToAlgorithm(h)
	if err != nil {
		return nil, nilTicket, err
	}

	hashSequenceStart := tpm2.HashSequenceStart{
		Auth: tpm2.TPM2BAuth{
			Buffer: auth,
		},
		HashAlg: alg,
	}

	rspHSS, err := hashSequenceStart.Execute(t)
	if err != nil {
		return nil, nilTicket, fmt.Errorf("HashSequenceStart failed: %w", err)
	}

	authHandle := tpm2.AuthHandle{
		Handle: rspHSS.SequenceHandle,
		Name: tpm2.TPM2BName{
			Buffer: auth,
		},
		Auth: tpm2.PasswordAuth(auth),
	}

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
func Sign(t transport.TPM, cfg *SignConfig) ([]byte, error) {
	if cfg == nil {
		cfg = &SignConfig{}
	}
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
func GetSKRHandle(t transport.TPM, cfg *ParentConfig) (Handle, error) {
	if cfg == nil {
		cfg = &ParentConfig{}
	}
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
	switch cfg.KeyType {
	case RSA:
		srkTemplate = defaultRSASRKTemplate
	case ECC:
		srkTemplate = defaultECCSRKTemplate
	default:
		return nil, fmt.Errorf("unsupported SRK KeyType: %v", cfg.KeyType)
	}

	srkCreateCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: cfg.Hierarchy,
			Auth:   cfg.Auth, // owner auth
		},
		InPublic: tpm2.New2B(srkTemplate),
	}
	srkHandle, err := CreatePrimary(t, srkCreateCmd)
	if err != nil {
		return nil, fmt.Errorf("ReadPublic failed (%v), and then CreatePrimary failed: %v", rerr, err)
	}
	defer srkHandle.Close() //nolint:errcheck

	// Make the SRK persistent at the desired handle.
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: cfg.Hierarchy,
			Auth:   cfg.Auth,
		},
		ObjectHandle:     srkHandle,
		PersistentHandle: cfg.Handle.Handle(),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("ReadPublic failed (%v), and then EvictControl failed: %v", rerr, err)
	}

	// Return a handle representing the persistent SRK.
	final := NewHandle(&tpm2.NamedHandle{
		Handle: cfg.Handle.Handle(),
		Name:   srkHandle.Name(),
	})

	return final, nil

}
