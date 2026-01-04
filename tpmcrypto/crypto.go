package tpmcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"slices"

	tpmkit "github.com/loicsikidi/go-tpm-kit"

	"github.com/google/go-tpm/tpm2"
)

const (
	// minRSABits is the minimum accepted bit size of an RSA key.
	minRSABits = 2048
	// minECCBits is the minimum accepted bit size of an ECC key.
	minECCBits = 256
)

var (
	ErrInvalidSignature  = errors.New("invalid signature")
	ErrSignatureTooShort = errors.New("signature invalid: length is shorter than 8 bytes")
)

// secureCurves represents a set of secure elliptic curves. For now,
// the selection is based on the key size only.
var secureCurves = map[tpm2.TPMECCCurve]bool{
	tpm2.TPMECCNistP256: true,
	tpm2.TPMECCNistP384: true,
	tpm2.TPMECCNistP521: true,
	tpm2.TPMECCBNP256:   true,
	tpm2.TPMECCBNP638:   true,
}

// PublicKey extracts the public key from a [tpm2.TPM2BPublic] or [tpm2.TPMTPublic] structures.
//
// Example:
//
//	pub := tpm2.TPMTPublic{Type: tpm2.TPMAlgRSA, ...}
//	key, err := tpmcrypto.PublicKey(pub)
//
// Note: pointers to these structures are also accepted.
func PublicKey(public any) (crypto.PublicKey, error) {
	var (
		pub         *tpm2.TPMTPublic
		errContents error
	)
	switch p := public.(type) {
	case *tpm2.TPM2BPublic:
		pub, errContents = p.Contents()
		if errContents != nil {
			return nil, fmt.Errorf("failed to get TPM2BPublic contents: %w", errContents)
		}
	case tpm2.TPM2BPublic:
		pub, errContents = p.Contents()
		if errContents != nil {
			return nil, fmt.Errorf("failed to get TPM2BPublic contents: %w", errContents)
		}
	case *tpm2.TPMTPublic:
		pub = p
	case tpm2.TPMTPublic:
		pub = &p
	default:
		return nil, fmt.Errorf("unsupported type: %T", public)
	}

	return tpm2.Pub(*pub)
}

// PublicKeyRSA extracts the RSA public key from a [tpm2.TPM2BPublic] or [tpm2.TPMTPublic] structure.
//
// Example:
//
//	pub := tpm2.TPMTPublic{Type: tpm2.TPMAlgRSA, ...}
//	rsaKey, err := tpmcrypto.PublicKeyRSA(pub)
func PublicKeyRSA(public any) (*rsa.PublicKey, error) {
	pub, err := PublicKey(public)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA public key, got %T", pub)
	}
	return rsaPub, nil
}

// PublicKeyECDSA extracts the ECDSA public key from a [tpm2.TPM2BPublic] or [tpm2.TPMTPublic] structure.
//
// Example:
//
//	pub := tpm2.TPMTPublic{Type: tpm2.TPMAlgECC, ...}
//	eccKey, err := tpmcrypto.PublicKeyECDSA(pub)
func PublicKeyECDSA(public any) (*ecdsa.PublicKey, error) {
	pub, err := PublicKey(public)
	if err != nil {
		return nil, err
	}

	eccPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected ECC public key, got %T", pub)
	}
	return eccPub, nil
}

// ValidatePublicKey checks if the provided TPMTPublic structure respects
// some basic security requirements for public keys used in attestation.
//
// Example:
//
//	pub := tpm2.TPMTPublic{Type: tpm2.TPMAlgRSA, Parameters: ...}
//	if err := tpmcrypto.ValidatePublicKey(pub); err != nil { /* handle */ }
func ValidatePublicKey(pub tpm2.TPMTPublic) error {
	switch pub.Type {
	case tpm2.TPMAlgRSA:
		rsaParams, err := pub.Parameters.RSADetail()
		if err != nil {
			return fmt.Errorf("failed to get RSA details: %w", err)
		}

		if rsaParams.KeyBits < minRSABits {
			return fmt.Errorf("public key too small: must be at least %d bits but was %d bits", minRSABits, rsaParams.KeyBits)
		}
	case tpm2.TPMAlgECC:
		eccParams, err := pub.Parameters.ECCDetail()
		if err != nil {
			return fmt.Errorf("failed to get ECC details: %w", err)
		}

		if !secureCurves[eccParams.CurveID] {
			return fmt.Errorf("public key uses insecure curve")
		}
		eccPoint, err := pub.Unique.ECC()
		if err != nil {
			return fmt.Errorf("failed to get ECC point: %w", err)
		}
		if len(eccPoint.X.Buffer)*8 < minECCBits {
			return fmt.Errorf("attestation key too small: must be at least %d bits but was %d bits", minECCBits, len(eccPoint.X.Buffer)*8)
		}
		if len(eccPoint.Y.Buffer)*8 < minECCBits {
			return fmt.Errorf("attestation key too small: must be at least %d bits but was %d bits", minECCBits, len(eccPoint.Y.Buffer)*8)
		}
	default:
		return fmt.Errorf("public key of alg %#x not supported", pub.Type)
	}

	return nil
}

// VerifySignatureFromPublic verifies the signature produced by a TPM using the TPMTPublic.
//
// Example:
//
//	err := tpmcrypto.VerifySignatureFromPublic(pub, signature, data)
func VerifySignatureFromPublic(pub tpm2.TPMTPublic, sig tpm2.TPMTSignature, data []byte) error {
	if err := ValidatePublicKey(pub); err != nil {
		return err
	}

	if len(tpm2.Marshal(sig)) < 8 {
		return ErrSignatureTooShort
	}

	signHash, err := GetSigHashFromPublic(pub)
	if err != nil {
		return err
	}

	pubKey, err := PublicKey(pub)
	if err != nil {
		return err
	}

	return VerifySignature(pubKey, sig, signHash, data)
}

// VerifySignature checks the signature procuded by a TPM using the provided public key.
//
// Example:
//
//	err := tpmcrypto.VerifySignature(publicKey, sig, crypto.SHA256, data)
func VerifySignature(pub crypto.PublicKey, sig tpm2.TPMTSignature, signHash crypto.Hash, data []byte) error {
	digest, err := GetDigest(data, signHash)
	if err != nil {
		return err
	}

	switch p := pub.(type) {
	case *rsa.PublicKey:
		return verifyRSA(p, sig, signHash, digest)
	case *ecdsa.PublicKey:
		return verifyECDSA(p, sig, digest)
	default:
		return fmt.Errorf("signature verification for alg %T is not supported", p)
	}
}

// TODO(lsikidi): Add support for RSAPSS signature.
func verifyRSA(pub *rsa.PublicKey, sig tpm2.TPMTSignature, hash crypto.Hash, digest []byte) error {
	rsaSig, err := sig.Signature.RSASSA()
	if err != nil {
		return fmt.Errorf("failed to get RSASSA signature: %w", err)
	}

	if err := rsa.VerifyPKCS1v15(pub, hash, digest, rsaSig.Sig.Buffer); err != nil {
		return ErrInvalidSignature
	}
	return nil
}

// TODO(lsikidi): Add support for ECDAA signature 🤔?
func verifyECDSA(pub *ecdsa.PublicKey, sig tpm2.TPMTSignature, digest []byte) error {
	eccSig, err := sig.Signature.ECDSA()
	if err != nil {
		return fmt.Errorf("failed to get ECDSA signature: %w", err)
	}
	r := new(big.Int).SetBytes(eccSig.SignatureR.Buffer)
	s := new(big.Int).SetBytes(eccSig.SignatureS.Buffer)

	if !ecdsa.Verify(pub, digest, r, s) {
		return ErrInvalidSignature
	}
	return nil
}

// GetDigest computes the digest of the provided data using the specified hash function.
//
// Example:
//
//	digest, err := tpmcrypto.GetDigest(data, crypto.SHA256)
func GetDigest(data []byte, hash crypto.Hash) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("hash function %v is not available", hash)
	}
	h := hash.New()
	if _, err := h.Write(data); err != nil {
		return nil, fmt.Errorf("failed to write hash: %w", err)
	}
	return h.Sum(nil), nil
}

// GetSigSchemeFromPublic extracts the signature scheme from a [tpm2.TPMTPublic] structure.
//
// Example:
//
//	scheme, err := tpmcrypto.GetSigSchemeFromPublic(pub)
func GetSigSchemeFromPublic(public tpm2.TPMTPublic) (tpm2.TPMTSigScheme, error) {
	scheme, hash, err := GetSigSchemeAndHashFromPublic(public)
	if err != nil {
		return tpm2.TPMTSigScheme{}, err
	}
	return GetSigScheme(scheme, hash), nil
}

// GetSigSchemeFromPublicKey extracts the signature scheme from a [crypto.PublicKey]
// and [crypto.SignerOpts]. It returns a [tpm2.TPMTSigScheme] that can be used for signing operations.
//
// Example:
//
//	scheme, err := tpmcrypto.GetSigSchemeFromPublicKey(pubKey, crypto.SHA256)
//
// Note: [crypto.SignerOpts] is used to determine the hash function and signature scheme.
// This is useful for agnostic key (scheme = TPMAlgNull) which is not limited to
// a specific signature scheme.
func GetSigSchemeFromPublicKey(pub crypto.PublicKey, opts crypto.SignerOpts) (tpm2.TPMTSigScheme, error) {
	alg, err := HashToAlgorithm(opts.HashFunc())
	if err != nil {
		return tpm2.TPMTSigScheme{}, err
	}

	switch pub.(type) {
	case *ecdsa.PublicKey:
		return GetSigScheme(tpm2.TPMAlgECDSA, alg), nil
	case *rsa.PublicKey:
		return getSigSchemeFromRSA(alg, opts), nil
	default:
		return tpm2.TPMTSigScheme{}, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// GetSigScheme creates a [tpm2.TPMTSigScheme] structure based on the provided
// signature scheme and hash algorithm.
//
// Example:
//
//	scheme := tpmcrypto.GetSigScheme(tpm2.TPMAlgRSASSA, tpm2.TPMAlgSHA256)
func GetSigScheme(scheme, hash tpm2.TPMAlgID) tpm2.TPMTSigScheme {
	return tpm2.TPMTSigScheme{
		Scheme: scheme,
		Details: tpm2.NewTPMUSigScheme(
			scheme,
			&tpm2.TPMSSchemeHash{
				HashAlg: hash,
			},
		),
	}
}

// GetSigHashFromPublic extracts the hash algorithm used for signing from a [tpm2.TPMTPublic] structure.
//
// Example:
//
//	hash, err := tpmcrypto.GetSigHashFromPublic(pub)
func GetSigHashFromPublic(public tpm2.TPMTPublic) (crypto.Hash, error) {
	_, hash, err := GetSigSchemeAndHashFromPublic(public)
	if err != nil {
		return 0, err
	}
	return hash.Hash()
}

// GetSigSchemeAndHashFromPublic extracts the signature scheme and hash algorithm represented as [tpm2.TPMAlgID]
//
// Example:
//
//	scheme, hash, err := tpmcrypto.GetSigSchemeAndHashFromPublic(pub)
func GetSigSchemeAndHashFromPublic(public tpm2.TPMTPublic) (scheme, hash tpm2.TPMAlgID, err error) {
	switch public.Type {
	case tpm2.TPMAlgRSA:
		rsaDetail, err := public.Parameters.RSADetail()
		if err != nil {
			return scheme, hash, fmt.Errorf("failed to get RSA details: %w", err)
		}

		scheme = rsaDetail.Scheme.Scheme
		switch scheme {
		case tpm2.TPMAlgRSASSA:
			sigScheme, err := rsaDetail.Scheme.Details.RSASSA()
			if err != nil {
				return scheme, hash, fmt.Errorf("failed to get RSASSA scheme: %w", err)
			}
			hash = sigScheme.HashAlg
		case tpm2.TPMAlgRSAPSS:
			sigScheme, err := rsaDetail.Scheme.Details.RSAPSS()
			if err != nil {
				return scheme, hash, fmt.Errorf("failed to get RSAPSS scheme: %w", err)
			}
			hash = sigScheme.HashAlg
		}
	case tpm2.TPMAlgECC:
		eccDetail, err := public.Parameters.ECCDetail()
		if err != nil {
			return scheme, hash, fmt.Errorf("failed to get ECC details: %w", err)
		}

		scheme = eccDetail.Scheme.Scheme
		switch scheme {
		case tpm2.TPMAlgECDSA:
			sigScheme, err := eccDetail.Scheme.Details.ECDSA()
			if err != nil {
				return scheme, hash, fmt.Errorf("failed to get ECDSA scheme: %w", err)
			}
			hash = sigScheme.HashAlg
		case tpm2.TPMAlgECDAA:
			sigScheme, err := eccDetail.Scheme.Details.ECDAA()
			if err != nil {
				return scheme, hash, fmt.Errorf("failed to get ECDAA scheme: %w", err)
			}
			hash = sigScheme.HashAlg
		}
	default:
		return scheme, hash, fmt.Errorf("unsupported key type: %T", public.Type)
	}
	return scheme, hash, nil
}

func getSigSchemeFromRSA(alg tpm2.TPMAlgID, opts crypto.SignerOpts) tpm2.TPMTSigScheme {
	var scheme tpm2.TPMAlgID
	if _, ok := opts.(*rsa.PSSOptions); ok {
		scheme = tpm2.TPMAlgRSAPSS
	} else {
		scheme = tpm2.TPMAlgRSASSA
	}

	return GetSigScheme(scheme, alg)
}

// HashToAlgorithm looks up the [tpm2.TPMAlgID] corresponding to the provided [crypto.Hash]
//
// Example:
//
//	alg, err := tpmcrypto.HashToAlgorithm(crypto.SHA256)
func HashToAlgorithm(hash crypto.Hash) (tpm2.TPMAlgID, error) {
	for _, info := range tpmkit.HashInfo {
		if info.Hash == hash {
			return info.Alg, nil
		}
	}
	return tpm2.TPMAlgID(0), fmt.Errorf("go hash algorithm #%d has no TPM2 algorithm", hash)
}

// NewRSASigKeyParameters creates a new RSA key parameters structure
// dedicated for signing operations based on the specified size and scheme.
//
// The size must be one of the supported RSA key sizes (2048, 3072, or 4096 bits).
// The scheme must be a valid TPM algorithm ID for RSA signatures
// (e.g., TPMAlgRSASSA, TPMAlgRSAPSS, or TPMAlgNull).
//
// Example:
//
//	params, err := tpmcrypto.NewRSASigKeyParameters(2048, tpm2.TPMAlgRSASSA)
func NewRSASigKeyParameters(size int, scheme tpm2.TPMAlgID) (*tpm2.TPMUPublicParms, error) {
	keySize := tpm2.TPMKeyBits(size)
	var (
		params  tpm2.TPMUPublicParms
		hashAlg tpm2.TPMAlgID
	)
	switch keySize {
	case 2048:
		hashAlg = tpm2.TPMAlgSHA256
	case 3072:
		hashAlg = tpm2.TPMAlgSHA384
	case 4096:
		hashAlg = tpm2.TPMAlgSHA512
	default:
		return nil, fmt.Errorf("unsupported RSA key size: %d", size)
	}

	// foreword: we do this check here because we want to validate key size first.
	// concept: a key with scheme = TPM_ALG_NULL is a key which is not limited to
	// a specific signature/decryption scheme.
	if scheme == tpm2.TPMAlgNull {
		params = tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				KeyBits: keySize,
			},
		)
		return &params, nil
	}

	details, err := newSigKeyParamDetails(scheme, hashAlg)
	if err != nil {
		return nil, err
	}

	params = tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgRSA,
		&tpm2.TPMSRSAParms{
			Scheme: tpm2.TPMTRSAScheme{
				Scheme:  scheme,
				Details: details,
			},
			KeyBits: tpm2.TPMKeyBits(size),
		},
	)
	return &params, nil
}

// NewECCSigKeyParameters creates a new ECC key parameters structure
// dedicated for signing operations based on a specified curve.
//
// The curve must be one of the supported TPM ECC curves (e.g., NIST P-256, P-384, or P-521).
//
// Example:
//
//	params, err := tpmcrypto.NewECCSigKeyParameters(tpm2.TPMECCNistP256)
func NewECCSigKeyParameters(curve tpm2.TPMECCCurve) (*tpm2.TPMUPublicParms, error) {
	var hashAlg tpm2.TPMAlgID

	switch curve {
	case tpm2.TPMECCNistP256:
		hashAlg = tpm2.TPMAlgSHA256
	case tpm2.TPMECCNistP384:
		hashAlg = tpm2.TPMAlgSHA384
	case tpm2.TPMECCNistP521:
		hashAlg = tpm2.TPMAlgSHA512
	default:
		return nil, fmt.Errorf("unsupported curve id: %#x", curve)
	}

	details, err := newSigKeyParamDetails(tpm2.TPMAlgECDSA, hashAlg)
	if err != nil {
		return nil, err
	}

	params := tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgECC,
		&tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme:  tpm2.TPMAlgECDSA,
				Details: details,
			},
			CurveID: curve,
		},
	)
	return &params, nil
}

// NewHMACParameters creates a new HMAC key parameters structure
// based on the specified hash algorithm.
//
// The hash algorithm must be one of the supported TPM hash algorithms
// (e.g., TPMAlgSHA256, TPMAlgSHA384, or TPMAlgSHA512).
//
// Example:
//
//	params, err := tpmcrypto.NewHMACParameters(tpm2.TPMAlgSHA256)
func NewHMACParameters(hashAlg tpm2.TPMAlgID) (*tpm2.TPMUPublicParms, error) {
	if !slices.Contains([]tpm2.TPMAlgID{tpm2.TPMAlgSHA256, tpm2.TPMAlgSHA384, tpm2.TPMAlgSHA512}, hashAlg) {
		return nil, fmt.Errorf("unsupported hash algorithm for HMAC: %#x", hashAlg)
	}
	params := tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgKeyedHash,
		&tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme: tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(
					tpm2.TPMAlgHMAC,
					&tpm2.TPMSSchemeHMAC{
						HashAlg: hashAlg,
					},
				),
			},
		},
	)
	return &params, nil
}

// NewECCKeyUnique creates a new unique identifier for an ECC key based on the specified curve.
//
// Example:
//
//	unique, err := tpmcrypto.NewECCKeyUnique(tpm2.TPMECCNistP256)
func NewECCKeyUnique(curveID tpm2.TPMECCCurve) (*tpm2.TPMUPublicID, error) {
	var eccPointSize int
	switch curveID {
	case tpm2.TPMECCNistP256:
		eccPointSize = 32
	case tpm2.TPMECCNistP384:
		eccPointSize = 48
	case tpm2.TPMECCNistP521:
		eccPointSize = 65
	default:
		return nil, fmt.Errorf("unsupported ECC curve: %#x", curveID)
	}

	unique := tpm2.NewTPMUPublicID(
		tpm2.TPMAlgECC,
		&tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{
				Buffer: make([]byte, eccPointSize),
			},
			Y: tpm2.TPM2BECCParameter{
				Buffer: make([]byte, eccPointSize),
			},
		},
	)
	return &unique, nil
}

func newSigKeyParamDetails(scheme tpm2.TPMAlgID, hashAlg tpm2.TPMAlgID) (tpm2.TPMUAsymScheme, error) {
	switch scheme {
	case tpm2.TPMAlgRSASSA:
		return tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgRSASSA,
			&tpm2.TPMSSigSchemeRSASSA{
				HashAlg: hashAlg,
			},
		), nil
	case tpm2.TPMAlgRSAPSS:
		return tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgRSAPSS,
			&tpm2.TPMSSigSchemeRSAPSS{
				HashAlg: hashAlg,
			},
		), nil
	case tpm2.TPMAlgECDSA:
		return tpm2.NewTPMUAsymScheme(
			tpm2.TPMAlgECDSA,
			&tpm2.TPMSSigSchemeECDSA{
				HashAlg: hashAlg,
			},
		), nil
	default:
		return tpm2.TPMUAsymScheme{}, fmt.Errorf("unsupported signature scheme: %#x", scheme)
	}
}
