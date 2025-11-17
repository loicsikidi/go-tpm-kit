# tpmcrypto

Package `tpmcrypto` provides cryptographic utilities and helper functions for working with TPM 2.0 public keys, signatures, and cryptographic operations.

## Features

### Public Key Extraction and Conversion

Extract and convert TPM public key structures to standard Go `crypto` types:

- **`PublicKey()`**: Extracts `crypto.PublicKey` from `tpm2.TPM2BPublic` or `tpm2.TPMTPublic`
- **`PublicKeyRSA()`**: Extracts `*rsa.PublicKey` with type checking
- **`PublicKeyECDSA()`**: Extracts `*ecdsa.PublicKey` with type checking

**Example:**
```go
// Extract public key from TPM structure
pub := tpm2.TPMTPublic{Type: tpm2.TPMAlgRSA, ...}
key, err := tpmcrypto.PublicKey(pub)
if err != nil {
    log.Fatal(err)
}

// Type-specific extraction
rsaKey, err := tpmcrypto.PublicKeyRSA(pub)
```

### Public Key Validation

`ValidatePublicKey()` enforces security requirements for TPM public keys:

- **RSA keys**: Minimum 2048 bits
- **ECC keys**: Minimum 256 bits and secure curve validation (NIST P-256/P-384/P-521, Brainpool P-256/P-638)

**Example:**
```go
pub := tpm2.TPMTPublic{Type: tpm2.TPMAlgRSA, Parameters: ...}
if err := tpmcrypto.ValidatePublicKey(pub); err != nil {
    log.Fatalf("Invalid public key: %v", err)
}
```

### Signature Verification

Verify TPM signatures using both TPM structures and standard Go crypto types:

- **`VerifySignatureFromPublic()`**: Verifies using `tpm2.TPMTPublic` (includes validation)
- **`VerifySignature()`**: Verifies using `crypto.PublicKey`

Supports:
- **RSA**: RSASSA-PKCS1v15 signatures
- **ECDSA**: Standard ECDSA signatures

**Example:**
```go
// Verify using TPM public structure
err := tpmcrypto.VerifySignatureFromPublic(pub, signature, data)
if err != nil {
    log.Fatalf("Signature verification failed: %v", err)
}

// Verify using crypto.PublicKey
err = tpmcrypto.VerifySignature(publicKey, sig, crypto.SHA256, data)
```

### Signature Scheme Management

Utilities for working with TPM signature schemes:

- **`GetSigSchemeFromPublic()`**: Extracts signature scheme from `tpm2.TPMTPublic`
- **`GetSigSchemeFromPublicKey()`**: Determines signature scheme from `crypto.PublicKey` and `crypto.SignerOpts`
- **`GetSigScheme()`**: Constructs `tpm2.TPMTSigScheme` from scheme and hash algorithm
- **`GetSigHashFromPublic()`**: Extracts hash algorithm from public key structure

**Example:**
```go
// Extract signature scheme from TPM public key
scheme, err := tpmcrypto.GetSigSchemeFromPublic(pub)

// Determine scheme from Go public key and signer options
scheme, err := tpmcrypto.GetSigSchemeFromPublicKey(pubKey, crypto.SHA256)

// Create custom signature scheme
scheme := tpmcrypto.GetSigScheme(tpm2.TPMAlgRSASSA, tpm2.TPMAlgSHA256)
```

### Key Parameter Builders

Create TPM key parameter structures for signing keys:

- **`NewRSASigKeyParameters()`**: Creates RSA signing key parameters
  - Supports 2048, 3072, 4096-bit keys
  - Automatic hash algorithm selection based on key size
  - Support for agnostic keys (`TPMAlgNull` scheme)

- **`NewECCSigKeyParameters()`**: Creates ECC signing key parameters
  - Supports NIST P-256, P-384, P-521 curves
  - Automatic hash algorithm selection based on curve

**Example:**
```go
// Create RSA-2048 key parameters with RSASSA scheme
params, err := tpmcrypto.NewRSASigKeyParameters(2048, tpm2.TPMAlgRSASSA)
if err != nil {
    log.Fatal(err)
}

// Create ECC P-256 key parameters
params, err := tpmcrypto.NewECCSigKeyParameters(tpm2.TPMECCNistP256)

// Create agnostic RSA key (can use any signature scheme)
params, err := tpmcrypto.NewRSASigKeyParameters(2048, tpm2.TPMAlgNull)
```

### Hash Algorithm Conversion

- **`HashToAlgorithm()`**: Converts `crypto.Hash` to `tpm2.TPMAlgID`
- **`GetDigest()`**: Computes digest using `crypto.Hash`

**Example:**
```go
// Convert crypto.Hash to TPM algorithm ID
algID, err := tpmcrypto.HashToAlgorithm(crypto.SHA256)

// Compute digest
digest, err := tpmcrypto.GetDigest(data, crypto.SHA256)
```

### ECC Key Unique Identifier

`NewECCKeyUnique()` creates unique identifiers for ECC keys based on curve parameters.

**Example:**
```go
unique, err := tpmcrypto.NewECCKeyUnique(tpm2.TPMECCNistP256)
```

## Supported Algorithms

### RSA Signatures
- RSASSA-PKCS1v15 (verification and parameter creation)
- RSAPSS (parameter creation, verification TODO)

### ECDSA Signatures
- Standard ECDSA with NIST curves (P-256, P-384, P-521)
- Brainpool curves (P-256, P-638)

### Hash Algorithms
- SHA-256, SHA-384, SHA-512
- Automatic selection based on key size/curve

## Security Considerations

- All public keys are validated for minimum secure sizes
- Only secure elliptic curves are accepted
- RSA keys must be at least 2048 bits
- ECC keys must be at least 256 bits

## License

See [LICENSE](../LICENSE) file in the repository root.
