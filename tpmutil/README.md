# tpmutil

Package `tpmutil` provides high-level utilities and abstractions for working with TPM 2.0 devices using the [go-tpm](https://github.com/google/go-tpm) library.

## Features

### Smart Handle Management

The package introduces an intelligent `Handle` abstraction that extends TPM handle functionality:

- **Type Identification**: Automatically determine handle types (transient, persistent, NV index, etc.) via `Type()`
- **Resource Cleanup**: `HandleCloser` interface provides automatic resource management through `Close()` which flushes TPM handles
- **Unified Interface**: Work seamlessly with both `tpm2.AuthHandle` and `tpm2.NamedHandle` through a common interface

This creates a clean contract for TPM commands that return handles, enabling proper resource lifecycle management.

**Example:**
```go
// Create a closable handle for automatic cleanup
keyHandle := tpmutil.NewHandleCloser(tpm, &tpm2.NamedHandle{
    Handle: createRsp.ObjectHandle,
    Name:   createRsp.Name,
})
defer keyHandle.Close() // Automatically flushes the handle

// Check handle type
if keyHandle.Type() == tpmutil.TransientHandle {
    fmt.Println("This is a transient key")
}
```

### Helper Functions

#### Sign

`Sign()` automatically formats signature output based on key type and signature algorithm:

- **ECC keys**: Returns DER-encoded ECDSA signatures (ASN.1 format with R and S components)
- **RSA keys**: Returns raw signature bytes, supporting both RSASSA and RSAPSS schemes

**Example:**
```go
signature, err := tpmutil.Sign(tpm, &tpmutil.SignConfig{
    KeyHandle:  keyHandle,
    Digest:     digest,
    PublicKey:  publicKey,
    SignerOpts: crypto.SHA256,
    Validation: tpmutil.NullTicket,
})
// signature is ready to use, formatted correctly for the key type
```

#### NVRead/NVWrite/Hash: Batch Buffer Management

These functions handle TPM buffer size limitations automatically by splitting large data into chunks:

- **`NVRead()`**: Reads NV index data in configurable blocks, automatically handling offset management
- **`NVWrite()`**: Writes data to NV indices in batches (max 2048 bytes), with automatic space allocation
- **`Hash()`**: Computes hash digests using TPM's sequence commands for data larger than buffer size

**Example:**
```go
// Write large data to NV index - automatically batched
data := make([]byte, 1024)
err := tpmutil.NVWrite(tpm, &tpmutil.NVWriteConfig{
    Index:     0x01500000,
    Data:      data,
    Hierarchy: tpm2.TPMRHOwner,
})

// Read it back - automatically handles chunking
readData, err := tpmutil.NVRead(tpm, &tpmutil.NVReadConfig{
    Index:     0x01500000,
    Hierarchy: tpm2.TPMRHOwner,
})
```

#### GetSKRHandle: Intelligent Storage Root Key Management

`GetSKRHandle()` provides smart SRK (Storage Root Key) lifecycle management:

1. **Search**: First attempts to read from the persistent handle location
2. **Create & Persist**: If not found, creates a new SRK and stores it at the specified persistent handle
3. **Return**: Returns a `Handle` ready for use as a parent key

Supports both ECC and RSA storage root keys.

**Example:**
```go
// Get or create an ECC SRK at the default persistent handle
srkHandle, err := tpmutil.GetSKRHandle(tpm, &tpmutil.ParentConfig{
    KeyType:   tpmutil.ECC,
    Hierarchy: tpm2.TPMRHOwner,
})
// srkHandle is ready to use as a parent for key creation
// The SRK persists across TPM resets
```

#### PCR Format Conversion

Convert between external PCR representations (slices of PCR numbers) and internal TPM formats:

- **`ToTPMLPCRSelection()`**: Converts PCR numbers to `tpm2.TPMLPCRSelection` for use in TPM commands
- **`PCRSelectToPCRs()`**: Converts PCR selection bitmaps back to PCR numbers

**Example:**
```go
// Convert PCR numbers to TPM format
selection := tpmutil.ToTPMLPCRSelection([]uint{0, 1, 7}, tpm2.TPMAlgSHA256)
// Use in PolicyPCR, Quote, etc.

// Convert bitmap back to numbers
pcrs := tpmutil.PCRSelectToPCRs([]byte{0x83, 0x00, 0x00}) // Returns []uint{0, 1, 7}
```

## Configuration Pattern

All main functions accept configuration structs that implement the `CheckAndSetDefault()` pattern for validation and default value handling:

```go
cfg := &tpmutil.HashConfig{
    Data:    data,
    HashAlg: crypto.SHA256,
}
// CheckAndSetDefault() called internally - sets defaults and validates
result, err := tpmutil.Hash(tpm, cfg)
```
