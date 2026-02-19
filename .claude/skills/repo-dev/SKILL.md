---
name: repo-dev
desc: Guidelines and best practices for developing the `go-tpm-kit` repository
allowed-tools: Read, Grep, Glob, Write, AskUserQuestion
---

# go-tpm-kit Coding Conventions

This document formalizes the coding conventions used across the `go-tpm-kit` project. Its purpose is to enable any contributor (human or agent) to produce code that is consistent with the rest of the codebase.

**Module**: `github.com/loicsikidi/go-tpm-kit`
**Go version**: 1.23.0
**Primary dependency**: `github.com/google/go-tpm` (v0.9.8+)

---

## Table of Contents

1. [Common Conventions (All Packages)](#1-common-conventions-all-packages)
2. [Package: tpmutil](#2-package-tpmutil)
3. [Package: tpmcrypto](#3-package-tpmcrypto)
4. [Package: tpmsession](#4-package-tpmsession)
5. [Package: tpmtest](#5-package-tpmtest)
6. [Root Package (tpmkit)](#6-root-package-tpmkit)
7. [Internal Utilities](#7-internal-utilities)

---

## 1. Common Conventions (All Packages)

### 1.1 License Header

Every `.go` source file **must** begin with a license header before the `package` declaration. The header uses the BSD 3-Clause license matching the project's [LICENSE](../../LICENSE) file.

**Template:**

```go
// Copyright (c) <YEAR>, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
```

Where `<YEAR>` is the year the file was created. For files created across multiple years, use a range (e.g., `2025-2026`).

The header must be separated from the `package` declaration by a blank line:

```go
// Copyright (c) <YEAR>, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil
```

### 1.2 File Organization

| Purpose | Naming Convention | Examples |
|---------|-------------------|----------|
| Main implementation | `<feature>.go` | `tpmutil.go`, `session.go`, `crypto.go` |
| Configuration structs | `config.go` | `tpmutil/config.go` |
| Error definitions | `errors.go` | `tpmutil/errors.go` |
| Constants & templates | `constants.go` | `tpmutil/constants.go` |
| Handle/type abstractions | `<concept>.go` | `handle.go`, `key.go`, `result.go`, `pcr.go` |
| Tests | `<feature>_test.go` | `config_test.go`, `crypto_test.go` |
| Simulator-based tests | `<feature>_simulated_test.go` | `session_simulated_test.go` |
| Real TPM tests | `<feature>_real_tpm_test.go` | `session_real_tpm_test.go` |
| Per-function tests (tpmutil) | `tpmutil_<function>_test.go` | `tpmutil_createprimary_test.go` |

There are no `doc.go` files. Package documentation is placed at the top of the main source file.

### 1.3 Package Documentation

Package-level documentation is a multi-line comment block at the top of the main file:

```go
// Package tpmsession provides utilities for creating and managing encrypted TPM sessions.
//
// It supports two types of sessions:
//   - Bound sessions: sessions bound to a specific TPM object using an authorization value
//   - Salted sessions: sessions using encrypted salt for cryptographic binding to a TPM key
//
// Both session types provide parameter encryption and HMAC protection for TPM commands.
package tpmsession
```

### 1.4 Import Organization

Imports are organized in three groups separated by blank lines:

1. Standard library
2. External packages (`github.com/...`)
3. Internal project packages

```go
import (
    "crypto"
    "fmt"
    "io"

    "github.com/google/go-tpm/tpm2"
    "github.com/google/go-tpm/tpm2/transport"
    tpmkit "github.com/loicsikidi/go-tpm-kit"
    "github.com/loicsikidi/go-tpm-kit/internal/utils"
    "github.com/loicsikidi/go-tpm-kit/tpmcrypto"
)
```

The root module is imported with the alias `tpmkit`.

### 1.5 The `CheckAndSetDefault()` Pattern

Every configuration struct implements a `CheckAndSetDefault() error` method that:

1. **Validates** required fields (returns error if missing)
2. **Sets defaults** for optional fields (mutates the receiver)
3. **Validates constraints** (e.g., size limits, type compatibility)

```go
type HashConfig struct {
    Hierarchy tpm2.TPMHandle // Default: tpm2.TPMRHOwner
    BlockSize int            // Default: maxBufferSize (1024 bytes)
    HashAlg   crypto.Hash    // Default: crypto.SHA256
    Data      []byte         // Required
}

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
```

**Ordering within `CheckAndSetDefault()`**: There is no strict ordering, but the general pattern is:
- Validate hard constraints first (negative values, invalid types)
- Set defaults for zero-valued optional fields
- Validate required fields last

### 1.6 Optional Configuration via Variadic Arguments

Public API functions accept optional config structs as variadic arguments. The helper `utils.OptionalArg()` extracts the first element or returns the zero value:

```go
func NVRead(t transport.TPM, optionalCfg ...NVReadConfig) ([]byte, error) {
    cfg := utils.OptionalArg(optionalCfg)
    if err := cfg.CheckAndSetDefault(); err != nil {
        return nil, err
    }
    return nvRead(t, cfg.Hierarchy, cfg.Index, cfg.Auth, cfg.BlockSize, cfg.MultiIndex)
}
```

This is **not** the functional options pattern. It uses concrete config structs.

### 1.7 Constructor Naming

| Pattern | Purpose | Panic? | Example |
|---------|---------|--------|---------|
| `New*()` | Creates an object, returns `(T, error)` | No | `NewSessionManager()`, `NewHandle()`, `NewApplicationKeyTemplate()` |
| `Must*()` | Creates an object, panics on error | Yes | `MustGenerateRnd()`, `MustApplicationKeyTemplate()`, `MustAKTemplate()` |
| `Get*()` | Retrieves or creates a resource from TPM | No | `GetSKRHandle()`, `GetEKHandle()` |
| `Create*()` | Issues a TPM Create command | No | `CreatePrimary()`, `Create()`, `CreateSessionKey()` |
| `*WithResult()` | Returns full TPM command result | No | `CreatePrimaryWithResult()`, `CreateWithResult()` |

### 1.8 Public vs. Private API

- **Public**: Exported functions handle config validation (`CheckAndSetDefault()`) and are the entry points for users.
- **Private**: Unexported functions implement the actual logic. They receive already-validated, concrete parameters (not config structs).

```go
// Public: validates config, delegates to private
func NVRead(t transport.TPM, optionalCfg ...NVReadConfig) ([]byte, error) { ... }

// Private: implements logic with validated parameters
func nvRead(t transport.TPM, hierarchy, index tpm2.TPMHandle, auth tpm2.Session, blockSize int, multiIndex bool) ([]byte, error) { ... }
```

### 1.9 Error Handling

**Sentinel errors** are declared as package-level `var` blocks using `errors.New()`:

```go
var (
    ErrMissingHandle    = errors.New("keyHandle is required")
    ErrMissingData      = errors.New("data is required")
    ErrInvalidBlockSize = errors.New("blockSize must be positive")
)
```

**Custom error types** implement `Error()` and `Unwrap()`:

```go
type ErrHandleNotFound struct {
    Handle tpm2.TPMHandle
    Err    error
}

func (e *ErrHandleNotFound) Error() string { ... }
func (e *ErrHandleNotFound) Unwrap() error { return e.Err }
```

**Error wrapping** uses `fmt.Errorf()` with `%w`:

```go
return nil, fmt.Errorf("tpm2.ReadPublic() failed: %w", err)
```

### 1.10 Enum Types

Enums use `const` + `iota` with a dedicated type. The zero value is always the "unspecified" variant. A `String()` method is required:

```go
type KeyFamily int

const (
    UnspecifiedKey KeyFamily = iota
    RSA
    ECC
)

func (kt KeyFamily) String() string {
    switch kt {
    case RSA:
        return "RSA"
    case ECC:
        return "ECC"
    default:
        return fmt.Sprintf("unknown(%d)", kt)
    }
}
```

When JSON serialization is needed, `MarshalJSON()` / `UnmarshalJSON()` are implemented (see `tpmsession.SessionType`).

### 1.11 Godoc Comments

All exported symbols have godoc-style comments. Conventions:

- Starts with the exported name
- Uses [doc links](https://go.dev/doc/comment#doclinks) with `[TypeName]` notation for cross-references
- Documents defaults with `Default:` prefix in field comments
- Includes `Example:` sections with working code snippets
- Uses `Note:` for caveats
- References TCG specifications with `Source:` or `See` annotations

```go
// NVRead reads data from a non-volatile storage (NV) index.
//
// By default, data is read from a single NV index.
// When [NVReadConfig.MultiIndex] is true, data is read from successive NV indices
// starting from the base index. This should be used when reading data that was
// written with [NVWriteConfig.MultiIndex] enabled.
//
// Examples:
//
//	data, err := tpmutil.NVRead(tpm, tpmutil.NVReadConfig{
//	    Index:     0x01500000,
//	    Hierarchy: tpm2.TPMRHOwner,
//	})
//
// Note: If cfg is nil, default configuration is used.
func NVRead(t transport.TPM, optionalCfg ...NVReadConfig) ([]byte, error) {
```

For struct fields:

```go
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
}
```

### 1.12 Interface Design

Interfaces are small and focused. Implementations are unexported structs; users interact via the interface. Factory functions return the interface type:

```go
// Handle provides a layer of abstraction over TPM handles.
type Handle interface {
    Handle() tpm2.TPMHandle
    Name() tpm2.TPM2BName
    IsAuth() bool
    Type() HandleType
    Public() *tpm2.TPMTPublic
    HasPublic() bool
}

// HandleCloser extends Handle with the ability to release resources.
type HandleCloser interface {
    Handle
    io.Closer
}

// Unexported implementation
type tpmHandle struct { ... }
```

### 1.13 Testing Conventions

**Package name**: Tests use the external test package (`package tpmutil_test`, not `package tpmutil`). This enforces black-box testing through the public API.

**Table-driven tests**: The standard pattern for all tests:

```go
func TestNVReadConfigValidation(t *testing.T) {
    tests := []struct {
        name    string
        cfg     tpmutil.NVReadConfig
        wantErr error
    }{
        {
            name:    "missing Index",
            cfg:     tpmutil.NVReadConfig{},
            wantErr: tpmutil.ErrMissingIndex,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := tt.cfg.CheckAndSetDefault()
            if tt.wantErr != nil {
                if err == nil {
                    t.Errorf("expected error %v, got nil", tt.wantErr)
                } else if err != tt.wantErr {
                    t.Errorf("expected error %v, got %v", tt.wantErr, err)
                }
            } else if err != nil {
                t.Errorf("expected no error, got %v", err)
            }
        })
    }
}
```

**Assertions**: The project uses stdlib's `testing` package only (no testify or similar). Common patterns:
- `t.Errorf("expected X, got Y")` for assertions
- `t.Fatalf(...)` for setup/precondition failures
- `t.Helper()` for test utility functions
- `t.Cleanup(func() { ... })` for resource cleanup

**TPM simulator**: Tests requiring a TPM connection use `testutil.OpenSimulator(t)` (or `tpmtest.OpenSimulator(t)` from the public API):

```go
func TestNVWrite(t *testing.T) {
    thetpm := testutil.OpenSimulator(t)
    // ... test logic using thetpm
}
```

**Error comparison**: Uses direct comparison (`err != tt.wantErr`) for sentinel errors, or `errors.Is()` when testing error chains.

**Test naming**: Uses lowercase descriptive names with context:
- `"missing Index"`, `"negative BlockSize"`, `"valid custom BlockSize"`
- Compact form: `{"ok w/ small_payload", 10, false}`

### 1.14 Constants and Variables

**Public constants** include godoc with specification references:

```go
const (
    // MaxBufferSize is the size of TPM2B_MAX_BUFFER.
    // This value is TPM-dependent; the value here is what all TPMs support.
    // See TPM 2.0 spec, part 2, section 10.4.8 TPM2B_MAX_BUFFER.
    MaxBufferSize = 1024
)
```

**Package-level variables** group related values:

```go
var (
    NoAuth     = tpm2.PasswordAuth(nil)
    NullTicket = tpm2.TPMTTKHashCheck{...}
)
```

**Private constants** alias or derive from shared values:

```go
const (
    maxBufferSize = tpmkit.MaxBufferSize
    maxNVSize     = 2048
    maxIndexCount = 256
)
```

### 1.15 Concurrency

- `sync.RWMutex` for protecting mutable state (see `SessionManager`)
- `atomic.Pointer` for swappable function pointers (see `PromptAuthValue`)
- Tests validate concurrent access with goroutines and `sync.WaitGroup`

### 1.16 Resource Cleanup

- `HandleCloser` implements `io.Closer` to flush TPM handles
- `defer closer()` pattern for resource release in function bodies
- `t.Cleanup()` in tests for automatic teardown

---

## 2. Package: `tpmutil`

**Purpose**: Core TPM utility functions — key management, NV storage, hashing, signing, HMAC, symmetric crypto, PCR operations, handle abstractions.

### 2.1 File Layout

| File | Content |
|------|---------|
| `tpmutil.go` | Main operations: `NVRead`, `NVWrite`, `Hash`, `Hmac`, `Sign`, `SymEncryptDecrypt`, `GenerateRnd`, `GetSKRHandle`, `GetEKHandle`, `CreatePrimary`, `Create`, `Load`, `Persist`, `PersistEK` |
| `config.go` | All `*Config` structs with `CheckAndSetDefault()` |
| `errors.go` | Sentinel errors and custom error types |
| `handle.go` | `Handle`, `HandleCloser` interfaces and `tpmHandle` implementation |
| `key.go` | `KeyFamily`, `KeyType` enums, key template generators (`NewApplicationKeyTemplate`, `NewAKTemplate`) |
| `constants.go` | Predefined TPM handles, EK/SRK templates, application/AK key templates |
| `result.go` | `CreateResult`, `CreatePrimaryResult` with JSON serialization |
| `pcr.go` | PCR selection utilities |
| `policy.go` | EK policy callback |

### 2.2 Configuration Structs

All operations use dedicated config structs: `HashConfig`, `SignConfig`, `NVReadConfig`, `NVWriteConfig`, `ParentConfig`, `EKParentConfig`, `CreatePrimaryConfig`, `CreateConfig`, `LoadConfig`, `SymEncryptDecryptConfig`, `HmacConfig`, `KeyConfig`, `PersistConfig`.

Each follows the `CheckAndSetDefault()` pattern (see [1.5](#15-the-checkandsetdefault-pattern)).

### 2.3 Handle Abstraction

The `Handle` and `HandleCloser` interfaces abstract TPM handle types (`tpm2.TPMHandle`, `tpm2.AuthHandle`, `tpm2.NamedHandle`) into a uniform API. The unexported `tpmHandle` struct is the sole implementation.

Factory functions:
- `NewHandle(h)` — lightweight handle (no TPM transport, no `Close()`)
- `NewHandleCloser(tpm, h)` — closeable handle (flushes on `Close()`)
- `ToHandle(tpm, handle)` — converts raw `tpm2.TPMHandle` by issuing `ReadPublic`

### 2.4 Result Serialization

`CreateResult` and `CreatePrimaryResult` support JSON marshaling via `Marshal()` and loading via `LoadCreateResult()` / `LoadCreatePrimaryResult()`. The `Target` enum controls the output format.

### 2.5 Predefined Templates

TCG-compliant key templates are defined as package-level variables with spec references:
- SRK: `RSASRKTemplate`, `ECCSRKTemplate`
- EK (low-range): `RSAEKTemplate`, `ECCEKTemplate`
- EK (high-range): `RSA2048EKTemplate`, `ECCP256EKTemplate`, `ECCP384EKTemplate`, `ECCP521EKTemplate`, `ECCSM2P256EKTemplate`, `RSA3072EKTemplate`, `RSA4096EKTemplate`
- Application/AK: private templates exposed via `NewApplicationKeyTemplate()` and `NewAKTemplate()`

---

## 3. Package: `tpmcrypto`

**Purpose**: Cryptographic utility functions bridging TPM structures and Go's `crypto` standard library. Pure computation — no TPM transport required.

### 3.1 File Layout

| File | Content |
|------|---------|
| `crypto.go` | All functions (public key extraction, validation, signature verification, digest computation, scheme helpers, key parameter builders) |
| `crypto_test.go` | Table-driven tests |

### 3.2 Specific Conventions

- **No `CheckAndSetDefault()` pattern**: This is a stateless utility package. Functions validate their inputs inline.
- **No config structs**: Functions take direct parameters.
- **No internal sub-packages**: Everything in a single file.

### 3.3 Type Assertion Wrappers

Multiple levels of extraction are provided for type safety:

```go
PublicKey(public any) (crypto.PublicKey, error)          // Generic
PublicKeyRSA(public any) (*rsa.PublicKey, error)         // RSA-specific
PublicKeyECDSA(public any) (*ecdsa.PublicKey, error)     // ECC-specific
```

### 3.4 Dual-Interface Support

Functions accepting TPM types have counterparts accepting Go standard types:

```go
VerifySignatureFromPublic(pub tpm2.TPMTPublic, sig tpm2.TPMTSignature, data []byte) error
VerifySignature(pub crypto.PublicKey, sig tpm2.TPMTSignature, signHash crypto.Hash, data []byte) error
```

### 3.5 Security Constants

```go
const (
    minRSABits = 2048
    minECCBits = 256
)

var secureCurves = map[tpm2.TPMECCCurve]bool{ ... }
```

---

## 4. Package: `tpmsession`

**Purpose**: Encrypted TPM session management with bound and salted session types, parameter encryption, and audit session support.

### 4.1 File Layout

| File | Content |
|------|---------|
| `session.go` | `SessionManager`, `EncryptionType`, `AuditConfig`, `AuditResult`, session creation logic, auth prompting |
| `key.go` | `SessionKey`, `SessionType`, serialization (`Marshal`, `ParseSessionKey`, `ReadSessionKey`) |
| `session_simulated_test.go` | Simulator-based tests |
| `session_real_tpm_test.go` | Real TPM tests (build tag: `linux && localtest`) |
| `key_test.go` | `SessionKey` validation and serialization tests |

### 4.2 Specific Conventions

#### Thread Safety

`SessionManager` is thread-safe. Mutable fields are protected by `sync.RWMutex`:

```go
type SessionManager struct {
    // Immutable fields (no lock needed)
    tpm       transport.TPM
    key       *SessionKey

    // Protected by mu
    mu         sync.RWMutex
    hashAlg    tpm2.TPMAlgID
    aesKeySize tpm2.TPMKeyBits
    audit      *auditState
}
```

#### Method Chaining

`WithHashAlg()` returns `*SessionManager` to enable chaining:

```go
sm.WithHashAlg(crypto.SHA384).GetSession()
```

#### Pluggable Auth Provider

Authorization prompting is pluggable via `atomic.Pointer`:

```go
var PromptAuthValue atomic.Pointer[func() ([]byte, error)]
```

The default prompts via stdin. Tests override this with `PromptAuthValue.Store(...)`.

#### Build Tags for Real TPM Tests

```go
//go:build linux && localtest
```

#### JSON Serialization for `SessionKey`

`SessionKey.Marshal()` produces JSON. `ParseSessionKey()` and `ReadSessionKey()` deserialize. The `SessionType` enum supports `MarshalJSON()` / `UnmarshalJSON()`.

#### Name-Based Validation

`SessionKey.CheckAndSetDefault()` validates that the TPM Name cryptographically matches the Public area (for salted sessions), preventing man-in-the-middle attacks.

---

## 5. Package: `tpmtest`

**Purpose**: Public test infrastructure for consumers of the library.

### 5.1 File Layout

| File | Content |
|------|---------|
| `open.go` | `OpenSimulator(t *testing.T) transport.TPM` |

### 5.2 Specific Conventions

- Minimal package: a single function
- Mirrors `internal/utils/testutil.OpenSimulator()` for external consumers
- Uses `t.Fatalf()` for fatal setup errors, `t.Cleanup()` for teardown

---

## 6. Root Package (`tpmkit`)

**Purpose**: Shared constants and lookup tables used across sub-packages.

### 6.1 File Layout

| File | Content |
|------|---------|
| `constants.go` | `MaxBufferSize`, `SRKHandle`, `HashInfo` |

### 6.2 Conventions

- Only truly shared, cross-package values live here
- Imported as `tpmkit` in sub-packages: `tpmkit "github.com/loicsikidi/go-tpm-kit"`
- `HashInfo` is a lookup table mapping `tpm2.TPMAlgID` to `crypto.Hash`

---

## 7. Internal Utilities

### 7.1 `internal/utils`

| File | Content |
|------|---------|
| `args.go` | `OptionalArg[T]()`, `OptionalArgWithDefault[T]()` — generic helpers for variadic optional args |

### 7.2 `internal/utils/testutil`

| File | Content |
|------|---------|
| `open.go` | `OpenSimulator(t *testing.T) transport.TPM` — TPM simulator setup for internal tests |

---

## Quick Reference: Adding a New TPM Operation

When adding a new TPM operation to `tpmutil`, follow this checklist:

1. **Define a config struct** in `config.go` with a `CheckAndSetDefault() error` method
2. **Document each field** with godoc, noting defaults with `Default:` and required fields with `Required.`
3. **Use doc links** (`[TypeName]`) for cross-references to other types
4. **Add sentinel errors** to `errors.go` if new validation failures are introduced
5. **Create the public function** in `tpmutil.go` that:
   - Accepts `transport.TPM` as the first parameter
   - Accepts the config struct as a variadic parameter
   - Calls `utils.OptionalArg()` + `cfg.CheckAndSetDefault()`
   - Delegates to an unexported implementation function
6. **Create the private function** that receives validated, concrete parameters
7. **Write tests** in a `tpmutil_<function>_test.go` file using:
   - External test package (`package tpmutil_test`)
   - Table-driven tests
   - `testutil.OpenSimulator(t)` for TPM access
   - Config validation tests in `config_test.go`
