# tpmsession

Package `tpmsession` simplifies the implementation of **CPU to TPM Bus Protection** by providing encrypted TPM sessions with parameter encryption and HMAC protection. It focuses on protecting the confidentiality and integrity of data exchanged over the TPM bus.

## Background: TPM Session Types

The TPM specification defines three types of HMAC sessions, each serving a distinct purpose:

### 1. Authorization Sessions (Default)
- **Purpose:** Authenticate access to TPM objects
- **Protection:** Command parameter integrity and replay attack prevention (via nonces)
- **Use case:** Standard TPM command authorization

### 2. Encryption Sessions
- **Purpose:** Encrypt command and/or response parameters to protect data confidentiality
- **Protection:** Prevents eavesdropping on the CPU-TPM bus
- **Use case:** Protecting sensitive data in transit (this is the primary focus of this package)

### 3. Audit Sessions
- **Purpose:** Maintain a cryptographic audit trail of TPM operations
- **Protection:** The TPM maintains an audit digest (cumulative HMAC over commands)
- **Use case:** Proving that a sequence of operations occurred without tampering

## Objective: Bus Protection

This library implements the guidance from [TCG CPU-TPM Bus Protection Guidance – Passive Attack Mitigations](https://trustedcomputinggroup.org/wp-content/uploads/TCG_CPU_TPM_Bus_Protection_Guidance_Passive_Attack_Mitigation_v1p0_PUB.pdf).

**Primary focus:** Encrypting messages sent over the TPM bus using HMAC sessions of type "Bound" or "Salted" to derive a **sessionKey** that both the client and TPM can use for encrypting exchanges.

**Core component:** The `SessionManager` is responsible for creating and managing the lifecycle of TPM HMAC sessions dedicated to encryption.

**Additional capabilities:** The library also provides utilities to enable audit sessions, with some current limitations (see [Known Limitations](#known-limitations)).

## Design Philosophy

> [!IMPORTANT]
> This package has an **opinionated** approach to TPM session security, prioritizing safe defaults and clear security boundaries.

The package supports two distinct session types, each designed for specific operational contexts:

### Salted Sessions = Machine-to-Machine Automation

**Design intent:** Automated/unattended scenarios where no human intervention is possible.

**Two-phase workflow:**

**Phase 1 - Onboarding (Trust Establishment):**
- TPM key (typically EK or SRK) undergoes a challenge/verification process
- This proves the key belongs to a genuine TPM and can be trusted
- Verified key metadata is captured in a `SessionKey` structure
- The object is stored at a **persistent handle** (range 0x81000000-0x81FFFFFF)
- `SessionKey` is serialized and stored as a trusted resource

> [!NOTE]
> The onboarding/challenge phase is **not** implemented in this package. It is expected to be handled by higher-level attestation workflows (e.g., remote attestation, enrollment protocols).

**Phase 2 - Runtime Session Creation:**
- Stored `SessionKey` is loaded from disk
- `NewSessionManager` validates that the TPM object still matches the trusted metadata
- If validation passes, the session is established without human intervention
- Enables secure automated operations

**Use cases:** Service-to-service communication, automated TPM operations, containerized workloads, CI/CD pipelines.

### Bound Sessions = Human Operator Required

**Design intent:** Interactive operations where a **human operator** knows and provides the authorization value.

**Two-phase workflow:**

**Phase 1 - Onboarding (Trust Establishment):**
- TPM object (e.g., sealed data, signing key) is created or identified with a known authorization value
- Object is stored at a **persistent handle** (range 0x81000000-0x81FFFFFF)
- Object metadata is captured in a `SessionKey` structure
- `SessionKey` is serialized and stored as a trusted resource

**Phase 2 - Runtime Session Creation:**
- Stored `SessionKey` is loaded from disk
- Human operator is prompted for the authorization value during `NewSessionManager` construction
- Password is prompted directly in the terminal (no echo)
- One-time prompt per session manager lifecycle
- `NewSessionManager` validates that the TPM object still matches the trusted metadata
- If validation passes and auth is correct, the session is established

**Use cases:** Interactive administration, manual TPM operations, debugging sessions.

### Persistent Handles Requirement

> [!IMPORTANT]
> The handle in `SessionKey` **MUST** be a persistent TPM handle (range 0x81000000-0x81FFFFFF).
>
> **Rationale:**
> - SessionKeys are meant to be stored and reused across program restarts
> - Transient handles don't survive TPM resets, breaking the trust model
> - Persistent handles enable the onboarding/runtime separation described above

## Trust Model

The security model in this package is built around the `SessionKey` structure, which serves as a serializable trust anchor. This design follows the same principle as **ESYS_TR** (ESAPI Resource) from the TPM2 Software Stack ([tpm2-tss](https://github.com/tpm2-software/tpm2-tss)) Enhanced System API.

### The Name: Cryptographic Fingerprint

The critical security element is the **Name** field in `SessionKey`, which acts as a cryptographic fingerprint of the trusted TPM object:

- **Uniquely identifies** the exact cryptographic parameters of the object
- **Changes automatically** if the object's public parameters are modified
- **Used in HMAC calculations** for session authentication (both command and response)

This creates **two independent HMAC checks** (similar to ESAPI):
1. Session HMAC using the stored `Name` (command/response authentication)
2. TPM's own validation that the object matches the expected `Name`

### Validation at Runtime

When creating a session manager, `NewSessionManager()` performs critical validation to ensure session authenticity:

```go
// Load the SessionKey from storage
key, err := tpmsession.LoadSessionKey(blob)

// Create session manager - validates Name matches TPM object
sm, err := tpmsession.NewSessionManager(tpm, key)

// Get an encrypted, HMAC-protected session bound to the trusted object
session := sm.GetSession()
```

**Validation steps:**
- Reads the object from the persistent handle
- Verifies that the TPM-reported `Name` matches the stored `Name` in `SessionKey`
- Ensures the handle is persistent (not transient)
- Returns an error if any verification fails (indicating a possible attack or stale metadata)

**Protection against:**
- Handle substitution (wrong object at the persistent handle)
- Stale metadata (TPM object changed since onboarding)
- Downgrade attacks (weaker cryptographic parameters)
- Man-in-the-middle attacks (name comparison fails)

**Security guarantee:** If `NewSessionManager` succeeds, the session is communicating with the exact TPM object that was originally trusted.

## Scope and Responsibilities

> [!IMPORTANT]
> **Separation of Concerns**
>
> `SessionManager` is **solely responsible** for creating and managing sessions that provide:
> - **Parameter encryption** (command/response data protection)
> - **Audit capabilities** (command sequence attestation)
>
> **`SessionManager` does NOT handle authentication.** Authentication is the responsibility of TPM commands themselves.
>
> Sessions are meant to be used as parameters in TPM commands:
> ```go
> session := sm.GetSession()
> tpm2.CommandXXX{...}.Execute(tpm, session) // Session passed here
> ```

## Known Limitations

> [!WARNING]
> **Audit Mode Disables Encryption**
>
> When audit mode is active via [StartAuditSession], parameter encryption is automatically disabled.
>
> **Reason:** The underlying `tpm2.CommandAudit` implementation does not currently support auditing when parameters are encrypted.
>
> **Impact:** While in audit mode, command and response parameters are transmitted in cleartext (though still protected by HMAC).

## Features

- **Two session types supported:**
  - **Bound sessions**: Sessions bound to a specific TPM object using an authorization value
  - **Salted sessions**: Sessions using encrypted salt for cryptographic binding to a TPM key

- **Configurable security parameters:**
  - Customizable hash algorithms (SHA256, SHA384, SHA512)
  - Automatic AES key size matching to hash algorithm strength
  - Parameter encryption and HMAC protection for TPM commands
  - Configurable encryption direction (EncryptIn, EncryptOut, EncryptInOut)

- **Audit sessions:**
  - Track and attest to sequences of TPM commands
  - Cryptographic proof of operations via signed attestations
  - Integration with Attestation Keys (AK)

- **Session key management:**
  - Serialization/deserialization support (JSON format)
  - Validation of TPM objects and metadata
  - Secure authorization value prompting

## Installation

```bash
go get github.com/loicsikidi/go-tpm-kit/tpmsession
```

## Usage

### Onboarding Phase: Creating a SessionKey

During the onboarding phase, you create a `SessionKey` by reading the TPM object's metadata. This is typically done after verifying the TPM through attestation.

```go
package main

import (
    "log"
    "os"

    "github.com/google/go-tpm/tpm2/transport"
    "github.com/loicsikidi/go-tpm-kit/tpmsession"
)

func main() {
    // Open TPM
    tpm, err := transport.OpenTPM()
    if err != nil {
        log.Fatal(err)
    }
    defer tpm.Close()

    // After verifying the TPM (attestation process not shown here),
    // create a SessionKey for the trusted object (e.g., SRK at 0x81000001)
    key, err := tpmsession.CreateSessionKey(tpm, tpmsession.SaltedSession, 0x81000001)
    if err != nil {
        log.Fatal(err)
    }

    // Serialize and store the SessionKey for later use
    blob, err := key.Marshal()
    if err != nil {
        log.Fatal(err)
    }

    err = os.WriteFile("trusted-session-key.json", blob, 0600)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("SessionKey created and stored successfully")
}
```

### Runtime Phase: Using a SessionKey (Default SHA256 + AES-128)

```go
package main

import (
    "log"

    "github.com/google/go-tpm/tpm2/transport"
    "github.com/loicsikidi/go-tpm-kit/tpmsession"
)

func main() {
    // Open TPM
    tpm, err := transport.OpenTPM()
    if err != nil {
        log.Fatal(err)
    }
    defer tpm.Close()

    // Load the SessionKey from onboarding phase (stored on disk)
    key, err := tpmsession.ReadSessionKey("trusted-session-key.json")
    if err != nil {
        log.Fatal(err)
    }

    // Create session manager (validates TPM object matches stored metadata)
    sm, err := tpmsession.NewSessionManager(tpm, key)
    if err != nil {
        log.Fatal(err)
    }

    // Get session (uses default SHA256 + AES-128 with EncryptInOut)
    session := sm.GetSession()

    // Use session in TPM commands - you now have cryptographic proof
    // that you're talking to the correct TPM object
    // ...
}
```

### Using Custom Hash Algorithm (SHA384 + AES-192)

```go
// Create session manager
sm, err := tpmsession.NewSessionManager(tpm, key)
if err != nil {
    log.Fatal(err)
}

// Configure SHA384 hash algorithm (AES-192 is automatically matched)
session := sm.WithHashAlg(crypto.SHA384).GetSession()

// Use session in TPM commands with stronger security
// ...
```

### Customizing Parameter Encryption Direction

By default, `GetSession()` uses `EncryptInOut` to encrypt both command and response parameters. You can customize this behavior:

```go
// Only encrypt response parameters (decrypt session)
session := sm.GetSession(tpmsession.EncryptOut)

// Only encrypt command parameters (encrypt session)
session := sm.GetSession(tpmsession.EncryptIn)

// Encrypt both (default behavior)
session := sm.GetSession(tpmsession.EncryptInOut)
// Or simply:
session := sm.GetSession()
```

**When to use each mode:**

- **EncryptOut**: Use when the TPM command returns sensitive data (e.g., `ReadPublic`, `Unseal`)
- **EncryptIn**: Use when you're sending sensitive data to the TPM (e.g., `Create` with sensitive parameters)
- **EncryptInOut**: Use when both command and response contain sensitive data (default, most secure)

### Audit Sessions

Audit sessions allow you to track and attest to a sequence of TPM commands. This is useful for providing cryptographic proof that specific operations were performed.

```go
package main

import (
    "fmt"
    "log"

    "github.com/google/go-tpm/tpm2"
    "github.com/google/go-tpm/tpm2/transport"
    "github.com/loicsikidi/go-tpm-kit/tpmsession"
)

func main() {
    tpm, err := transport.OpenTPM()
    if err != nil {
        log.Fatal(err)
    }
    defer tpm.Close()

    // Load session key
    key, err := tpmsession.ReadSessionKey("session-key.json")
    if err != nil {
        log.Fatal(err)
    }

    sm, err := tpmsession.NewSessionManager(tpm, key)
    if err != nil {
        log.Fatal(err)
    }

    // Start audit session with an Attestation Key
    akHandle := tpmutil.NewHandle(0x81000003) // Your AK handle
    config := &tpmsession.AuditConfig{
        AKHandle: akHandle,
        HashAlg:  tpm2.TPMAlgSHA256,
    }
    err = sm.StartAuditSession(config)
    if err != nil {
        log.Fatal(err)
    }

    // All commands using this session will be audited
    session := sm.GetSession()

    // Execute multiple TPM commands
    _, err = tpm2.ReadPublic{
        ObjectHandle: tpm2.NamedHandle{
            Handle: 0x81000001,
            Name:   key.Name,
        },
    }.Execute(tpm, session)
    if err != nil {
        log.Fatal(err)
    }

    // Stop audit and get signed attestation
    result, err := sm.StopAuditSession()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Audit digest: %x\n", result.Attestation.Attested.SessionAudit.SessionDigest.Buffer)
    fmt.Printf("Signature: %x\n", result.Signature)
}
```

**Key points:**
- Only one audit session can be active at a time per `SessionManager`
- When audit is active, `GetSession()` returns the audit session
- The audit session tracks all commands executed with it
- Call `StopAuditSession()` to retrieve the signed attestation
- The attestation includes a digest of all audited commands and a signature from the AK

### Creating a Bound Session

Bound sessions can also use `CreateSessionKey` during onboarding, then be reused at runtime:

#### Onboarding Phase

```go
// Create a SessionKey for a bound session
// (e.g., for a sealed object at 0x81000002)
key, err := tpmsession.CreateSessionKey(tpm, tpmsession.BoundSession, 0x81000002)
if err != nil {
    log.Fatal(err)
}

// Store it for later use
blob, err := key.Marshal()
if err != nil {
    log.Fatal(err)
}
err = os.WriteFile("bound-session-key.json", blob, 0600)
```

#### Runtime Phase

```go
// Load the SessionKey
key, err := tpmsession.ReadSessionKey("bound-session-key.json")
if err != nil {
    log.Fatal(err)
}

// For bound sessions, you'll be prompted for the authorization value
sm, err := tpmsession.NewSessionManager(tpm, key)
if err != nil {
    log.Fatal(err)
}

session := sm.GetSession()
```

### Advanced: Manual SessionKey Construction

While `CreateSessionKey` is the recommended approach, you can also manually construct a SessionKey if needed (e.g., for testing or when you already have the metadata):

```go
// Manual construction of a salted session key
key := &tpmsession.SessionKey{
    SessionType: tpmsession.SaltedSession,
    Handle:      0x81000001,
    Name:        tpm2.TPM2BName{Buffer: nameBytes},
    Public:      &publicKey,
}

// Validate before use
if err := key.CheckAndSetDefault(); err != nil {
    log.Fatal(err)
}

// Then use it normally
sm, err := tpmsession.NewSessionManager(tpm, key)
// ...
```

> [!NOTE]
> Manual construction requires you to ensure the Name and Public fields are correct and match. `CreateSessionKey` is safer as it reads these directly from the TPM.

## Hash Algorithm and AES Key Size Matching

The package automatically matches AES encryption key sizes to hash algorithm strength for balanced security:

| Hash Algorithm | AES Key Size | Security Level |
|---------------|--------------|----------------|
| SHA256        | 128 bits     | ~128 bits      |
| SHA384        | 192 bits     | ~192 bits      |
| SHA512        | 256 bits     | ~256 bits      |

**Default:** SHA256 with AES-128 (recommended for most use cases)

**For stronger security:** Use `WithHashAlg(crypto.SHA384)` or `WithHashAlg(crypto.SHA512)`

## Session Types

See [Design Philosophy](#design-philosophy) for the complete rationale behind these session types.

### Bound Sessions

**Technical details:**
- Tied to a specific TPM object using an authorization value
- Session key derives from: bound object's auth value + nonces
- Requires human operator to provide the password at construction time

### Salted Sessions

**Technical details:**
- Uses encrypted salt for cryptographic binding to a TPM key
- Session key derives from: encrypted salt (protected by TPM key's public key) + nonces
- Requires prior onboarding phase to establish trust in the TPM key
- Operates without human intervention at runtime

## Security Considerations

### Persistent Handles Required

This package **only supports persistent TPM handles** (0x81000000-0x81FFFFFF) for the following reasons:

1. **SessionKeys are meant to be stored and reused** across program restarts
2. **Transient handles don't survive TPM resets**, breaking the trust model
3. **Persistent handles enable the onboarding/runtime separation** described in the design philosophy

**Recommended handles:**
- **0x81010001**: Endorsement Key (EK) 
- **0x81000001**: Storage Root Key (SRK)
- **0x81000002+**: Application-specific persistent objects

> [!TIP]
> EK and SRK handles are defined by the TPM specification and are commonly used for trusted operations.
>
> *Source: [TCG TPM v2.0 Provisioning Guidance v1.0 rev1.0](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf?page=28) (section 7.8 "NV Memory")*
>
> Application-specific keys should be created at persistent handles starting from 0x81000002 upwards.

### SessionKey Validation in NewSessionManager

The constructor performs critical validation to ensure session authenticity:

```
┌─────────────────────────────────────────────────────┐
│  NewSessionManager(tpm, sessionKey)                 │
└─────────────────────────────────────────────────────┘
                      │
                      ├─► 1. Validate SessionKey structure
                      │      - Check required fields (handle, name, type)
                      │      - Verify name format and length
                      │
                      ├─► 2. Read TPM object at specified handle
                      │      - Execute TPM2_ReadPublic command
                      │
                      ├─► 3. Compare TPM name with stored name
                      │      - Cryptographic comparison (constant-time)
                      │      - Detects tampering or object substitution
                      │
                      ├─► 4. [Salted only] Verify public key match
                      │      - Compare stored vs. actual public key
                      │      - Ensures encryption uses correct key
                      │
                      └─► 5. [Bound only] Prompt for auth value
                             - Secure terminal input (no echo)
                             - One-time prompt during construction
```

**What this protects against:**
- Using sessions with the wrong TPM object
- Stale SessionKey metadata (object was replaced)
- Man-in-the-middle attacks (name comparison fails)
- Accidental misconfigurations

**Security property:** After successful construction, you have cryptographic proof that you're communicating with the exact TPM object from the original onboarding.

### Parameter Encryption

All sessions use AES-CFB mode for parameter encryption:
- Encryption keys are derived from the session key using KDFa
- Command and/or response parameters can be encrypted based on the chosen `EncryptionType`
- The AES key size is automatically matched to the hash algorithm strength

### Nonce Size

The nonce size is fixed at **16 bytes (128 bits)** for all hash algorithms. This provides sufficient entropy for replay protection while being compatible with all TPM implementations.

### Authorization Value Prompting

For bound sessions, the authorization value is requested once during `NewSessionManager` construction using a secure terminal input (via [`golang.org/x/term`](https://github.com/golang/term)). You can customize this behavior by setting the global `PromptAuthValue` function pointer.

## Thread Safety

`SessionManager` is **safe for concurrent use** by multiple goroutines. All public methods are protected by internal synchronization mechanisms.

**Note:** The underlying TPM transport and simulator may have their own concurrency limitations. Dedicated tests needs to be run on a real TPM to validate thread safety in practice.

```bash
# Run all tests including concurrent access tests (requires real TPM)
go test -v -tags "linux localtest" ./tpmsession

# Run only standard tests (works with simulator)
go test -v ./tpmsession
```

## Examples

See the [session_test.go](./session_test.go) file for comprehensive examples of:
- Creating bound and salted sessions
- Using different hash algorithms
- Serializing and deserializing session keys
- Error handling and validation
- Thread-safe concurrent access (requires real TPM)
