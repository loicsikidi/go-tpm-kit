// Package tpmsession provides utilities for creating and managing encrypted TPM sessions.
//
// It supports two types of sessions:
//   - Bound sessions: sessions bound to a specific TPM object using an authorization value
//   - Salted sessions: sessions using encrypted salt for cryptographic binding to a TPM key
//
// Both session types provide parameter encryption and HMAC protection for TPM commands.
package tpmsession

import (
	"bytes"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"golang.org/x/term"
)

// SessionType represents the type of TPM session.
type SessionType int

const (
	// UnspecifiedSession indicates that the session type has not been set.
	UnspecifiedSession SessionType = iota

	// BoundSession is a session bound to a specific TPM object using an authorization value.
	BoundSession

	// SaltedSession is a session using encrypted salt for cryptographic binding to a TPM key.
	SaltedSession
)

func (st SessionType) String() string {
	switch st {
	case BoundSession:
		return "bound"
	case SaltedSession:
		return "salted"
	default:
		return fmt.Sprintf("Unknown(%d)", int(st))
	}
}

// MarshalJSON implements the [json.Marshaler] interface for SessionType.
func (st SessionType) MarshalJSON() ([]byte, error) {
	return json.Marshal(st.String())
}

// UnmarshalJSON implements the [json.Unmarshaler] interface for SessionType.
func (st *SessionType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	switch s {
	case "bound":
		*st = BoundSession
	case "salted":
		*st = SaltedSession
	default:
		*st = UnspecifiedSession
	}

	return nil
}

// SessionKey represents the metadata needed to establish a TPM session.
//
// For bound sessions, only Handle, Name, and SessionType are required.
// For salted sessions, Handle, Name, Public, and SessionType are all required.
//
// SessionKey can be marshaled using [SessionKey.Marshal] and unmarshaled using [LoadSessionKey].
type SessionKey struct {
	// SessionType specifies whether this is a bound or salted session.
	// Must be either [BoundSession] or [SaltedSession].
	SessionType SessionType

	// Handle is the persistent handle of the TPM object (e.g., 0x81000001 for SRK).
	Handle tpm2.TPMHandle

	// Name is the TPM Name of the object.
	Name tpm2.TPM2BName

	// Public is the public portion of the TPM object (TPM2B_PUBLIC).
	Public *tpm2.TPM2BPublic
}

// sessionKeyJSON is used for JSON marshaling/unmarshaling.
type sessionKeyJSON struct {
	SessionType SessionType `json:"session_type"`
	Handle      uint32      `json:"handle"`
	Name        []byte      `json:"name"`
	Public      []byte      `json:"public,omitempty"`
}

// Marshal serializes the SessionKey to stored data blob on disk.
func (sk SessionKey) Marshal() ([]byte, error) {
	j := sessionKeyJSON{
		SessionType: sk.SessionType,
		Handle:      uint32(sk.Handle),
		Name:        tpm2.Marshal(sk.Name),
	}

	if sk.Public != nil {
		j.Public = tpm2.Marshal(sk.Public)
	}

	return json.Marshal(j)
}

// LoadSessionKey deserializes a [SessionKey] from a stored data blob.
func LoadSessionKey(opaqueBlob []byte) (*SessionKey, error) {
	var sk SessionKey
	if err := sk.unmarshal(opaqueBlob); err != nil {
		return nil, fmt.Errorf("unmarshal session key: %w", err)
	}
	return &sk, nil
}

// unmarshal deserializes a SessionKey from a stored data blob.
func (sk *SessionKey) unmarshal(data []byte) error {
	var j sessionKeyJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}

	sk.SessionType = SessionType(j.SessionType)
	sk.Handle = tpm2.TPMHandle(j.Handle)

	name, err := tpm2.Unmarshal[tpm2.TPM2BName](j.Name)
	if err != nil {
		return fmt.Errorf("unmarshal name failed: %w", err)
	}
	sk.Name = *name

	if len(j.Public) > 0 {
		public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](j.Public)
		if err != nil {
			return fmt.Errorf("unmarshal public failed: %w", err)
		}
		sk.Public = public
	}

	return nil
}

// CheckAndSetDefault validates the SessionKey and sets default values where appropriate.
func (sk *SessionKey) CheckAndSetDefault() error {
	if sk.SessionType != BoundSession && sk.SessionType != SaltedSession {
		return errors.New("session type must be either BoundSession or SaltedSession")
	}

	if sk.Handle == 0 {
		return errors.New("handle must not be zero")
	}

	if len(sk.Name.Buffer) == 0 {
		return errors.New("name must not be empty")
	}

	if len(sk.Name.Buffer) < 2 {
		return errors.New("name too short: must include nameAlg (2 bytes) + hash")
	}

	// If Public is provided (salted session), validate it matches Name
	if sk.Public != nil {
		// Compute Name from Public and verify it matches
		computedName, err := computeName(*sk.Public)
		if err != nil {
			return fmt.Errorf("compute name from public: %w", err)
		}

		if !bytes.Equal(sk.Name.Buffer, computedName.Buffer) {
			return fmt.Errorf("name mismatch: stored=%x computed=%x", sk.Name.Buffer, computedName.Buffer)
		}
	}

	return nil
}

// computeName calculates the TPM Name from a public key.
//
// See TPM 2.0 Part 1, Section 16 (Names) for specification.
func computeName(pub tpm2.TPM2BPublic) (*tpm2.TPM2BName, error) {
	contents, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("get public contents: %w", err)
	}

	name, err := tpm2.ObjectName(contents)
	if err != nil {
		return nil, fmt.Errorf("compute object name: %w", err)
	}

	return name, nil
}

// PromptAuthValue is called to prompt for an authorization value for bound sessions.
// This variable can be overridden in tests or custom implementations.
//
// The default implementation prompts the user via stdin/stdout.
var PromptAuthValue atomic.Pointer[func() ([]byte, error)]

func init() {
	defaultPrompt := func() ([]byte, error) {
		fmt.Fprint(os.Stderr, "Enter authorization value: ")
		password, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read password: %w", err)
		}
		return password, nil
	}
	PromptAuthValue.Store(&defaultPrompt)
}

// SessionManager manages the lifecycle of a TPM session.
//
// It validates the session parameters upon creation and provides a method
// to retrieve the configured session for use in TPM commands.
type SessionManager struct {
	key         *SessionKey
	authValue   []byte
	sessionType SessionType
	public      *tpm2.TPMTPublic
	hashAlg     tpm2.TPMAlgID
	aesKeySize  tpm2.TPMKeyBits
}

// NewSessionManager creates a new SessionManager for the given SessionKey.
//
// The session type is determined by the [SessionKey.SessionType] field.
//
// For bound sessions, the global PromptAuthValue function is called to obtain
// the authorization value. This happens once during construction.
//
// The constructor validates that the SessionKey is valid and that the specified
// TPM object exists and matches the metadata in the SessionKey.
//
// By default, sessions use SHA256 for HMAC and AES-128 for encryption.
// Use [SessionManager.WithHashAlg] to configure different algorithms.
//
// Example (default SHA256 + AES-128):
//
//	key, err := tpmsession.LoadSessionKey(blob)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	sm, err := tpmsession.NewSessionManager(tpm, key)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	session := sm.GetSession()
//
// Example (custom hash algorithm with auto-matched AES key size):
//
//	sm, err := tpmsession.NewSessionManager(tpm, key)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Use SHA384 with AES-192 for stronger security
//	session := sm.WithHashAlg(crypto.SHA384).GetSession()
func NewSessionManager(tpm transport.TPM, key *SessionKey) (*SessionManager, error) {
	if err := key.CheckAndSetDefault(); err != nil {
		return nil, fmt.Errorf("invalid session key: %w", err)
	}

	var (
		authValue []byte
		public    *tpm2.TPMTPublic
		err       error
	)
	if key.SessionType == BoundSession {
		// Prompt for authorization value using the global prompter
		prompter := PromptAuthValue.Load()
		if prompter == nil {
			return nil, errors.New("PromptAuthValue not initialized")
		}

		authValue, err = (*prompter)()
		if err != nil {
			return nil, fmt.Errorf("prompt for auth value: %w", err)
		}
	} else {
		// cache public key contents for salted sessions
		public, err = key.Public.Contents()
		if err != nil {
			return nil, fmt.Errorf("get public contents: %w", err)
		}
	}

	// Validate that the object exists in the TPM and matches our metadata
	if err := validateTPMObject(tpm, key); err != nil {
		return nil, fmt.Errorf("TPM object validation failed: %w", err)
	}

	return &SessionManager{
		key:         key,
		public:      public,
		authValue:   authValue,
		sessionType: key.SessionType,
		hashAlg:     tpm2.TPMAlgSHA256, // default hash algorithm
		aesKeySize:  128,               // default AES key size matching SHA256
	}, nil
}

// WithHashAlg configures the hash algorithm for the HMAC session.
//
// The AES key size is automatically matched to the hash algorithm strength:
//   - SHA256 → AES-128 (128 bits of security)
//   - SHA384 → AES-192 (192 bits of security)
//   - SHA512 → AES-256 (256 bits of security)
//
// Example:
//
//	sm, err := tpmsession.NewSessionManager(tpm, &key)
//	if err != nil {
//	    return err
//	}
//	sm.WithHashAlg(crypto.SHA384)
//	session := sm.GetSession()
func (sm *SessionManager) WithHashAlg(hash crypto.Hash) *SessionManager {
	alg, err := tpmcrypto.HashToAlgorithm(hash)
	if err != nil {
		// Fallback to SHA256 + AES-128 if the algorithm is not supported
		sm.hashAlg = tpm2.TPMAlgSHA256
		sm.aesKeySize = 128
		return sm
	}

	sm.hashAlg = alg

	// Match AES key size to hash strength
	switch alg {
	case tpm2.TPMAlgSHA1:
		// upgrade to SHA256 for better security
		sm.hashAlg = tpm2.TPMAlgSHA256
		fallthrough
	case tpm2.TPMAlgSHA256, tpm2.TPMAlgSHA3256:
		sm.aesKeySize = 128
	case tpm2.TPMAlgSHA384, tpm2.TPMAlgSHA3384:
		sm.aesKeySize = 192
	case tpm2.TPMAlgSHA512, tpm2.TPMAlgSHA3512:
		sm.aesKeySize = 256
	default:
		// conservative default
		sm.aesKeySize = 128
	}

	return sm
}

// validateTPMObject verifies that the TPM object exists and matches the metadata.
func validateTPMObject(tpm transport.TPM, key *SessionKey) error {
	readPubResp, err := tpm2.ReadPublic{
		ObjectHandle: key.Handle,
	}.Execute(tpm)
	if err != nil {
		return fmt.Errorf("read public from TPM handle %#x: %w", key.Handle, err)
	}

	// Verify that the Name from the TPM matches our stored Name
	if !bytes.Equal(key.Name.Buffer, readPubResp.Name.Buffer) {
		return fmt.Errorf("name mismatch: stored=%x tpm=%x (possible attack or stale metadata)",
			key.Name.Buffer, readPubResp.Name.Buffer)
	}

	// For salted sessions, also verify the Public key matches
	if key.SessionType == SaltedSession {
		if key.Public == nil {
			return errors.New("public key must be provided for salted sessions")
		}
		storedPublicBytes := key.Public.Bytes()
		tpmPublicBytes := readPubResp.OutPublic.Bytes()

		if !bytes.Equal(storedPublicBytes, tpmPublicBytes) {
			return fmt.Errorf("public key mismatch between metadata and TPM (possible attack)")
		}
	}
	return nil
}

// GetSession returns a tpm2.Session configured for the session type.
//
// For bound sessions, it calls the AuthProvider to obtain the authorization value.
// For salted sessions, it uses encrypted salt for cryptographic binding.
//
// The returned session provides parameter encryption (in/out for convenience) and HMAC protection.
func (sm *SessionManager) GetSession() tpm2.Session {
	switch sm.sessionType {
	case BoundSession:
		return sm.getBoundSession()
	case SaltedSession:
		return sm.getSaltedSession()
	default:
		return nil
	}
}

// getBoundSession creates a bound session using the stored authorization value.
func (sm *SessionManager) getBoundSession() tpm2.Session {
	return tpm2.HMAC(
		sm.hashAlg,
		16, // nonce size
		tpm2.Auth(sm.authValue),
		tpm2.AESEncryption(sm.aesKeySize, tpm2.EncryptInOut),
		tpm2.Bound(sm.key.Handle, sm.key.Name, sm.authValue),
	)
}

// getSaltedSession creates a salted session with encrypted salt.
func (sm *SessionManager) getSaltedSession() tpm2.Session {
	return tpm2.HMAC(
		sm.hashAlg,
		16, // nonce size
		tpm2.AESEncryption(sm.aesKeySize, tpm2.EncryptInOut),
		tpm2.Salted(sm.key.Handle, *sm.public),
	)
}
