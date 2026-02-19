// Copyright (c) 2025, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
	"golang.org/x/term"
)

var (
	// ErrInvalidHandleType is returned when a SessionKey handle is not a persistent handle.
	ErrInvalidHandleType = errors.New("handle must be a persistent TPM handle (TPMHTPersistent)")

	// ErrValidationFailed is returned when TPM object validation fails.
	ErrValidationFailed = errors.New("TPM object validation failed")

	// ErrMissingTPMPublic is returned when a TPM public area is required but missing.
	ErrMissingTPMPublic = errors.New("missing TPM public area for salted session")
)

// EncryptionType represents the parameter encryption direction for TPM sessions.
//
// This is a public wrapper around tpm2's private parameterEncryption type,
// allowing users to specify encryption behavior without accessing private types.
type EncryptionType int

// Public constants for parameter encryption types.
// These mirror the corresponding tpm2 constants.
const (
	// EncryptIn specifies a decrypt session (encrypts command parameters sent to the TPM).
	EncryptIn EncryptionType = 1

	// EncryptOut specifies an encrypt session (encrypts response parameters from the TPM).
	EncryptOut EncryptionType = 2

	// EncryptInOut specifies a decrypt+encrypt session (encrypts both command and response parameters).
	EncryptInOut EncryptionType = 3
)

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

// AuditConfig configures an audit session.
type AuditConfig struct {
	// AKHandle is the Attestation Key used for signing the audit digest.
	// Must not be nil.
	AKHandle tpmutil.Handle

	// HashAlg specifies the hash algorithm to use for the audit digest.
	// Defaults to TPMAlgSHA256 if not specified.
	HashAlg tpm2.TPMAlgID

	// QualifyingData is optional extra data included in the attestation.
	// This can be used to bind the attestation to a specific context (e.g., nonce).
	QualifyingData []byte
}

// CheckAndSetDefault validates and sets default values for AuditConfig.
func (ac *AuditConfig) CheckAndSetDefault() error {
	if ac.AKHandle == nil {
		return errors.New("AKHandle cannot be nil")
	}

	// Set default hash algorithm if not specified
	if ac.HashAlg == 0 {
		ac.HashAlg = tpm2.TPMAlgSHA256
	}

	return nil
}

// auditState holds the state of an active audit session.
type auditState struct {
	// session is the persistent HMAC session with audit enabled
	session tpm2.Session
	// cleanup is the function to close the audit session
	cleanup func() error
	// config is the audit configuration
	config *AuditConfig
}

// AuditResult contains the attestation and signature from an audit session.
type AuditResult struct {
	// Attestation contains the TPM-generated attestation structure
	Attestation *tpm2.TPMSAttest
	// Signature contains the signature over the attestation
	Signature *tpm2.TPMTSignature
}

// SessionManager manages the lifecycle of a TPM session.
//
// It validates the session parameters upon creation and provides a method
// to retrieve the configured session for use in TPM commands.
//
// SessionManager is safe for concurrent use by multiple goroutines.
type SessionManager struct {
	tpm       transport.TPM
	key       *SessionKey
	authValue []byte
	// cached TPM public key contents for salted sessions
	public *tpm2.TPMTPublic

	// mu protects hashAlg, aesKeySize, and audit fields
	mu         sync.RWMutex
	hashAlg    tpm2.TPMAlgID
	aesKeySize tpm2.TPMKeyBits
	// audit holds the state of an active audit session, nil if no audit is active
	audit *auditState
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
//	key, err := tpmsession.ParseSessionKey(blob)
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

	// Validate that the handle is persistent
	h := tpmutil.NewHandle(key.Handle)
	if h.Type() != tpmutil.PersistentHandle {
		return nil, fmt.Errorf("%w: got %v (0x%08X)", ErrInvalidHandleType, h.Type(), key.Handle)
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

	// Initialize SessionManager with all fields before validation
	sm := &SessionManager{
		tpm:        tpm,
		key:        key,
		public:     public,
		authValue:  authValue,
		hashAlg:    tpm2.TPMAlgSHA256, // default hash algorithm
		aesKeySize: 128,               // default AES key size matching SHA256
	}

	// Validate that the object exists in the TPM and matches our metadata
	// This uses sm.GetSession() for two-phase HMAC verification
	if err := sm.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrValidationFailed, err)
	}

	return sm, nil
}

// WithHashAlg configures the hash algorithm for the HMAC session.
//
// The AES key size is automatically matched to the hash algorithm strength:
//   - SHA256 → AES-128 (128 bits of security)
//   - SHA384 → AES-192 (192 bits of security)
//   - SHA512 → AES-256 (256 bits of security)
//
// This method is safe for concurrent use.
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
	sm.mu.Lock()
	defer sm.mu.Unlock()

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

// validate verifies that the TPM object exists and matches the metadata.
//
// The Name is a cryptographic hash of the object's public area (TPM2B_PUBLIC),
// so verifying the Name implicitly verifies the entire public key structure.
// See TPM 2.0 Part 1, Section 16 (Names).
func (sm *SessionManager) validate() error {
	readPubResp, err := tpm2.ReadPublic{
		ObjectHandle: sm.key.Handle,
	}.Execute(sm.tpm)
	if err != nil {
		return fmt.Errorf("read public from TPM handle %#x: %w", sm.key.Handle, err)
	}

	// Verify that the Name from the TPM matches our stored Name
	if !bytes.Equal(sm.key.Name.Buffer, readPubResp.Name.Buffer) {
		return fmt.Errorf("name mismatch: stored=%x tpm=%x (object has changed since onboarding or possible attack)",
			sm.key.Name.Buffer, readPubResp.Name.Buffer)
	}

	return nil
}

// GetSession returns a [tpm2.Session] configured for the session type.
//
// For bound sessions, it calls the AuthProvider to obtain the authorization value.
// For salted sessions, it uses encrypted salt for cryptographic binding.
//
// The encType parameter is optional and specifies the parameter encryption direction:
//   - [EncryptIn]: encrypts command parameters sent to the TPM
//   - [EncryptOut]: encrypts response parameters from the TPM
//   - [EncryptInOut]: encrypts both command and response parameters (default)
//
// If no encType is provided, or if multiple values are provided, only the first
// value is used. If no value is provided, [EncryptInOut] is used as the default.
//
// When an audit session is active (via [SessionManager.StartAuditSession]), this method
// returns the audit session instead of creating a new one. The audit session tracks all
// commands executed with it until [SessionManager.StopAuditSession] is called.
//
// This method is safe for concurrent use.
//
// Example:
//
//	// Default encryption (EncryptInOut)
//	session := sm.GetSession()
//
//	// Only encrypt output
//	session := sm.GetSession(EncryptOut)
//
// Example with audit:
//
//	config := &tpmsession.AuditConfig{
//	    AKHandle: akHandle,
//	    HashAlg:  tpm2.TPMAlgSHA256,
//	}
//	sm.StartAuditSession(config)
//	session := sm.GetSession()
//	// Session now includes audit tracking
//	readPubResp, err := tpm2.ReadPublic{...}.Execute(tpm, session)
//	result, _ := sm.StopAuditSession()
func (sm *SessionManager) GetSession(encType ...EncryptionType) tpm2.Session {
	sm.mu.RLock()
	// If audit is active, return the audit session
	if sm.audit != nil {
		session := sm.audit.session
		sm.mu.RUnlock()
		return session
	}

	// Read sessionType while holding the lock
	sessionType := sm.key.SessionType
	sm.mu.RUnlock()

	// Default to EncryptInOut, use first value if provided
	encryption := EncryptInOut
	if len(encType) > 0 {
		encryption = encType[0]
	}

	switch sessionType {
	case BoundSession:
		return sm.getBoundSession(encryption)
	case SaltedSession:
		return sm.getSaltedSession(encryption)
	default:
		return nil
	}
}

// getAESEncryptionOption returns the appropriate AES encryption option based on EncryptionType.
// This converts our public EncryptionType to tpm2's private parameterEncryption type.
// This method must be called while holding sm.mu.RLock().
func (sm *SessionManager) getAESEncryptionOption(encType EncryptionType) tpm2.AuthOption {
	switch encType {
	case EncryptIn:
		return tpm2.AESEncryption(sm.aesKeySize, tpm2.EncryptIn)
	case EncryptOut:
		return tpm2.AESEncryption(sm.aesKeySize, tpm2.EncryptOut)
	case EncryptInOut:
		fallthrough
	default:
		return tpm2.AESEncryption(sm.aesKeySize, tpm2.EncryptInOut)
	}
}

// getBoundSession creates a bound session using the stored authorization value.
func (sm *SessionManager) getBoundSession(encType EncryptionType) tpm2.Session {
	sm.mu.RLock()
	hashAlg := sm.hashAlg
	aesOption := sm.getAESEncryptionOption(encType)
	sm.mu.RUnlock()

	return tpm2.HMAC(
		hashAlg,
		16, // nonce size
		aesOption,
		tpm2.Bound(sm.key.Handle, sm.key.Name, sm.authValue),
	)
}

// getSaltedSession creates a salted session with encrypted salt.
func (sm *SessionManager) getSaltedSession(encType EncryptionType) tpm2.Session {
	sm.mu.RLock()
	hashAlg := sm.hashAlg
	aesOption := sm.getAESEncryptionOption(encType)
	sm.mu.RUnlock()

	return tpm2.HMAC(
		hashAlg,
		16, // nonce size
		tpm2.Salted(sm.key.Handle, *sm.public),
		aesOption,
	)
}

// StartAuditSession starts auditing for sessions returned by [SessionManager.GetSession].
//
// When audit is active, all TPM commands executed with sessions from GetSession() will
// be tracked in the audit digest. Call [SessionManager.StopAuditSession] to retrieve
// the signed attestation of the audit log.
//
// The config parameter specifies the audit configuration, including the Attestation Key,
// hash algorithm, and optional qualifying data. The config is validated using
// [AuditConfig.CheckAndSetDefault].
//
// Only one audit session can be active at a time per SessionManager. Calling this
// method while an audit session is already active will return an error.
//
// This method is safe for concurrent use.
//
// Example:
//
//	config := &tpmsession.AuditConfig{
//	    AKHandle: akHandle,
//	    HashAlg:  tpm2.TPMAlgSHA256,
//	    QualifyingData: []byte("my-nonce"),
//	}
//	err := sm.StartAuditSession(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer sm.StopAuditSession()
//
//	// All commands using sm.GetSession() will be audited
//	session := sm.GetSession()
//	readPubResp, err := tpm2.ReadPublic{...}.Execute(tpm, session)
//
//	result, err := sm.StopAuditSession()
//	// result contains the attestation and signature
func (sm *SessionManager) StartAuditSession(config *AuditConfig) error {
	if config == nil {
		return errors.New("config cannot be nil")
	}

	// Validate and set defaults
	if err := config.CheckAndSetDefault(); err != nil {
		return fmt.Errorf("invalid audit config: %w", err)
	}

	// Check if audit is already active before creating the session
	sm.mu.Lock()
	if sm.audit != nil {
		sm.mu.Unlock()
		return errors.New("audit session already active")
	}
	sm.mu.Unlock()

	// Create a persistent HMAC session with audit enabled
	// Don't hold the lock during TPM operation as it can be slow
	session, cleanup, err := tpm2.HMACSession(
		sm.tpm,
		config.HashAlg,
		16, // nonce size
		tpm2.Audit(),
	)
	if err != nil {
		return fmt.Errorf("create audit session: %w", err)
	}

	// Acquire lock again to set the audit state
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Double-check that audit wasn't started by another goroutine
	if sm.audit != nil {
		// Clean up the session we just created
		if cleanup != nil {
			if err := cleanup(); err != nil {
				return fmt.Errorf("cleanup audit session: %w", err)
			}
		}
		return errors.New("audit session already active")
	}

	sm.audit = &auditState{
		session: session,
		cleanup: cleanup,
		config:  config,
	}

	return nil
}

// StopAuditSession stops the active audit session and returns the signed attestation.
//
// This method retrieves the audit digest from the TPM and signs it with the
// Attestation Key that was provided to [SessionManager.StartAuditSession].
//
// After this call, the audit session is closed and resources are freed, regardless
// of whether the attestation generation succeeded or failed.
//
// Returns an error if:
//   - No audit session is currently active
//   - Failed to get the session audit digest
//   - Failed to sign the attestation
//
// This method is safe for concurrent use.
//
// Example:
//
//	result, err := sm.StopAuditSession()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Audit digest: %x\n", result.Attestation.Attested.SessionAudit.SessionDigest.Buffer)
func (sm *SessionManager) StopAuditSession() (*AuditResult, error) {
	sm.mu.Lock()
	if sm.audit == nil {
		sm.mu.Unlock()
		return nil, errors.New("no active audit session")
	}

	// Save the audit state before cleanup
	audit := sm.audit
	sm.audit = nil
	sm.mu.Unlock()

	// Ensure we clean up the session
	defer func() {
		if audit.cleanup != nil {
			if err := audit.cleanup(); err != nil {
				fmt.Printf("warning: failed to cleanup audit session: %v\n", err)
			}
		}
	}()

	// Read AK name
	akReadPubResp, err := tpm2.ReadPublic{
		ObjectHandle: audit.config.AKHandle.Handle(),
	}.Execute(sm.tpm)
	if err != nil {
		return nil, fmt.Errorf("read AK public: %w", err)
	}

	// Get the session audit digest
	getSessionAuditResp, err := tpm2.GetSessionAuditDigest{
		PrivacyAdminHandle: tpm2.TPMRHEndorsement,
		SignHandle: tpm2.NamedHandle{
			Handle: audit.config.AKHandle.Handle(),
			Name:   akReadPubResp.Name,
		},
		SessionHandle:  audit.session.Handle(),
		QualifyingData: tpm2.TPM2BData{Buffer: audit.config.QualifyingData},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: audit.config.HashAlg,
				},
			),
		},
	}.Execute(sm.tpm)
	if err != nil {
		return nil, fmt.Errorf("get session audit digest: %w", err)
	}

	// Parse the attestation structure
	attestation, err := getSessionAuditResp.AuditInfo.Contents()
	if err != nil {
		return nil, fmt.Errorf("parse attestation: %w", err)
	}

	return &AuditResult{
		Attestation: attestation,
		Signature:   &getSessionAuditResp.Signature,
	}, nil
}
