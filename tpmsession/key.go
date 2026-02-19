// Copyright (c) 2025, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmsession

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
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
// SessionKey can be marshaled using [SessionKey.Marshal] and unmarshaled using [ParseSessionKey].
type SessionKey struct {
	// SessionType specifies whether this is a bound or salted session.
	// Must be either [BoundSession] or [SaltedSession].
	SessionType SessionType

	// Handle is the persistent handle of the TPM object (e.g., 0x81000001 for SRK).
	//
	// IMPORTANT: Must be a persistent handle (range 0x81000000-0x81FFFFFF).
	// Transient handles are not supported as they don't survive TPM resets,
	// which would break the trust model of storing and reusing SessionKeys.
	//
	// This constraint is enforced in [NewSessionManager], which will return
	// [ErrInvalidHandleType] if the handle is not persistent.
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

// Marshal serializes the SessionKey to a blob for storage.
//
// The returned blob can be saved to disk and later loaded with [ReadSessionKey]
// or [ParseSessionKey]. The blob should be protected with appropriate file
// permissions (e.g., 0600).
//
// For salted sessions, this includes the Public area. For bound sessions,
// only the handle and name are stored (the auth value is never persisted).
//
// Returns [ErrMissingTPMPublic] if this is a SaltedSession without a Public area.
func (sk SessionKey) Marshal() ([]byte, error) {
	j := sessionKeyJSON{
		SessionType: sk.SessionType,
		Handle:      uint32(sk.Handle),
		Name:        tpm2.Marshal(sk.Name),
	}

	if sk.SessionType == SaltedSession && sk.Public == nil {
		return nil, ErrMissingTPMPublic
	}

	if sk.Public != nil {
		j.Public = tpm2.Marshal(sk.Public)
	}

	return json.Marshal(j)
}

// ParseSessionKey deserializes a [SessionKey] from a blob.
//
// This is the lower-level function used when you already have the serialized
// data in memory. For reading from a file, use [ReadSessionKey] instead.
//
// The blob should be created by [SessionKey.Marshal].
func ParseSessionKey(opaqueBlob []byte) (*SessionKey, error) {
	var sk SessionKey
	if err := sk.unmarshal(opaqueBlob); err != nil {
		return nil, fmt.Errorf("unmarshal session key: %w", err)
	}
	return &sk, nil
}

// ReadSessionKey reads and deserializes a [SessionKey] from a file.
//
// This is a convenience function that combines reading a file and parsing
// the SessionKey. It's the typical way to load a SessionKey during the
// runtime phase.
//
// Example:
//
//	key, err := tpmsession.ReadSessionKey("trusted-session-key.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	sm, err := tpmsession.NewSessionManager(tpm, key)
func ReadSessionKey(path string) (*SessionKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	return ParseSessionKey(data)
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

// CheckAndSetDefault validates the SessionKey structure.
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

	if sk.SessionType == SaltedSession {
		if sk.Public == nil {
			return ErrMissingTPMPublic
		}

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

// CreateSessionKey creates a new [SessionKey] by reading metadata from the TPM.
//
// This function is typically used during the onboarding phase to create a SessionKey
// from a trusted TPM object. It validates that the handle exists, reads the object's
// Name and Public area, and constructs a properly initialized SessionKey.
//
// For [BoundSession], only the Handle and Name are populated.
// For [SaltedSession], Handle, Name, and Public are all populated.
//
// The handle must be a persistent TPM handle (TPMHTPersistent range).
//
// Example usage during onboarding:
//
//	// Create a session key for a salted session with the SRK
//	key, err := tpmsession.CreateSessionKey(tpm, tpmsession.SaltedSession, 0x81000001)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Store it for later use
//	blob, err := key.Marshal()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	err = os.WriteFile("session-key.json", blob, 0600)
func CreateSessionKey(tpm transport.TPM, sessionType SessionType, handle tpm2.TPMHandle) (*SessionKey, error) {
	if sessionType != BoundSession && sessionType != SaltedSession {
		return nil, fmt.Errorf("invalid session type: %v", sessionType)
	}

	// Validate handle type
	h := tpmutil.NewHandle(handle)
	if h.Type() != tpmutil.PersistentHandle {
		return nil, fmt.Errorf("%w: got %v (0x%08X)", ErrInvalidHandleType, h.Type(), handle)
	}

	// Read public area to get Name
	readPubResp, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("read public from TPM: %w", err)
	}

	sk := &SessionKey{
		SessionType: sessionType,
		Handle:      handle,
		Name:        readPubResp.Name,
	}

	// For salted sessions, also store the Public area
	if sessionType == SaltedSession {
		sk.Public = &readPubResp.OutPublic
	}

	// Validate the key before returning
	if err := sk.CheckAndSetDefault(); err != nil {
		return nil, fmt.Errorf("validate session key: %w", err)
	}

	return sk, nil
}
