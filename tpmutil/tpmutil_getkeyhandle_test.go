// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/internal/utils/testutil"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestGetKeyHandle_NotFound(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	persistentHandle := tpm2.TPMHandle(0x81000099)

	_, err := tpmutil.GetPersistedKeyHandle(thetpm, tpmutil.GetPersistedKeyHandleConfig{
		Handle: tpmutil.NewHandle(persistentHandle),
	})
	if err == nil {
		t.Fatal("expected error when handle not found, got nil")
	}

	var handleErr *tpmutil.ErrHandleNotFound
	if !errors.As(err, &handleErr) {
		t.Fatalf("expected ErrHandleNotFound, got %T: %v", err, err)
	}

	if handleErr.Handle != persistentHandle {
		t.Errorf("expected handle 0x%x in error, got 0x%x", persistentHandle, handleErr.Handle)
	}
}

func TestGetKeyHandle_AlreadyPersisted(t *testing.T) {
	tests := []struct {
		name         string
		template     tpm2.TPMTPublic
		handle       tpmutil.Handle
		expectedType tpm2.TPMAlgID
	}{
		{
			name:         "RSA",
			template:     tpmutil.RSASRKTemplate,
			handle:       tpmutil.NewHandle(tpm2.TPMHandle(0x81000010)),
			expectedType: tpm2.TPMAlgRSA,
		},
		{
			name:         "ECC",
			template:     tpmutil.ECCSRKTemplate,
			handle:       tpmutil.NewHandle(tpm2.TPMHandle(0x81000011)),
			expectedType: tpm2.TPMAlgECC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thetpm := testutil.OpenSimulator(t)

			// Create a transient primary key
			primaryHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
				PrimaryHandle: tpm2.TPMRHOwner,
				Auth:          tpmutil.NoAuth,
				InPublic:      tt.template,
			})
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}
			defer primaryHandle.Close()

			// Persist it
			_, err = tpmutil.Persist(thetpm, tpmutil.PersistConfig{
				TransientHandle:  primaryHandle,
				PersistentHandle: tt.handle,
			})
			if err != nil {
				t.Fatalf("Persist failed: %v", err)
			}

			// Read the key back via GetKeyHandle
			handle, err := tpmutil.GetPersistedKeyHandle(thetpm, tpmutil.GetPersistedKeyHandleConfig{
				Handle: tt.handle,
			})
			if err != nil {
				t.Fatalf("GetKeyHandle failed: %v", err)
			}
			defer handle.Close()

			if handle.Handle() != tt.handle.Handle() {
				t.Errorf("expected handle 0x%x, got 0x%x", tt.handle.Handle(), handle.Handle())
			}

			// Verify the key type via ReadPublic
			if handle.Public().Type != tt.expectedType {
				t.Errorf("expected %v key type, got %v", tt.expectedType, handle.Public().Type)
			}
		})
	}
}

func TestGetKeyHandle_OrdinaryKey(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	srkHandle, err := tpmutil.GetSRKHandle(thetpm)
	if err != nil {
		t.Fatalf("GetSRKHandle failed: %v", err)
	}

	appKeyTemplate := tpmutil.MustApplicationKeyTemplate()
	childHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
		ParentHandle: srkHandle,
		InPublic:     appKeyTemplate,
	})
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	persistentHandle := tpmutil.NewHandle(tpm2.TPMHandle(0x81000020))
	_, err = tpmutil.Persist(thetpm, tpmutil.PersistConfig{
		TransientHandle:  childHandle,
		PersistentHandle: persistentHandle,
	})
	if err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	handle, err := tpmutil.GetPersistedKeyHandle(thetpm, tpmutil.GetPersistedKeyHandleConfig{
		Handle: persistentHandle,
	})
	if err != nil {
		t.Fatalf("GetPersistedKeyHandle failed: %v", err)
	}

	// Ensure the key can be used for signing
	msg := []byte("test message")
	result, err := tpmutil.Hash(thetpm, tpmutil.HashConfig{
		Hierarchy: tpm2.TPMRHOwner,
		HashAlg:   crypto.SHA256,
		Data:      msg,
	})
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	signature, err := tpmutil.Sign(thetpm, tpmutil.SignConfig{
		KeyHandle:  handle,
		Validation: result.Validation,
		SignerOpts: crypto.SHA256,
		Digest:     result.Digest,
	})
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	pubKey, err := tpmcrypto.PublicKey(handle.Public())
	if err != nil {
		t.Fatalf("PublicKey() failed: %v", err)
	}
	if !ecdsa.VerifyASN1(pubKey.(*ecdsa.PublicKey), result.Digest, signature) {
		t.Error("signature verification failed")
	}
}

func TestGetKeyHandle_ConfigValidation(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	tests := []struct {
		name    string
		cfg     []tpmutil.GetPersistedKeyHandleConfig
		wantErr bool
	}{
		{
			name:    "nil config (zero value)",
			cfg:     nil,
			wantErr: true,
		},
		{
			name: "transient handle rejected",
			cfg: []tpmutil.GetPersistedKeyHandleConfig{
				{Handle: tpmutil.NewHandle(tpm2.TPMHandle(0x80000001))},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tpmutil.GetPersistedKeyHandle(thetpm, tt.cfg...)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
