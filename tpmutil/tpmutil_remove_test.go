// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil_test

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/internal/utils/testutil"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestRemove(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	targetHandle := tpmutil.NewHandle(tpm2.TPMHandle(0x81000100))

	transientHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpmutil.ECCSRKTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer transientHandle.Close() //nolint:errcheck

	_, err = tpmutil.Persist(thetpm, tpmutil.PersistConfig{
		TransientHandle:  transientHandle,
		PersistentHandle: targetHandle,
	})
	if err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	err = tpmutil.Remove(thetpm, tpmutil.RemoveConfig{
		Handle: targetHandle,
	})
	if err != nil {
		t.Fatalf("RemoveKey failed: %v", err)
	}

	_, err = tpm2.ReadPublic{
		ObjectHandle: targetHandle.Handle(),
	}.Execute(thetpm)
	if !errors.Is(err, tpm2.TPMRCHandle) {
		t.Fatalf("Expected TPMRCHandle error after removal, got: %v", err)
	}
}

func TestRemove_Idempotent(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	targetHandle := tpmutil.NewHandle(tpm2.TPMHandle(0x81000100))

	err := tpmutil.Remove(thetpm, tpmutil.RemoveConfig{
		Handle: targetHandle,
	})
	if err != nil {
		t.Fatalf("RemoveKey on non-existent key should return nil, got: %v", err)
	}
}

func TestRemove_MissingHandle(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	err := tpmutil.Remove(thetpm, tpmutil.RemoveConfig{})
	if err == nil {
		t.Fatal("Expected error when Handle is nil, got nil")
	}
}

func TestRemove_InvalidHandleType(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	err := tpmutil.Remove(thetpm, tpmutil.RemoveConfig{
		Handle: tpmutil.NewHandle(tpm2.TPMHandle(0x80000000)),
	})
	if err == nil {
		t.Fatal("Expected error when Handle is not persistent, got nil")
	}
}

func TestRemove_CertChainWithoutCertHandle(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	targetHandle := tpmutil.NewHandle(tpm2.TPMHandle(0x81000100))
	certChainHandle := tpm2.TPMHandle(0x01C00010)

	err := tpmutil.Remove(thetpm, tpmutil.RemoveConfig{
		Handle:          targetHandle,
		CertChainHandle: certChainHandle,
	})
	if err == nil {
		t.Fatal("Expected error when CertChainHandle is used without CertHandle")
	}
}

func TestRemove_WithCertHandles(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	targetHandle := tpmutil.NewHandle(tpm2.TPMHandle(0x81000100))
	certHandle := tpm2.TPMHandle(0x01C00002)
	certChainHandle := tpm2.TPMHandle(0x01C00010)

	// Create and persist a primary key
	transientHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpmutil.ECCSRKTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer transientHandle.Close() //nolint:errcheck

	_, err = tpmutil.Persist(thetpm, tpmutil.PersistConfig{
		TransientHandle:  transientHandle,
		PersistentHandle: targetHandle,
	})
	if err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	// Create certificate index
	err = tpmutil.NVWrite(thetpm, tpmutil.NVWriteConfig{
		Index:     certHandle,
		Data:      []byte("certificate"),
		Hierarchy: tpm2.TPMRHOwner,
	})
	if err != nil {
		t.Fatalf("NVWrite failed for cert index: %v", err)
	}

	// Create certificate chain indices (3 consecutive)
	for i := range 3 {
		currentIndex := tpm2.TPMHandle(uint32(certChainHandle) + uint32(i))
		err := tpmutil.NVWrite(thetpm, tpmutil.NVWriteConfig{
			Index:     currentIndex,
			Data:      []byte("cert chain"),
			Hierarchy: tpm2.TPMRHOwner,
		})
		if err != nil {
			t.Fatalf("NVWrite failed for cert chain index 0x%x: %v", currentIndex, err)
		}
	}

	// Remove all
	err = tpmutil.Remove(thetpm, tpmutil.RemoveConfig{
		Handle:          targetHandle,
		CertHandle:      certHandle,
		CertChainHandle: certChainHandle,
	})
	if err != nil {
		t.Fatalf("Remove failed: %v", err)
	}

	// Verify persistent handle is removed
	_, err = tpm2.ReadPublic{
		ObjectHandle: targetHandle.Handle(),
	}.Execute(thetpm)
	if !errors.Is(err, tpm2.TPMRCHandle) {
		t.Fatalf("Expected TPMRCHandle error for persistent handle after removal, got: %v", err)
	}

	// Verify certificate index is removed
	_, err = tpm2.NVReadPublic{
		NVIndex: certHandle,
	}.Execute(thetpm)
	if !errors.Is(err, tpm2.TPMRCHandle) {
		t.Fatalf("Expected TPMRCHandle error for cert index after removal, got: %v", err)
	}

	// Verify all certificate chain indices are removed
	for i := range 3 {
		currentIndex := tpm2.TPMHandle(uint32(certChainHandle) + uint32(i))
		_, err := tpm2.NVReadPublic{
			NVIndex: currentIndex,
		}.Execute(thetpm)
		if !errors.Is(err, tpm2.TPMRCHandle) {
			t.Fatalf("Expected TPMRCHandle error for cert chain index 0x%x after removal, got: %v", currentIndex, err)
		}
	}
}
