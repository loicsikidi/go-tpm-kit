// Copyright (c) 2025, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	tpmkit "github.com/loicsikidi/go-tpm-kit"
	"github.com/loicsikidi/go-tpm-kit/tpmtest"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestGetSKRHandle_CreateNew_RSA(t *testing.T) {
	thetpm := tpmtest.OpenSimulator(t)

	cfg := tpmutil.ParentConfig{
		KeyFamily: tpmutil.RSA,
	}
	srkHandle, err := tpmutil.GetSKRHandle(thetpm, cfg)
	if err != nil {
		t.Fatalf("GetSKRHandle() failed: %v", err)
	}

	if srkHandle.Handle() != tpmkit.SRKHandle {
		t.Errorf("Expected handle %v, got %v", tpmkit.SRKHandle, srkHandle.Handle())
	}

	// Verify the key is persistent
	readPub := tpm2.ReadPublic{
		ObjectHandle: tpmkit.SRKHandle,
	}
	rsp, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic() failed: %v", err)
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("Contents() failed: %v", err)
	}

	if pub.Type != tpm2.TPMAlgRSA {
		t.Errorf("Expected RSA key type, got %v", pub.Type)
	}
}

func TestGetSKRHandle_CreateNew_ECC(t *testing.T) {
	thetpm := tpmtest.OpenSimulator(t)

	cfg := tpmutil.ParentConfig{
		KeyFamily: tpmutil.ECC,
	}
	srkHandle, err := tpmutil.GetSKRHandle(thetpm, cfg)
	if err != nil {
		t.Fatalf("GetSKRHandle() failed: %v", err)
	}

	if srkHandle.Handle() != tpmkit.SRKHandle {
		t.Errorf("Expected handle %v, got %v", tpmkit.SRKHandle, srkHandle.Handle())
	}

	// Verify the key is persistent
	readPub := tpm2.ReadPublic{
		ObjectHandle: tpmkit.SRKHandle,
	}
	rsp, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic() failed: %v", err)
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("Contents() failed: %v", err)
	}

	if pub.Type != tpm2.TPMAlgECC {
		t.Errorf("Expected ECC key type, got %v", pub.Type)
	}
}

func TestGetSKRHandle_AlreadyPersisted_SKR(t *testing.T) {
	thetpm := tpmtest.OpenSimulator(t)

	// First, create and persist an RSA SRK
	cfg := tpmutil.ParentConfig{
		KeyFamily: tpmutil.RSA,
	}
	_, err := tpmutil.GetSKRHandle(thetpm, cfg)
	if err != nil {
		t.Fatalf("Initial GetSKRHandle() failed: %v", err)
	}

	// Now call GetSKRHandle but with ECC kty - it should find the existing SRK
	cfg2 := tpmutil.ParentConfig{
		KeyFamily: tpmutil.ECC,
	}
	srkHandle, err := tpmutil.GetSKRHandle(thetpm, cfg2)
	if err != nil {
		t.Fatalf("Second GetSKRHandle() failed: %v", err)
	}

	if srkHandle.Handle() != tpmkit.SRKHandle {
		t.Errorf("Expected handle %v, got %v", tpmkit.SRKHandle, srkHandle.Handle())
	}

	// Verify the key can be read
	readPub := tpm2.ReadPublic{
		ObjectHandle: srkHandle.Handle(),
	}
	rsp, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic() failed: %v", err)
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("Contents() failed: %v", err)
	}

	if pub.Type != tpm2.TPMAlgRSA {
		t.Errorf("Expected RSA key type, got %v", pub.Type)
	}
}

func TestGetSKRHandle_CustomOwnerPassword(t *testing.T) {
	thetpm := tpmtest.OpenSimulator(t)

	// Set a custom owner hierarchy password
	ownerPassword := []byte("custom-owner-password")
	hierChange := tpm2.HierarchyChangeAuth{
		AuthHandle: tpmutil.ToAuthHandle(tpmutil.NewHandle(tpm2.TPMRHOwner), tpmutil.NoAuth), // Default empty password
		NewAuth: tpm2.TPM2BAuth{
			Buffer: ownerPassword,
		},
	}
	_, err := hierChange.Execute(thetpm)
	if err != nil {
		t.Fatalf("HierarchyChangeAuth() failed: %v", err)
	}

	// Try to get SRK with the custom password
	cfg := tpmutil.ParentConfig{
		KeyFamily: tpmutil.ECC,
		Auth:      tpm2.PasswordAuth(ownerPassword),
	}
	srkHandle, err := tpmutil.GetSKRHandle(thetpm, cfg)
	if err != nil {
		t.Fatalf("GetSKRHandle() with custom password failed: %v", err)
	}

	if srkHandle.Handle() != tpmkit.SRKHandle {
		t.Errorf("Expected handle %v, got %v", tpmkit.SRKHandle, srkHandle.Handle())
	}
}

func TestGetSKRHandle_NonStandardHandle(t *testing.T) {
	thetpm := tpmtest.OpenSimulator(t)

	// Use a non-standard persistent handle
	customHandle := tpm2.TPMHandle(0x81000010)

	cfg := tpmutil.ParentConfig{
		KeyFamily: tpmutil.ECC,
		Handle:    tpmutil.NewHandle(customHandle),
	}
	srkHandle, err := tpmutil.GetSKRHandle(thetpm, cfg)
	if err != nil {
		t.Fatalf("GetSKRHandle() with custom handle failed: %v", err)
	}

	if srkHandle.Handle() != customHandle {
		t.Errorf("Expected handle %v, got %v", customHandle, srkHandle.Handle())
	}

	// Verify the key is persisted at the custom handle
	readPub := tpm2.ReadPublic{
		ObjectHandle: customHandle,
	}
	rsp, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic() failed: %v", err)
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("Contents() failed: %v", err)
	}

	if pub.Type != tpm2.TPMAlgECC {
		t.Errorf("Expected ECC key type, got %v", pub.Type)
	}
}
