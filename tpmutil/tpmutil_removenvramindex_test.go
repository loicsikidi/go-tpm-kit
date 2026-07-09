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

func TestRemoveNVRAMIndex(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	nvIndex := tpm2.TPMHandle(0x01500100)

	err := tpmutil.NVWrite(thetpm, tpmutil.NVWriteConfig{
		Index:     nvIndex,
		Data:      []byte("test data"),
		Hierarchy: tpm2.TPMRHOwner,
	})
	if err != nil {
		t.Fatalf("NVWrite failed: %v", err)
	}

	err = tpmutil.RemoveNVRAMIndex(thetpm, tpmutil.RemoveNVRAMIndexConfig{
		Index:     nvIndex,
		Hierarchy: tpm2.TPMRHOwner,
	})
	if err != nil {
		t.Fatalf("RemoveNVRAMIndex failed: %v", err)
	}

	_, err = tpm2.NVReadPublic{
		NVIndex: nvIndex,
	}.Execute(thetpm)
	if !errors.Is(err, tpm2.TPMRCHandle) {
		t.Fatalf("Expected TPMRCHandle error after removal, got: %v", err)
	}
}

func TestRemoveNVRAMIndex_Idempotent(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	nvIndex := tpm2.TPMHandle(0x01500100)

	err := tpmutil.RemoveNVRAMIndex(thetpm, tpmutil.RemoveNVRAMIndexConfig{
		Index:     nvIndex,
		Hierarchy: tpm2.TPMRHOwner,
	})
	if err != nil {
		t.Fatalf("RemoveNVRAMIndex on non-existent NV index should return nil, got: %v", err)
	}
}

func TestRemoveNVRAMIndex_MissingIndex(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	err := tpmutil.RemoveNVRAMIndex(thetpm, tpmutil.RemoveNVRAMIndexConfig{})
	if err == nil {
		t.Fatal("Expected error when Index is 0, got nil")
	}
}

func TestRemoveNVRAMIndex_MultiIndex(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	baseIndex := tpm2.TPMHandle(0x01500100)

	// Write data across 3 consecutive indices
	data := make([]byte, 4196)
	err := tpmutil.NVWrite(thetpm, tpmutil.NVWriteConfig{
		Index:      baseIndex,
		Data:       data,
		MultiIndex: true,
	})
	if err != nil {
		t.Fatalf("NVWrite failed: %v", err)
	}

	// Verify all 3 indices exist
	for i := range 3 {
		currentIndex := tpm2.TPMHandle(uint32(baseIndex) + uint32(i))
		_, err := tpm2.NVReadPublic{
			NVIndex: currentIndex,
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("Expected index 0x%x to exist after write, got error: %v", currentIndex, err)
		}
	}

	// Remove all consecutive indices
	err = tpmutil.RemoveNVRAMIndex(thetpm, tpmutil.RemoveNVRAMIndexConfig{
		Index:      baseIndex,
		MultiIndex: true,
	})
	if err != nil {
		t.Fatalf("RemoveNVRAMIndex with MultiIndex failed: %v", err)
	}

	// Verify all indices are removed
	for i := range 3 {
		currentIndex := tpm2.TPMHandle(uint32(baseIndex) + uint32(i))
		_, err := tpm2.NVReadPublic{
			NVIndex: currentIndex,
		}.Execute(thetpm)
		if !errors.Is(err, tpm2.TPMRCHandle) {
			t.Fatalf("Expected TPMRCHandle error for index 0x%x after removal, got: %v", currentIndex, err)
		}
	}
}

func TestRemoveNVRAMIndex_MultiIndexWithGap(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	baseIndex := tpm2.TPMHandle(0x01500100)

	// Create 3 consecutive indices (0x01500100, 0x01500101, 0x01500102)
	for i := range 3 {
		currentIndex := tpm2.TPMHandle(uint32(baseIndex) + uint32(i))
		err := tpmutil.NVWrite(thetpm, tpmutil.NVWriteConfig{
			Index:     currentIndex,
			Data:      []byte("test data"),
			Hierarchy: tpm2.TPMRHOwner,
		})
		if err != nil {
			t.Fatalf("NVWrite failed for index 0x%x: %v", currentIndex, err)
		}
	}

	// Create non-consecutive index (0x01500105)
	gapIndex := tpm2.TPMHandle(0x01500105)
	err := tpmutil.NVWrite(thetpm, tpmutil.NVWriteConfig{
		Index:     gapIndex,
		Data:      []byte("gap data"),
		Hierarchy: tpm2.TPMRHOwner,
	})
	if err != nil {
		t.Fatalf("NVWrite failed for gap index 0x%x: %v", gapIndex, err)
	}

	// Remove consecutive indices with MultiIndex
	err = tpmutil.RemoveNVRAMIndex(thetpm, tpmutil.RemoveNVRAMIndexConfig{
		Index:      baseIndex,
		MultiIndex: true,
	})
	if err != nil {
		t.Fatalf("RemoveNVRAMIndex with MultiIndex failed: %v", err)
	}

	// Verify the 3 consecutive indices are removed
	for i := range 3 {
		currentIndex := tpm2.TPMHandle(uint32(baseIndex) + uint32(i))
		_, err := tpm2.NVReadPublic{
			NVIndex: currentIndex,
		}.Execute(thetpm)
		if !errors.Is(err, tpm2.TPMRCHandle) {
			t.Fatalf("Expected TPMRCHandle error for index 0x%x after removal, got: %v", currentIndex, err)
		}
	}

	// Verify the gap index still exists
	_, err = tpm2.NVReadPublic{
		NVIndex: gapIndex,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("Expected gap index 0x%x to still exist, got error: %v", gapIndex, err)
	}
}
