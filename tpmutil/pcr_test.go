// Copyright (c) 2025, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil_test

import (
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestToTPMLPCRSelection(t *testing.T) {
	tests := []struct {
		name     string
		pcrs     []uint
		bank     tpm2.TPMIAlgHash
		wantZero bool // expect zero/empty result
	}{
		{
			name:     "empty PCRs",
			pcrs:     []uint{},
			bank:     tpm2.TPMAlgSHA256,
			wantZero: true,
		},
		{
			name: "single PCR",
			pcrs: []uint{0},
			bank: tpm2.TPMAlgSHA256,
		},
		{
			name: "multiple PCRs",
			pcrs: []uint{0, 1, 2, 7},
			bank: tpm2.TPMAlgSHA256,
		},
		{
			name: "all standard PCRs",
			pcrs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
			bank: tpm2.TPMAlgSHA256,
		},
		{
			name: "SHA1 bank",
			pcrs: []uint{0, 1, 2},
			bank: tpm2.TPMAlgSHA1,
		},
		{
			name: "SHA384 bank",
			pcrs: []uint{0, 1, 2},
			bank: tpm2.TPMAlgSHA384,
		},
		{
			name: "SHA512 bank",
			pcrs: []uint{0, 1, 2},
			bank: tpm2.TPMAlgSHA512,
		},
		{
			name: "duplicated PCRs",
			pcrs: []uint{0, 1, 1, 2, 2, 2},
			bank: tpm2.TPMAlgSHA256,
		},
		{
			name: "unsorted PCRs",
			pcrs: []uint{7, 2, 15, 0, 10},
			bank: tpm2.TPMAlgSHA256,
		},
		{
			name:     "PCR beyond max index (should be filtered)",
			pcrs:     []uint{24, 25, 100},
			bank:     tpm2.TPMAlgSHA256,
			wantZero: true, // all PCRs filtered out
		},
		{
			name: "PCR at max index (should be accepted)",
			pcrs: []uint{23},
			bank: tpm2.TPMAlgSHA256,
		},
		{
			name: "mixed valid and invalid PCRs",
			pcrs: []uint{0, 1, 24, 2, 50},
			bank: tpm2.TPMAlgSHA256,
		},
		{
			name: "invalid hash algorithm defaults to SHA256",
			pcrs: []uint{0, 1, 2},
			bank: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tpmutil.ToTPMLPCRSelection(tt.pcrs, tt.bank)

			if tt.wantZero {
				if len(result.PCRSelections) != 0 {
					t.Errorf("Expected empty PCRSelections for %s, got %d", tt.name, len(result.PCRSelections))
				}
				return
			}

			if len(result.PCRSelections) == 0 {
				t.Errorf("Expected non-empty PCRSelections for %s", tt.name)
				return
			}

			if len(result.PCRSelections) != 1 {
				t.Errorf("Expected exactly one PCRSelection, got %d", len(result.PCRSelections))
				return
			}

			// Check hash algorithm (should be SHA256 if bank was 0)
			expectedHash := tt.bank
			if expectedHash == 0 {
				expectedHash = tpm2.TPMAlgSHA256
			}
			if result.PCRSelections[0].Hash != expectedHash {
				t.Errorf("Hash algorithm should match (or default to SHA256): expected %v, got %v", expectedHash, result.PCRSelections[0].Hash)
			}

			// Round-trip test: convert back to PCR list
			gotPCRs := tpmutil.PCRSelectToPCRs(result.PCRSelections[0].PCRSelect)

			// For valid cases, check that we can recover the PCRs
			// Note: duplicates will be removed and order may change
			if len(tt.pcrs) > 0 && !tt.wantZero {
				t.Logf("Input PCRs: %v, Got PCRs: %v", tt.pcrs, gotPCRs)
				// At minimum, we should get back some PCRs
				if len(gotPCRs) == 0 {
					t.Error("Round-trip should return PCRs")
				}

				// Verify all returned PCRs are within valid range
				for _, pcr := range gotPCRs {
					if pcr > uint(tpmutil.MaxPCRIndex) {
						t.Errorf("All returned PCRs should be within MaxPCRIndex (%d), got %d", tpmutil.MaxPCRIndex, pcr)
					}
				}
			}
		})
	}
}

func TestPCRSelectToPCRs(t *testing.T) {
	var empty []uint // empty slice
	tests := []struct {
		name string
		arg  []uint
	}{
		{"empty", empty},
		{"simple", []uint{0, 1, 2}},
		{"all pcr", []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}},
		{"odd", []uint{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23}},
		{"even", []uint{0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22}},
		{"debug", []uint{15}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tpmutil.PCRSelectToPCRs(tpm2.PCClientCompatible.PCRs(tt.arg...))
			if !reflect.DeepEqual(tt.arg, got) {
				t.Errorf("PCRSelectToPCRs should return the same PCRs as input: expected %v, got %v", tt.arg, got)
			}
		})
	}
}

func TestToTPMLPCRSelection_Filtering(t *testing.T) {
	tests := []struct {
		name        string
		inputPCRs   []uint
		expectedOut []uint
		bank        tpm2.TPMIAlgHash
	}{
		{
			name:        "filter out invalid PCRs",
			inputPCRs:   []uint{0, 1, 24, 2, 50},
			expectedOut: []uint{0, 1, 2},
			bank:        tpm2.TPMAlgSHA256,
		},
		{
			name:        "accept PCR at max index",
			inputPCRs:   []uint{23},
			expectedOut: []uint{23},
			bank:        tpm2.TPMAlgSHA256,
		},
		{
			name:        "all invalid PCRs return empty",
			inputPCRs:   []uint{24, 25, 100},
			expectedOut: nil,
			bank:        tpm2.TPMAlgSHA256,
		},
		{
			name:        "deduplicate and sort",
			inputPCRs:   []uint{5, 1, 5, 3, 1},
			expectedOut: []uint{1, 3, 5},
			bank:        tpm2.TPMAlgSHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tpmutil.ToTPMLPCRSelection(tt.inputPCRs, tt.bank)

			if tt.expectedOut == nil {
				if len(result.PCRSelections) != 0 {
					t.Errorf("Expected empty PCRSelections, got %d", len(result.PCRSelections))
				}
				return
			}

			if len(result.PCRSelections) != 1 {
				t.Errorf("Expected exactly one PCRSelection, got %d", len(result.PCRSelections))
				return
			}

			gotPCRs := tpmutil.PCRSelectToPCRs(result.PCRSelections[0].PCRSelect)
			if !reflect.DeepEqual(tt.expectedOut, gotPCRs) {
				t.Errorf("Should filter, deduplicate, and sort PCRs correctly: expected %v, got %v", tt.expectedOut, gotPCRs)
			}
		})
	}
}

func TestToTPMLPCRSelection_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		pcrs []uint
		bank tpm2.TPMIAlgHash
	}{
		{
			name: "simple round-trip",
			pcrs: []uint{0, 1, 2},
			bank: tpm2.TPMAlgSHA256,
		},
		{
			name: "all PCRs round-trip",
			pcrs: []uint{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
			bank: tpm2.TPMAlgSHA256,
		},
		{
			name: "sparse PCRs round-trip",
			pcrs: []uint{0, 7, 15, 23},
			bank: tpm2.TPMAlgSHA1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to TPMLPCRSelection
			selection := tpmutil.ToTPMLPCRSelection(tt.pcrs, tt.bank)

			// Convert back to PCR list
			gotPCRs := tpmutil.PCRSelectToPCRs(selection.PCRSelections[0].PCRSelect)

			// Should match original (order and dedup handled by PCClientCompatible)
			if !reflect.DeepEqual(tt.pcrs, gotPCRs) {
				t.Errorf("Round-trip should preserve PCRs: expected %v, got %v", tt.pcrs, gotPCRs)
			}
		})
	}
}
