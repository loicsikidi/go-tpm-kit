// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmtest"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestCreateResult_Marshal(t *testing.T) {
	thetpm := tpmtest.OpenSimulator(t)

	// Create a primary key to use as parent
	eccTemplate := tpmutil.ECCSRKTemplate
	parentHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      eccTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary() failed: %v", err)
	}
	defer parentHandle.Close()

	// Create a child key and get result
	result, err := tpmutil.CreateWithResult(thetpm, tpmutil.CreateConfig{
		ParentHandle: parentHandle,
		InPublic:     eccTemplate,
	})
	if err != nil {
		t.Fatalf("CreateWithResult() failed: %v", err)
	}

	t.Run("Marshal to JSON (default)", func(t *testing.T) {
		data, err := result.Marshal()
		if err != nil {
			t.Fatalf("Marshal() failed: %v", err)
		}

		if len(data) == 0 {
			t.Error("Expected non-empty marshaled data")
		}

		var unmarshaled map[string]any
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Errorf("Failed to unmarshal JSON: %v", err)
		}
	})

	t.Run("Marshal to JSON (explicit)", func(t *testing.T) {
		data, err := result.Marshal(tpmutil.JSON)
		if err != nil {
			t.Fatalf("Marshal(JSON) failed: %v", err)
		}

		if len(data) == 0 {
			t.Error("Expected non-empty marshaled data")
		}
	})

	t.Run("Marshal to KeyFiles (not implemented)", func(t *testing.T) {
		_, err := result.Marshal(tpmutil.KeyFiles)
		if err == nil {
			t.Error("Expected error for KeyFiles target, got nil")
		}

		expectedMsg := "unsupported operation"
		if err.Error() != expectedMsg {
			t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
		}
	})
}

func TestLoadCreateResult(t *testing.T) {
	thetpm := tpmtest.OpenSimulator(t)

	// Create a primary key to use as parent
	eccTemplate := tpmutil.ECCSRKTemplate
	parentHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      eccTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary() failed: %v", err)
	}
	defer parentHandle.Close()

	// Create a child key and get result
	originalResult, err := tpmutil.CreateWithResult(thetpm, tpmutil.CreateConfig{
		ParentHandle: parentHandle,
		InPublic:     eccTemplate,
	})
	if err != nil {
		t.Fatalf("CreateWithResult() failed: %v", err)
	}

	t.Run("Marshal and Load round trip", func(t *testing.T) {
		// Create temp file
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "key.json")

		// Marshal to file
		data, err := originalResult.Marshal()
		if err != nil {
			t.Fatalf("Marshal() failed: %v", err)
		}

		if err := os.WriteFile(filePath, data, 0644); err != nil {
			t.Fatalf("WriteFile() failed: %v", err)
		}

		// Load from file
		loadedResult, err := tpmutil.LoadCreateResult(filePath)
		if err != nil {
			t.Fatalf("LoadCreateResult() failed: %v", err)
		}

		// Compare OutPrivate
		if len(loadedResult.OutPrivate.Buffer) != len(originalResult.OutPrivate.Buffer) {
			t.Errorf("OutPrivate buffer length mismatch: got %d, want %d",
				len(loadedResult.OutPrivate.Buffer), len(originalResult.OutPrivate.Buffer))
		}

		// Compare OutPublic
		if len(loadedResult.OutPublic.Bytes()) != len(originalResult.OutPublic.Bytes()) {
			t.Errorf("OutPublic bytes length mismatch: got %d, want %d",
				len(loadedResult.OutPublic.Bytes()), len(originalResult.OutPublic.Bytes()))
		}

		// Verify we can load the key using the loaded result
		keyHandle, err := tpmutil.Load(thetpm, tpmutil.LoadConfig{
			ParentHandle: parentHandle,
			InPrivate:    loadedResult.OutPrivate,
			InPublic:     loadedResult.OutPublic,
		})
		if err != nil {
			t.Fatalf("Load() with loaded result failed: %v", err)
		}
		defer keyHandle.Close()

		if keyHandle.Type() != tpmutil.TransientHandle {
			t.Errorf("Expected handle type Transient, got %s", keyHandle.Type())
		}

		public := keyHandle.Public()
		if public.Type != tpm2.TPMAlgECC {
			t.Errorf("Expected public type ECC, got %v", public.Type)
		}
	})

	t.Run("Load non-existent file", func(t *testing.T) {
		_, err := tpmutil.LoadCreateResult("/nonexistent/path/key.json")
		if err == nil {
			t.Error("Expected error for non-existent file, got nil")
		}
	})

	t.Run("Load invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "invalid.json")

		if err := os.WriteFile(filePath, []byte("not valid json"), 0644); err != nil {
			t.Fatalf("WriteFile() failed: %v", err)
		}

		_, err := tpmutil.LoadCreateResult(filePath)
		if err == nil {
			t.Error("Expected error for invalid JSON, got nil")
		}
	})
}

func TestCreatePrimaryResult_Marshal(t *testing.T) {
	thetpm := tpmtest.OpenSimulator(t)

	// Create a primary key
	eccTemplate := tpmutil.ECCSRKTemplate
	result, closer, err := tpmutil.CreatePrimaryWithResult(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      eccTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimaryWithResult() failed: %v", err)
	}
	defer closer()

	t.Run("Marshal to JSON (default)", func(t *testing.T) {
		data, err := result.Marshal()
		if err != nil {
			t.Fatalf("Marshal() failed: %v", err)
		}

		if len(data) == 0 {
			t.Error("Expected non-empty marshaled data")
		}

		// Verify it's valid JSON by unmarshaling
		var unmarshaled map[string]any
		if err := json.Unmarshal(data, &unmarshaled); err != nil {
			t.Errorf("Failed to unmarshal JSON: %v", err)
		}
	})

	t.Run("Marshal to JSON (explicit)", func(t *testing.T) {
		data, err := result.Marshal(tpmutil.JSON)
		if err != nil {
			t.Fatalf("Marshal(JSON) failed: %v", err)
		}

		if len(data) == 0 {
			t.Error("Expected non-empty marshaled data")
		}
	})

	t.Run("Marshal to KeyFiles (not implemented)", func(t *testing.T) {
		_, err := result.Marshal(tpmutil.KeyFiles)
		if err == nil {
			t.Error("Expected error for KeyFiles target, got nil")
		}

		expectedMsg := "unsupported operation"
		if err.Error() != expectedMsg {
			t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
		}
	})
}

func TestLoadCreatePrimaryResult(t *testing.T) {
	thetpm := tpmtest.OpenSimulator(t)

	// Create a primary key
	eccTemplate := tpmutil.ECCSRKTemplate
	originalResult, closer, err := tpmutil.CreatePrimaryWithResult(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      eccTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimaryWithResult() failed: %v", err)
	}
	defer closer()

	t.Run("Marshal and Load round trip", func(t *testing.T) {
		// Create temp file
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "primary-key.json")

		// Marshal to file
		data, err := originalResult.Marshal()
		if err != nil {
			t.Fatalf("Marshal() failed: %v", err)
		}

		if err := os.WriteFile(filePath, data, 0644); err != nil {
			t.Fatalf("WriteFile() failed: %v", err)
		}

		// Load from file
		loadedResult, err := tpmutil.LoadCreatePrimaryResult(filePath)
		if err != nil {
			t.Fatalf("LoadCreatePrimaryResult() failed: %v", err)
		}

		// Verify ObjectHandle is 0 (not marshaled)
		if loadedResult.ObjectHandle != 0 {
			t.Errorf("Expected ObjectHandle to be 0, got %v", loadedResult.ObjectHandle)
		}

		// Compare OutPublic
		if len(loadedResult.OutPublic.Bytes()) != len(originalResult.OutPublic.Bytes()) {
			t.Errorf("OutPublic bytes length mismatch: got %d, want %d",
				len(loadedResult.OutPublic.Bytes()), len(originalResult.OutPublic.Bytes()))
		}

		// Compare Name
		if len(loadedResult.Name.Buffer) != len(originalResult.Name.Buffer) {
			t.Errorf("Name buffer length mismatch: got %d, want %d",
				len(loadedResult.Name.Buffer), len(originalResult.Name.Buffer))
		}

		// Verify the public key type
		public, err := loadedResult.OutPublic.Contents()
		if err != nil {
			t.Fatalf("OutPublic.Contents() failed: %v", err)
		}

		if public.Type != tpm2.TPMAlgECC {
			t.Errorf("Expected public type ECC, got %v", public.Type)
		}
	})

	t.Run("Load non-existent file", func(t *testing.T) {
		_, err := tpmutil.LoadCreatePrimaryResult("/nonexistent/path/primary-key.json")
		if err == nil {
			t.Error("Expected error for non-existent file, got nil")
		}
	})

	t.Run("Load invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		filePath := filepath.Join(tmpDir, "invalid.json")

		if err := os.WriteFile(filePath, []byte("not valid json"), 0644); err != nil {
			t.Fatalf("WriteFile() failed: %v", err)
		}

		_, err := tpmutil.LoadCreatePrimaryResult(filePath)
		if err == nil {
			t.Error("Expected error for invalid JSON, got nil")
		}
	})
}
