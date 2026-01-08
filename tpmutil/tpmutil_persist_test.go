package tpmutil_test

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/internal/utils/testutil"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestPersist(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	targetHandle := tpmutil.NewHandle(tpm2.TPMHandle(0x81000100))

	// Create a transient primary key
	transientHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpmutil.ECCSRKTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer transientHandle.Close() //nolint:errcheck

	// Persist the transient key
	persistentHandle, err := tpmutil.Persist(thetpm, tpmutil.PersistConfig{
		TransientHandle:  transientHandle,
		PersistentHandle: targetHandle,
		Hierarchy:        tpm2.TPMRHOwner,
	})
	if err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	// Verify the persistent handle exists
	readPublicRsp, err := tpm2.ReadPublic{
		ObjectHandle: persistentHandle.Handle(),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	// Verify the names match
	if !bytes.Equal(readPublicRsp.Name.Buffer, transientHandle.Name().Buffer) {
		t.Errorf("Name mismatch: got %v, want %v", readPublicRsp.Name, transientHandle.Name())
	}
}

func TestPersist_DefaultHierarchy(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	targetHandle := tpmutil.NewHandle(tpm2.TPMHandle(0x81000101))

	// Create a transient primary key
	transientHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpmutil.ECCSRKTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer transientHandle.Close() //nolint:errcheck

	// Persist with default hierarchy (should be TPMRHOwner)
	persistentHandle, err := tpmutil.Persist(thetpm, tpmutil.PersistConfig{
		TransientHandle:  transientHandle,
		PersistentHandle: targetHandle,
	})
	if err != nil {
		t.Fatalf("Persist failed: %v", err)
	}

	// Verify it was persisted
	_, err = tpm2.ReadPublic{
		ObjectHandle: persistentHandle.Handle(),
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}
}

func TestPersist_InvalidTransientHandle(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	// Try to persist with a persistent handle (should fail)
	_, err := tpmutil.Persist(thetpm, tpmutil.PersistConfig{
		TransientHandle:  tpmutil.NewHandle(tpm2.TPMHandle(0x81000000)),
		PersistentHandle: tpmutil.NewHandle(tpm2.TPMHandle(0x81000100)),
	})
	if err == nil {
		t.Fatal("Expected error when using non-transient handle, got nil")
	}
}

func TestPersist_InvalidPersistentHandle(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	// Create a transient primary key
	transientHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpmutil.ECCSRKTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer transientHandle.Close() //nolint:errcheck

	// Try to persist to a transient handle (should fail)
	_, err = tpmutil.Persist(thetpm, tpmutil.PersistConfig{
		TransientHandle:  transientHandle,
		PersistentHandle: tpmutil.NewHandle(tpm2.TPMHandle(0x80000000)),
	})
	if err == nil {
		t.Fatal("Expected error when using non-persistent target handle, got nil")
	}
}

func TestPersist_MissingTransientHandle(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	_, err := tpmutil.Persist(thetpm, tpmutil.PersistConfig{
		PersistentHandle: tpmutil.NewHandle(tpm2.TPMHandle(0x81000100)),
	})
	if err == nil {
		t.Fatal("Expected error when TransientHandle is nil, got nil")
	}
}

func TestPersist_MissingPersistentHandle(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	transientHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpmutil.ECCSRKTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer transientHandle.Close() //nolint:errcheck

	_, err = tpmutil.Persist(thetpm, tpmutil.PersistConfig{
		TransientHandle: transientHandle,
	})
	if err == nil {
		t.Fatal("Expected error when PersistentHandle is nil, got nil")
	}
}

func TestPersist_HandleAlreadyOccupied(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)
	targetHandle := tpmutil.NewHandle(tpm2.TPMHandle(0x81000102))

	// Create and persist the first key
	firstHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpmutil.ECCSRKTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary (first) failed: %v", err)
	}
	defer firstHandle.Close() //nolint:errcheck

	persistedFirst, err := tpmutil.Persist(thetpm, tpmutil.PersistConfig{
		TransientHandle:  firstHandle,
		PersistentHandle: targetHandle,
	})
	if err != nil {
		t.Fatalf("Persist (first) failed: %v", err)
	}
	defer func() {
		_, _ = tpm2.EvictControl{
			Auth:             tpmutil.ToAuthHandle(tpmutil.NewHandle(tpm2.TPMRHOwner), tpmutil.NoAuth),
			ObjectHandle:     persistedFirst,
			PersistentHandle: targetHandle.Handle(),
		}.Execute(thetpm)
	}()

	// Create a second key
	secondHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpmutil.RSASRKTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary (second) failed: %v", err)
	}
	defer secondHandle.Close() //nolint:errcheck

	t.Run("WithoutForce", func(t *testing.T) {
		// Try to persist without Force (should fail)
		_, err := tpmutil.Persist(thetpm, tpmutil.PersistConfig{
			TransientHandle:  secondHandle,
			PersistentHandle: targetHandle,
		})
		if err == nil {
			t.Fatal("Expected error when handle is already occupied without Force, got nil")
		}
	})

	t.Run("WithForce", func(t *testing.T) {
		// Persist with Force (should succeed)
		persistedSecond, err := tpmutil.Persist(thetpm, tpmutil.PersistConfig{
			TransientHandle:  secondHandle,
			PersistentHandle: targetHandle,
			Force:            true,
		})
		if err != nil {
			t.Fatalf("Persist with Force failed: %v", err)
		}

		// Verify the new key is persisted
		readPublicRsp, err := tpm2.ReadPublic{
			ObjectHandle: persistedSecond.Handle(),
		}.Execute(thetpm)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}

		// Verify the names match the second key
		if !bytes.Equal(readPublicRsp.Name.Buffer, secondHandle.Name().Buffer) {
			t.Errorf("Name mismatch: got %v, want %v", readPublicRsp.Name, secondHandle.Name())
		}
	})
}
