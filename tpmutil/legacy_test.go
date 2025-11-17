package tpmutil_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestCreatePrimaryWithResponse(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	cmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}

	rsp, closer, err := tpmutil.CreatePrimaryWithResponse(thetpm, cmd)
	if err != nil {
		t.Fatalf("CreatePrimary() failed: %v", err)
	}
	defer func() {
		if err := closer(); err != nil {
			t.Errorf("closer() failed: %v", err)
		}
	}()

	if rsp.ObjectHandle != 0x80000000 {
		t.Errorf("Expected handle 0x80000000, got 0x%x", rsp.ObjectHandle)
	}
}

func TestLoad(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	// First create a primary key
	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}
	rspPrimary, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary() failed: %v", err)
	}
	defer func() {
		flushContext := tpm2.FlushContext{FlushHandle: rspPrimary.ObjectHandle}
		if _, err := flushContext.Execute(thetpm); err != nil {
			t.Errorf("FlushContext() failed: %v", err)
		}
	}()

	// Create a child key
	create := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: rspPrimary.ObjectHandle,
			Name:   rspPrimary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(tpm2.RSASRKTemplate),
	}
	rspCreate, err := create.Execute(thetpm)
	if err != nil {
		t.Fatalf("Create() failed: %v", err)
	}

	// Load the child key
	load := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: rspPrimary.ObjectHandle,
			Name:   rspPrimary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPrivate: rspCreate.OutPrivate,
		InPublic:  rspCreate.OutPublic,
	}

	handle, err := tpmutil.Load(thetpm, load)
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}
	defer func() {
		if err := handle.Close(); err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	}()

	if handle.Type() != tpmutil.TransientHandle {
		t.Errorf("Expected handle type Transient, got %s", handle.Type())
	}
}
