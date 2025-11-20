package tpmutil

/*
This file hosts helpers that got tpm2 commands as arguments instead of config structs.

Ideally, for consistency, all helpers should use the same pattern. I need to figure out which pattern is the best.

Meanwhile, to avoid confusion, I put helpers that use tpm2 commands in this separate file.
*/

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// CreatePrimary creates a primary key in the TPM and returns a [HandleCloser].
//
// Example:
//
//	primaryHandle, err := tpmutil.CreatePrimary(tpm, createPrimaryCmd)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	defer primaryHandle.Close()
//	// Use keyHandle for TPM operations
//
// Note: this method is useful when you only need the handle.
func CreatePrimary(t transport.TPM, cmd tpm2.CreatePrimary) (HandleCloser, error) {
	rsp, err := cmd.Execute(t)
	if err != nil {
		return nil, err
	}

	h := &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}
	return NewHandleCloser(t, h), nil
}

// CreatePrimaryWithResponse creates a primary key in the TPM and returns the response along with a closer function.
//
// Example:
//
//	// Create an ECC SRK in the owner hierarchy
//	createPrimaryRsp, closer, err := tpmutil.CreatePrimary(tpm, createPrimaryCmd)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer closer()
//
// Note: this method is useful when you need access to the full CreatePrimaryResponse.
func CreatePrimaryWithResponse(t transport.TPM, cmd tpm2.CreatePrimary) (*tpm2.CreatePrimaryResponse, func() error, error) {
	rsp, err := cmd.Execute(t)
	if err != nil {
		return nil, nil, err
	}

	closer := func() error {
		_, err := (&tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}).Execute(t)
		return err
	}
	return rsp, closer, nil
}

// Load loads a key into the TPM and returns a [HandleCloser].
//
// Example:
//
//	// Load a previously created key into the TPM
//	keyHandle, err := tpmutil.Load(tpm, loadCmd)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer keyHandle.Close()
func Load(t transport.TPM, cmd tpm2.Load) (HandleCloser, error) {
	rsp, err := cmd.Execute(t)
	if err != nil {
		return nil, err
	}

	h := &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}
	return NewHandleCloser(t, h), nil
}
