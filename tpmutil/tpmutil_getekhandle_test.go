package tpmutil_test

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestGetEKHandle_NotFound(t *testing.T) {
	tests := []struct {
		name           string
		keyFamily      tpmutil.KeyFamily
		expectedHandle tpm2.TPMHandle
	}{
		{
			name:           "RSA",
			keyFamily:      tpmutil.RSA,
			expectedHandle: tpmutil.RSAEKHandle,
		},
		{
			name:           "ECC",
			keyFamily:      tpmutil.ECC,
			expectedHandle: tpmutil.ECCEKHandle,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thetpm, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatalf("Failed to open simulator: %v", err)
			}
			defer thetpm.Close()

			cfg := tpmutil.EKParentConfig{
				KeyFamily: tt.keyFamily,
			}
			_, err = tpmutil.GetEKHandle(thetpm, cfg)
			if err == nil {
				t.Fatal("Expected error when EK not found, got nil")
			}

			var handleErr *tpmutil.ErrHandleNotFound
			if !errors.As(err, &handleErr) {
				t.Fatalf("Expected ErrHandleNotFound, got %T: %v", err, err)
			}

			if handleErr.Handle != tt.expectedHandle {
				t.Errorf("Expected handle 0x%x in error, got 0x%x", tt.expectedHandle, handleErr.Handle)
			}
		})
	}
}

func TestGetEKHandle_AlreadyPersisted(t *testing.T) {
	tests := []struct {
		name           string
		keyFamily      tpmutil.KeyFamily
		template       tpm2.TPMTPublic
		expectedHandle tpm2.TPMHandle
		expectedType   tpm2.TPMAlgID
	}{
		{
			name:           "RSA",
			keyFamily:      tpmutil.RSA,
			template:       tpmutil.RSAEKTemplate,
			expectedHandle: tpmutil.RSAEKHandle,
			expectedType:   tpm2.TPMAlgRSA,
		},
		{
			name:           "ECC",
			keyFamily:      tpmutil.ECC,
			template:       tpmutil.ECCEKTemplate,
			expectedHandle: tpmutil.ECCEKHandle,
			expectedType:   tpm2.TPMAlgECC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thetpm, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatalf("Failed to open simulator: %v", err)
			}
			defer thetpm.Close()

			// Create and persist an EK manually
			ekHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
				PrimaryHandle: tpm2.TPMRHEndorsement,
				Auth:          tpmutil.NoAuth,
				Template:      tt.template,
			})
			if err != nil {
				t.Fatalf("CreatePrimary failed: %v", err)
			}
			defer ekHandle.Close()

			// Persist it at the expected handle
			_, err = tpm2.EvictControl{
				Auth: tpm2.AuthHandle{
					Handle: tpm2.TPMRHOwner,
					Auth:   tpmutil.NoAuth,
				},
				ObjectHandle:     ekHandle,
				PersistentHandle: tt.expectedHandle,
			}.Execute(thetpm)
			if err != nil {
				t.Fatalf("EvictControl failed: %v", err)
			}

			// Now try to get the EK
			cfg := tpmutil.EKParentConfig{
				KeyFamily: tt.keyFamily,
			}
			handle, err := tpmutil.GetEKHandle(thetpm, cfg)
			if err != nil {
				t.Fatalf("GetEKHandle failed: %v", err)
			}

			if handle.Handle() != tt.expectedHandle {
				t.Errorf("Expected handle 0x%x, got 0x%x", tt.expectedHandle, handle.Handle())
			}

			// Verify the key can be read and has the correct type
			readPub := tpm2.ReadPublic{
				ObjectHandle: handle.Handle(),
			}
			rsp, err := readPub.Execute(thetpm)
			if err != nil {
				t.Fatalf("ReadPublic failed: %v", err)
			}

			pub, err := rsp.OutPublic.Contents()
			if err != nil {
				t.Fatalf("Contents failed: %v", err)
			}

			if pub.Type != tt.expectedType {
				t.Errorf("Expected %v key type, got %v", tt.expectedType, pub.Type)
			}
		})
	}
}

func TestGetEKHandle_CustomHandle(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	// Use a non-standard persistent handle
	customHandle := tpm2.TPMHandle(0x81010010)

	// Create and persist an RSA EK at custom handle
	ekHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		Auth:          tpmutil.NoAuth,
		Template:      tpmutil.RSAEKTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer ekHandle.Close()

	// Persist it at the custom handle
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpmutil.NoAuth,
		},
		ObjectHandle:     ekHandle,
		PersistentHandle: customHandle,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("EvictControl failed: %v", err)
	}

	// Try to get the EK at the custom handle
	cfg := tpmutil.EKParentConfig{
		KeyFamily: tpmutil.RSA,
		Handle:    tpmutil.NewHandle(customHandle),
	}
	handle, err := tpmutil.GetEKHandle(thetpm, cfg)
	if err != nil {
		t.Fatalf("GetEKHandle failed: %v", err)
	}

	if handle.Handle() != customHandle {
		t.Errorf("Expected handle 0x%x, got 0x%x", customHandle, handle.Handle())
	}

	// Verify the key is persisted at the custom handle
	readPub := tpm2.ReadPublic{
		ObjectHandle: customHandle,
	}
	rsp, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("Contents failed: %v", err)
	}

	if pub.Type != tpm2.TPMAlgRSA {
		t.Errorf("Expected RSA key type, got %v", pub.Type)
	}
}

func TestGetEKHandle_DefaultConfig(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	// Create and persist an ECC EK at default handle
	ekHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		Auth:          tpmutil.NoAuth,
		Template:      tpmutil.ECCEKTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer ekHandle.Close()

	// Persist it at the default RSA EK handle
	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpmutil.NoAuth,
		},
		ObjectHandle:     ekHandle,
		PersistentHandle: tpmutil.ECCEKHandle,
	}.Execute(thetpm)
	if err != nil {
		t.Fatalf("EvictControl failed: %v", err)
	}

	// Call GetEKHandle with nil config (should use defaults: RSA at 0x81010001)
	handle, err := tpmutil.GetEKHandle(thetpm)
	if err != nil {
		t.Fatalf("GetEKHandle with nil config failed: %v", err)
	}

	if handle.Handle() != tpmutil.ECCEKHandle {
		t.Errorf("Expected default handle 0x%x, got 0x%x", tpmutil.ECCEKHandle, handle.Handle())
	}

	// Verify it's an ECC key
	readPub := tpm2.ReadPublic{
		ObjectHandle: handle.Handle(),
	}
	rsp, err := readPub.Execute(thetpm)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("Contents failed: %v", err)
	}

	if pub.Type != tpm2.TPMAlgECC {
		t.Errorf("Expected ECC key type, got %v", pub.Type)
	}
}
