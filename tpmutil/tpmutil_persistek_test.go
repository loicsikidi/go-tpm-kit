package tpmutil_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestPersistEK_CreateNew(t *testing.T) {
	tests := []struct {
		name           string
		keyType        tpmutil.KeyType
		isLowRange     bool
		expectedHandle tpm2.TPMHandle
		expectedAlg    tpm2.TPMAlgID
	}{
		{
			name:           "RSA2048_LowRange",
			keyType:        tpmutil.RSA2048,
			isLowRange:     true,
			expectedHandle: tpmutil.RSAEKHandle,
			expectedAlg:    tpm2.TPMAlgRSA,
		},
		{
			name:           "RSA2048_HighRange",
			keyType:        tpmutil.RSA2048,
			isLowRange:     false,
			expectedHandle: tpmutil.RSAEKHandle,
			expectedAlg:    tpm2.TPMAlgRSA,
		},
		{
			name:           "ECCNISTP256_LowRange",
			keyType:        tpmutil.ECCNISTP256,
			isLowRange:     true,
			expectedHandle: tpmutil.ECCEKHandle,
			expectedAlg:    tpm2.TPMAlgECC,
		},
		{
			name:           "ECCNISTP256_HighRange",
			keyType:        tpmutil.ECCNISTP256,
			isLowRange:     false,
			expectedHandle: tpmutil.ECCEKHandle,
			expectedAlg:    tpm2.TPMAlgECC,
		},
		{
			name:           "ECCNISTP384",
			keyType:        tpmutil.ECCNISTP384,
			isLowRange:     false,
			expectedHandle: tpmutil.ECCEKHandle,
			expectedAlg:    tpm2.TPMAlgECC,
		},
		{
			name:           "ECCNISTP521",
			keyType:        tpmutil.ECCNISTP521,
			isLowRange:     false,
			expectedHandle: tpmutil.ECCEKHandle,
			expectedAlg:    tpm2.TPMAlgECC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thetpm, err := simulator.OpenSimulator()
			if err != nil {
				t.Fatalf("Failed to open simulator: %v", err)
			}
			defer thetpm.Close()

			// Determine KeyFamily based on keyType
			var keyFamily tpmutil.KeyFamily
			switch tt.keyType {
			case tpmutil.RSA2048, tpmutil.RSA3072, tpmutil.RSA4096:
				keyFamily = tpmutil.RSA
			case tpmutil.ECCNISTP256, tpmutil.ECCNISTP384, tpmutil.ECCNISTP521:
				keyFamily = tpmutil.ECC
			}

			cfg := tpmutil.EKParentConfig{
				KeyFamily:  keyFamily,
				KeyType:    tt.keyType,
				IsLowRange: tt.isLowRange,
			}

			handle, err := tpmutil.PersistEK(thetpm, cfg)
			if err != nil {
				t.Fatalf("PersistEK failed: %v", err)
			}

			if handle.Handle() != tt.expectedHandle {
				t.Errorf("Expected handle 0x%x, got 0x%x", tt.expectedHandle, handle.Handle())
			}

			// Verify the key is persisted and has the correct type
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

			if pub.Type != tt.expectedAlg {
				t.Errorf("Expected %v key type, got %v", tt.expectedAlg, pub.Type)
			}
		})
	}
}

func TestPersistEK_WithTransientKey(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	// Create a transient EK manually
	transientEK, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHEndorsement,
		Template:      tpmutil.RSAEKTemplate,
	})
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer transientEK.Close()

	// Persist it using PersistEK
	cfg := tpmutil.EKParentConfig{
		KeyFamily:    tpmutil.RSA,
		TransientKey: transientEK,
		KeyType:      tpmutil.RSA2048,
	}

	handle, err := tpmutil.PersistEK(thetpm, cfg)
	if err != nil {
		t.Fatalf("PersistEK failed: %v", err)
	}

	if handle.Handle() != tpmutil.RSAEKHandle {
		t.Errorf("Expected handle 0x%x, got 0x%x", tpmutil.RSAEKHandle, handle.Handle())
	}

	// Verify the key is persisted
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

	if pub.Type != tpm2.TPMAlgRSA {
		t.Errorf("Expected RSA key type, got %v", pub.Type)
	}
}

func TestPersistEK_CustomHandle(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	customHandle := tpm2.TPMHandle(0x81010020)

	cfg := tpmutil.EKParentConfig{
		KeyFamily:  tpmutil.RSA,
		Handle:     tpmutil.NewHandle(customHandle),
		KeyType:    tpmutil.RSA2048,
		IsLowRange: true,
	}

	handle, err := tpmutil.PersistEK(thetpm, cfg)
	if err != nil {
		t.Fatalf("PersistEK failed: %v", err)
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

func TestPersistEK_HandleAlreadyOccupied(t *testing.T) {
	t.Run("WithoutForce", func(t *testing.T) {
		thetpm, err := simulator.OpenSimulator()
		if err != nil {
			t.Fatalf("Failed to open simulator: %v", err)
		}
		defer thetpm.Close()

		// First, persist an EK at the default RSA handle
		cfg1 := tpmutil.EKParentConfig{
			KeyFamily:  tpmutil.RSA,
			KeyType:    tpmutil.RSA2048,
			IsLowRange: true,
		}

		handle1, err := tpmutil.PersistEK(thetpm, cfg1)
		if err != nil {
			t.Fatalf("First PersistEK failed: %v", err)
		}

		if handle1.Handle() != tpmutil.RSAEKHandle {
			t.Errorf("Expected handle 0x%x, got 0x%x", tpmutil.RSAEKHandle, handle1.Handle())
		}

		// Now try to persist another EK at the same handle without Force - should fail
		cfg2 := tpmutil.EKParentConfig{
			KeyFamily:  tpmutil.RSA,
			KeyType:    tpmutil.RSA2048,
			IsLowRange: false, // Different template
			Force:      false,
		}

		_, err = tpmutil.PersistEK(thetpm, cfg2)
		if err == nil {
			t.Fatal("Expected error when handle is already occupied and Force=false, got nil")
		}
	})

	t.Run("WithForce", func(t *testing.T) {
		thetpm, err := simulator.OpenSimulator()
		if err != nil {
			t.Fatalf("Failed to open simulator: %v", err)
		}
		defer thetpm.Close()

		// First, persist an EK at the default RSA handle (low-range template)
		cfg1 := tpmutil.EKParentConfig{
			KeyFamily:  tpmutil.RSA,
			KeyType:    tpmutil.RSA2048,
			IsLowRange: true,
		}

		handle1, err := tpmutil.PersistEK(thetpm, cfg1)
		if err != nil {
			t.Fatalf("First PersistEK failed: %v", err)
		}

		if handle1.Handle() != tpmutil.RSAEKHandle {
			t.Errorf("Expected handle 0x%x, got 0x%x", tpmutil.RSAEKHandle, handle1.Handle())
		}

		// Verify it's using the low-range template (RSAEKTemplate)
		readPub1 := tpm2.ReadPublic{
			ObjectHandle: handle1.Handle(),
		}
		rsp1, err := readPub1.Execute(thetpm)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}
		pub1, err := rsp1.OutPublic.Contents()
		if err != nil {
			t.Fatalf("Contents failed: %v", err)
		}

		// Now persist another EK at the same handle with Force=true (high-range template)
		cfg2 := tpmutil.EKParentConfig{
			KeyFamily:  tpmutil.RSA,
			KeyType:    tpmutil.RSA2048,
			IsLowRange: false, // Different template (high-range)
			Force:      true,
		}

		handle2, err := tpmutil.PersistEK(thetpm, cfg2)
		if err != nil {
			t.Fatalf("Second PersistEK with Force=true failed: %v", err)
		}

		if handle2.Handle() != tpmutil.RSAEKHandle {
			t.Errorf("Expected handle 0x%x, got 0x%x", tpmutil.RSAEKHandle, handle2.Handle())
		}

		// Verify the key was replaced (should now use high-range template)
		readPub2 := tpm2.ReadPublic{
			ObjectHandle: handle2.Handle(),
		}
		rsp2, err := readPub2.Execute(thetpm)
		if err != nil {
			t.Fatalf("ReadPublic after force failed: %v", err)
		}
		pub2, err := rsp2.OutPublic.Contents()
		if err != nil {
			t.Fatalf("Contents after force failed: %v", err)
		}

		// Both should be RSA, but the templates might differ slightly
		if pub2.Type != tpm2.TPMAlgRSA {
			t.Errorf("Expected RSA key type after force, got %v", pub2.Type)
		}

		// The name should have changed because we used a different template
		if string(rsp1.Name.Buffer) == string(rsp2.Name.Buffer) {
			t.Error("Expected different Name after forcing with different template")
		}

		// Sanity check: original key type should also be RSA
		if pub1.Type != tpm2.TPMAlgRSA {
			t.Errorf("Expected RSA key type for original, got %v", pub1.Type)
		}
	})
}

func TestPersistEK_MissingKeyType(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	cfg := tpmutil.EKParentConfig{
		KeyFamily: tpmutil.RSA,
		// KeyType is not specified
	}

	_, err = tpmutil.PersistEK(thetpm, cfg)
	if err == nil {
		t.Fatal("Expected error when KeyType is not specified, got nil")
	}
}

func TestPersistEK_DefaultConfig(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	// Using default config should fail because KeyType is required
	_, err = tpmutil.PersistEK(thetpm)
	if err == nil {
		t.Fatal("Expected error with nil config (KeyType required), got nil")
	}
}
