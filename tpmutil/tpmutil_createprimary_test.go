package tpmutil_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestCreatePrimaryWithConfig(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	t.Run("with ECC template", func(t *testing.T) {
		eccTemplate := tpm2.ECCSRKTemplate
		handle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			Template:      eccTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer func() {
			if err := handle.Close(); err != nil {
				t.Errorf("Close() failed: %v", err)
			}
		}()

		if handle.Handle() != 0x80000000 {
			t.Errorf("Expected handle 0x80000000, got 0x%x", handle.Handle())
		}

		if handle.Type() != tpmutil.TransientHandle {
			t.Errorf("Expected handle type Transient, got %s", handle.Type())
		}

		if !handle.HasPublic() {
			t.Error("Expected HasPublic() to return true")
		}

		public := handle.Public()
		if public == nil {
			t.Fatal("Expected Public() to return non-nil value")
		}

		if public.Type != tpm2.TPMAlgECC {
			t.Errorf("Expected public type ECC, got %v", public.Type)
		}
	})

	t.Run("with RSA template", func(t *testing.T) {
		rsaTemplate := tpm2.RSASRKTemplate
		handle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			Template:      rsaTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer func() {
			if err := handle.Close(); err != nil {
				t.Errorf("Close() failed: %v", err)
			}
		}()

		if handle.Type() != tpmutil.TransientHandle {
			t.Errorf("Expected handle type Transient, got %s", handle.Type())
		}

		public := handle.Public()
		if public == nil {
			t.Fatal("Expected Public() to return non-nil value")
		}

		if public.Type != tpm2.TPMAlgRSA {
			t.Errorf("Expected public type RSA, got %v", public.Type)
		}
	})

}

func TestCreatePrimaryWithResponseAndConfig(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	t.Run("with ECC template", func(t *testing.T) {
		eccTemplate := tpm2.ECCSRKTemplate
		rsp, closer, err := tpmutil.CreatePrimaryWithResponse(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			Template:      eccTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimaryWithResponse() failed: %v", err)
		}
		defer func() {
			if err := closer(); err != nil {
				t.Errorf("closer() failed: %v", err)
			}
		}()

		if rsp.ObjectHandle != 0x80000000 {
			t.Errorf("Expected handle 0x80000000, got 0x%x", rsp.ObjectHandle)
		}

		public, err := rsp.OutPublic.Contents()
		if err != nil {
			t.Fatalf("OutPublic.Contents() failed: %v", err)
		}

		if public.Type != tpm2.TPMAlgECC {
			t.Errorf("Expected public type ECC, got %v", public.Type)
		}
	})

	t.Run("with RSA template", func(t *testing.T) {
		rsaTemplate := tpm2.RSASRKTemplate
		rsp, closer, err := tpmutil.CreatePrimaryWithResponse(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			Template:      rsaTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimaryWithResponse() failed: %v", err)
		}
		defer func() {
			if err := closer(); err != nil {
				t.Errorf("closer() failed: %v", err)
			}
		}()

		public, err := rsp.OutPublic.Contents()
		if err != nil {
			t.Fatalf("OutPublic.Contents() failed: %v", err)
		}

		if public.Type != tpm2.TPMAlgRSA {
			t.Errorf("Expected public type RSA, got %v", public.Type)
		}
	})
}

func TestCreatePrimaryConfig_CheckAndSetDefault(t *testing.T) {
	t.Run("all defaults", func(t *testing.T) {
		eccTemplate := tpm2.ECCSRKTemplate
		cfg := tpmutil.CreatePrimaryConfig{
			Template: eccTemplate,
		}

		err := cfg.CheckAndSetDefault()
		if err != nil {
			t.Fatalf("CheckAndSetDefault() failed: %v", err)
		}

		if cfg.PrimaryHandle != tpm2.TPMRHOwner {
			t.Errorf("Expected PrimaryHandle TPMRHOwner, got 0x%x", cfg.PrimaryHandle)
		}

		if cfg.Auth == nil {
			t.Error("Expected Auth to be set to NoAuth")
		}
	})

	t.Run("custom values preserved", func(t *testing.T) {
		eccTemplate := tpm2.ECCSRKTemplate
		cfg := tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHEndorsement,
			Template:      eccTemplate,
		}

		err := cfg.CheckAndSetDefault()
		if err != nil {
			t.Fatalf("CheckAndSetDefault() failed: %v", err)
		}

		if cfg.PrimaryHandle != tpm2.TPMRHEndorsement {
			t.Errorf("Expected PrimaryHandle TPMRHEndorsement, got 0x%x", cfg.PrimaryHandle)
		}
	})
}

func TestLoadWithConfig(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	t.Run("load child key", func(t *testing.T) {
		// First create a primary key
		eccTemplate := tpm2.ECCSRKTemplate
		primaryHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			Template:      eccTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer primaryHandle.Close()

		// Create a child key
		create := tpm2.Create{
			ParentHandle: tpm2.AuthHandle{
				Handle: primaryHandle.Handle(),
				Name:   primaryHandle.Name(),
				Auth:   tpm2.PasswordAuth(nil),
			},
			InPublic: tpm2.New2B(tpm2.ECCSRKTemplate),
		}
		createRsp, err := create.Execute(thetpm)
		if err != nil {
			t.Fatalf("Create() failed: %v", err)
		}

		// Load the child key using the new Load function
		childHandle, err := tpmutil.Load(thetpm, tpmutil.LoadConfig{
			ParentHandle: primaryHandle,
			InPrivate:    createRsp.OutPrivate,
			InPublic:     createRsp.OutPublic,
		})
		if err != nil {
			t.Fatalf("Load() failed: %v", err)
		}
		defer childHandle.Close()

		if childHandle.Type() != tpmutil.TransientHandle {
			t.Errorf("Expected handle type Transient, got %s", childHandle.Type())
		}

		if !childHandle.HasPublic() {
			t.Error("Expected HasPublic() to return true")
		}

		public := childHandle.Public()
		if public == nil {
			t.Fatal("Expected Public() to return non-nil value")
		}

		if public.Type != tpm2.TPMAlgECC {
			t.Errorf("Expected public type ECC, got %v", public.Type)
		}
	})

	t.Run("missing parent handle", func(t *testing.T) {
		_, err := tpmutil.Load(thetpm, tpmutil.LoadConfig{
			InPrivate: tpm2.TPM2BPrivate{Buffer: []byte("dummy")},
			InPublic:  tpm2.TPM2BPublic{},
		})
		if err == nil {
			t.Error("Expected error for missing parent handle, got nil")
		}
	})

	t.Run("missing InPrivate", func(t *testing.T) {
		eccTemplate := tpm2.ECCSRKTemplate
		primaryHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			Template: eccTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer primaryHandle.Close()

		_, err = tpmutil.Load(thetpm, tpmutil.LoadConfig{
			ParentHandle: primaryHandle,
			InPublic:     tpm2.TPM2BPublic{},
		})
		if err == nil {
			t.Error("Expected error for missing InPrivate, got nil")
		}
	})
}

func TestLoadConfig_CheckAndSetDefault(t *testing.T) {
	t.Run("all required fields", func(t *testing.T) {
		handle := tpmutil.NewHandle(&tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000001),
			Name:   tpm2.TPM2BName{Buffer: []byte("test")},
		})

		cfg := tpmutil.LoadConfig{
			ParentHandle: handle,
			InPrivate:    tpm2.TPM2BPrivate{Buffer: []byte("private")},
			InPublic:     tpm2.TPM2BPublic{},
		}

		err := cfg.CheckAndSetDefault()
		if err != nil {
			t.Fatalf("CheckAndSetDefault() failed: %v", err)
		}

		if cfg.Auth == nil {
			t.Error("Expected Auth to be set to NoAuth")
		}
	})

	t.Run("missing parent handle", func(t *testing.T) {
		cfg := tpmutil.LoadConfig{
			InPrivate: tpm2.TPM2BPrivate{Buffer: []byte("private")},
			InPublic:  tpm2.TPM2BPublic{},
		}

		err := cfg.CheckAndSetDefault()
		if err == nil {
			t.Error("Expected error for missing parent handle, got nil")
		}
	})

	t.Run("missing InPrivate", func(t *testing.T) {
		handle := tpmutil.NewHandle(&tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000001),
			Name:   tpm2.TPM2BName{Buffer: []byte("test")},
		})

		cfg := tpmutil.LoadConfig{
			ParentHandle: handle,
			InPublic:     tpm2.TPM2BPublic{},
		}

		err := cfg.CheckAndSetDefault()
		if err == nil {
			t.Error("Expected error for missing InPrivate, got nil")
		}
	})
}
