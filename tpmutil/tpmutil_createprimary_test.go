package tpmutil_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

var (
	eccSigningTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
	}

	keyedHashTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
		},
	}
)

func TestCreatePrimaryWithConfig(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("Failed to open simulator: %v", err)
	}
	defer thetpm.Close()

	t.Run("with ECC template", func(t *testing.T) {
		eccTemplate := tpmutil.ECCSRKTemplate
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
		rsaTemplate := tpmutil.RSASRKTemplate
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

	t.Run("with UserAuth", func(t *testing.T) {
		userAuth := []byte("my-secret-password")

		handle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			Template:      eccSigningTemplate,
			UserAuth:      userAuth,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() with UserAuth failed: %v", err)
		}
		defer func() {
			if err := handle.Close(); err != nil {
				t.Errorf("Close() failed: %v", err)
			}
		}()

		if handle.Type() != tpmutil.TransientHandle {
			t.Errorf("Expected handle type Transient, got %s", handle.Type())
		}

		// Test signing with correct auth
		digest := make([]byte, 32)
		for i := range digest {
			digest[i] = byte(i)
		}
		signCmd := tpm2.Sign{
			KeyHandle: tpmutil.ToAuthHandle(handle, tpm2.PasswordAuth(userAuth)),
			Digest:    tpm2.TPM2BDigest{Buffer: digest},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSchemeHash{
						HashAlg: tpm2.TPMAlgSHA256,
					},
				),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}

		signRsp, err := signCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("Sign() failed: %v", err)
		}

		if signRsp.Signature.SigAlg != tpm2.TPMAlgECDSA {
			t.Errorf("Expected signature algorithm ECDSA, got %v", signRsp.Signature.SigAlg)
		}

		// Test signing with wrong auth should fail
		wrongAuthCmd := tpm2.Sign{
			KeyHandle: tpmutil.ToAuthHandle(handle, tpm2.PasswordAuth([]byte("wrong-password"))),
			Digest:    tpm2.TPM2BDigest{Buffer: digest},
			InScheme: tpm2.TPMTSigScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUSigScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSchemeHash{
						HashAlg: tpm2.TPMAlgSHA256,
					},
				),
			},
			Validation: tpm2.TPMTTKHashCheck{
				Tag: tpm2.TPMSTHashCheck,
			},
		}

		_, err = wrongAuthCmd.Execute(thetpm)
		if err == nil {
			t.Error("Expected Sign() to fail with wrong password")
		}
	})

	t.Run("with SealingData", func(t *testing.T) {
		sealingData := []byte("secret sealed data")

		handle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			Template:      keyedHashTemplate,
			SealingData:   sealingData,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() with SealingData failed: %v", err)
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
		if public.Type != tpm2.TPMAlgKeyedHash {
			t.Errorf("Expected public type KeyedHash, got %v", public.Type)
		}

		// Test unsealing the data
		unsealCmd := tpm2.Unseal{
			ItemHandle: tpmutil.ToAuthHandle(handle),
		}
		unsealRsp, err := unsealCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("Unseal() failed: %v", err)
		}

		if string(unsealRsp.OutData.Buffer) != string(sealingData) {
			t.Errorf("Expected unsealed data %q, got %q", sealingData, unsealRsp.OutData.Buffer)
		}
	})

	t.Run("with both UserAuth and SealingData", func(t *testing.T) {
		userAuth := []byte("my-password")
		sealingData := []byte("secret sealed data")

		handle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			Template:      keyedHashTemplate,
			UserAuth:      userAuth,
			SealingData:   sealingData,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() with UserAuth and SealingData failed: %v", err)
		}
		defer func() {
			if err := handle.Close(); err != nil {
				t.Errorf("Close() failed: %v", err)
			}
		}()

		if handle.Type() != tpmutil.TransientHandle {
			t.Errorf("Expected handle type Transient, got %s", handle.Type())
		}

		// Test unsealing with correct auth
		unsealCmd := tpm2.Unseal{
			ItemHandle: tpmutil.ToAuthHandle(handle, tpm2.PasswordAuth(userAuth)),
		}
		unsealRsp, err := unsealCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("Unseal() failed: %v", err)
		}

		if string(unsealRsp.OutData.Buffer) != string(sealingData) {
			t.Errorf("Expected unsealed data %q, got %q", sealingData, unsealRsp.OutData.Buffer)
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
		eccTemplate := tpmutil.ECCSRKTemplate
		rsp, closer, err := tpmutil.CreatePrimaryWithResult(thetpm, tpmutil.CreatePrimaryConfig{
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
		rsaTemplate := tpmutil.RSASRKTemplate
		rsp, closer, err := tpmutil.CreatePrimaryWithResult(thetpm, tpmutil.CreatePrimaryConfig{
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
		eccTemplate := tpmutil.ECCSRKTemplate
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
		eccTemplate := tpmutil.ECCSRKTemplate
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

	t.Run("sealing data validation - invalid template type", func(t *testing.T) {
		eccTemplate := tpmutil.ECCSRKTemplate
		cfg := tpmutil.CreatePrimaryConfig{
			Template:    eccTemplate,
			SealingData: []byte("secret data"),
		}

		err := cfg.CheckAndSetDefault()
		if err == nil {
			t.Error("Expected error when SealingData is provided with non-KeyedHash template, got nil")
		}
	})

	t.Run("sealing data validation - SensitiveDataOrigin set", func(t *testing.T) {
		template := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SensitiveDataOrigin: true,
			},
		}
		cfg := tpmutil.CreatePrimaryConfig{
			Template:    template,
			SealingData: []byte("secret data"),
		}

		err := cfg.CheckAndSetDefault()
		if err == nil {
			t.Error("Expected error when SealingData is provided with SensitiveDataOrigin set, got nil")
		}
	})

	t.Run("sealing data validation - valid", func(t *testing.T) {
		template := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SensitiveDataOrigin: false,
			},
		}
		cfg := tpmutil.CreatePrimaryConfig{
			Template:    template,
			SealingData: []byte("secret data"),
		}

		err := cfg.CheckAndSetDefault()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
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
		eccTemplate := tpmutil.ECCSRKTemplate
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
			ParentHandle: tpmutil.ToAuthHandle(primaryHandle),
			InPublic:     tpm2.New2B(tpmutil.ECCSRKTemplate),
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
		eccTemplate := tpmutil.ECCSRKTemplate
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
