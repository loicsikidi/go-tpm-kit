package tpmutil_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/internal/utils/testutil"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestCreate(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	t.Run("with ECC template", func(t *testing.T) {
		eccTemplate := tpmutil.ECCSRKTemplate
		parentHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      eccTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer parentHandle.Close()

		keyHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
			ParentHandle: parentHandle,
			InPublic:     eccTemplate,
		})
		if err != nil {
			t.Fatalf("Create() failed: %v", err)
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

	t.Run("with RSA template", func(t *testing.T) {
		rsaTemplate := tpmutil.RSASRKTemplate
		parentHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      rsaTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer parentHandle.Close()

		keyHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
			ParentHandle: parentHandle,
			InPublic:     rsaTemplate,
		})
		if err != nil {
			t.Fatalf("Create() failed: %v", err)
		}
		defer keyHandle.Close()

		if keyHandle.Type() != tpmutil.TransientHandle {
			t.Errorf("Expected handle type Transient, got %s", keyHandle.Type())
		}

		public := keyHandle.Public()
		if public.Type != tpm2.TPMAlgRSA {
			t.Errorf("Expected public type RSA, got %v", public.Type)
		}
	})

	t.Run("with both userAuth and data", func(t *testing.T) {
		userAuth := []byte("my-secret-password")
		sealingData := []byte("data-to-seal")

		parentHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpmutil.RSASRKTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer parentHandle.Close()

		template := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
			},
		}

		keyHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
			ParentHandle: parentHandle,
			InPublic:     template,
			UserAuth:     userAuth,
			SealingData:  sealingData,
		})
		if err != nil {
			t.Fatalf("Create() failed: %v", err)
		}
		defer keyHandle.Close()

		unsealCmd := tpm2.Unseal{
			ItemHandle: tpmutil.ToAuthHandle(keyHandle, tpm2.PasswordAuth(userAuth)),
		}
		unsealRsp, err := unsealCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("Unseal() failed: %v", err)
		}

		if string(unsealRsp.OutData.Buffer) != string(sealingData) {
			t.Errorf("Expected unsealed data %q, got %q", sealingData, unsealRsp.OutData.Buffer)
		}
	})

	t.Run("with only userAuth", func(t *testing.T) {
		userAuth := []byte("my-secret-password")

		parentHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpmutil.ECCSRKTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer parentHandle.Close()

		signingTemplate := tpm2.TPMTPublic{
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

		keyHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
			ParentHandle: parentHandle,
			InPublic:     signingTemplate,
			UserAuth:     userAuth,
		})
		if err != nil {
			t.Fatalf("Create() failed: %v", err)
		}
		defer keyHandle.Close()

		digest := make([]byte, 32)
		for i := range digest {
			digest[i] = byte(i)
		}
		signCmd := tpm2.Sign{
			KeyHandle: tpmutil.ToAuthHandle(keyHandle, tpm2.PasswordAuth(userAuth)),
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

		wrongAuthCmd := tpm2.Sign{
			KeyHandle: tpmutil.ToAuthHandle(keyHandle, tpm2.PasswordAuth([]byte("wrong-password"))),
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

	t.Run("with only sealingData", func(t *testing.T) {
		sealingData := []byte("data-to-seal")

		parentHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpmutil.RSASRKTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer parentHandle.Close()

		template := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
			},
		}

		keyHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
			ParentHandle: parentHandle,
			InPublic:     template,
			SealingData:  sealingData,
		})
		if err != nil {
			t.Fatalf("Create() failed: %v", err)
		}
		defer keyHandle.Close()

		unsealCmd := tpm2.Unseal{
			ItemHandle: tpmutil.ToAuthHandle(keyHandle),
		}
		unsealRsp, err := unsealCmd.Execute(thetpm)
		if err != nil {
			t.Fatalf("Unseal() failed: %v", err)
		}

		if string(unsealRsp.OutData.Buffer) != string(sealingData) {
			t.Errorf("Expected unsealed data %q, got %q", sealingData, unsealRsp.OutData.Buffer)
		}
	})

	t.Run("with neither userAuth nor sealingData", func(t *testing.T) {
		parentHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpmutil.RSASRKTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer parentHandle.Close()

		keyHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
			ParentHandle: parentHandle,
			InPublic:     tpmutil.RSASRKTemplate,
		})
		if err != nil {
			t.Fatalf("Create() failed: %v", err)
		}
		defer keyHandle.Close()
	})

	t.Run("with empty slices", func(t *testing.T) {
		parentHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpmutil.RSASRKTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer parentHandle.Close()

		keyHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
			ParentHandle: parentHandle,
			InPublic:     tpmutil.ECCSRKTemplate,
			UserAuth:     []byte{},
			SealingData:  []byte{},
		})
		if err != nil {
			t.Fatalf("Create() failed: %v", err)
		}
		defer keyHandle.Close()
	})
}

func TestCreateWithResult(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	t.Run("with ECC template", func(t *testing.T) {
		// First create a primary key to use as parent
		eccTemplate := tpmutil.ECCSRKTemplate
		parentHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      eccTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer parentHandle.Close()

		// Create a child key
		result, err := tpmutil.CreateWithResult(thetpm, tpmutil.CreateConfig{
			ParentHandle: parentHandle,
			InPublic:     eccTemplate,
		})
		if err != nil {
			t.Fatalf("Create() failed: %v", err)
		}

		if len(result.OutPrivate.Buffer) == 0 {
			t.Error("Expected OutPrivate to be non-empty")
		}

		public, err := result.OutPublic.Contents()
		if err != nil {
			t.Fatalf("OutPublic.Contents() failed: %v", err)
		}

		if public.Type != tpm2.TPMAlgECC {
			t.Errorf("Expected public type ECC, got %v", public.Type)
		}

		if len(result.CreationHash.Buffer) == 0 {
			t.Error("Expected CreationHash to be non-empty")
		}

		// Verify we can load the created key
		keyHandle, err := tpmutil.Load(thetpm, tpmutil.LoadConfig{
			ParentHandle: parentHandle,
			InPrivate:    result.OutPrivate,
			InPublic:     result.OutPublic,
		})
		if err != nil {
			t.Fatalf("Load() failed: %v", err)
		}
		defer keyHandle.Close()

		if keyHandle.Type() != tpmutil.TransientHandle {
			t.Errorf("Expected handle type Transient, got %s", keyHandle.Type())
		}
	})

	t.Run("with RSA template", func(t *testing.T) {
		// First create a primary key to use as parent
		rsaTemplate := tpmutil.RSASRKTemplate
		parentHandle, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      rsaTemplate,
		})
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer parentHandle.Close()

		// Create a child key
		result, err := tpmutil.CreateWithResult(thetpm, tpmutil.CreateConfig{
			ParentHandle: parentHandle,
			InPublic:     rsaTemplate,
		})
		if err != nil {
			t.Fatalf("Create() failed: %v", err)
		}

		if len(result.OutPrivate.Buffer) == 0 {
			t.Error("Expected OutPrivate to be non-empty")
		}

		public, err := result.OutPublic.Contents()
		if err != nil {
			t.Fatalf("OutPublic.Contents() failed: %v", err)
		}

		if public.Type != tpm2.TPMAlgRSA {
			t.Errorf("Expected public type RSA, got %v", public.Type)
		}

		// Verify we can load the created key
		keyHandle, err := tpmutil.Load(thetpm, tpmutil.LoadConfig{
			ParentHandle: parentHandle,
			InPrivate:    result.OutPrivate,
			InPublic:     result.OutPublic,
		})
		if err != nil {
			t.Fatalf("Load() failed: %v", err)
		}
		defer keyHandle.Close()

		if keyHandle.Type() != tpmutil.TransientHandle {
			t.Errorf("Expected handle type Transient, got %s", keyHandle.Type())
		}
	})
}

func TestCreateConfig_CheckAndSetDefault(t *testing.T) {
	t.Run("all defaults", func(t *testing.T) {
		handle := tpmutil.NewHandle(&tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000001),
			Name:   tpm2.TPM2BName{Buffer: []byte("test")},
		})

		eccTemplate := tpmutil.ECCSRKTemplate
		cfg := tpmutil.CreateConfig{
			ParentHandle: handle,
			InPublic:     eccTemplate,
		}

		err := cfg.CheckAndSetDefault()
		if err != nil {
			t.Fatalf("CheckAndSetDefault() failed: %v", err)
		}

		if cfg.ParentAuth == nil {
			t.Error("Expected Auth to be set to NoAuth")
		}
	})

	t.Run("missing parent handle", func(t *testing.T) {
		eccTemplate := tpmutil.ECCSRKTemplate
		cfg := tpmutil.CreateConfig{
			InPublic: eccTemplate,
		}

		err := cfg.CheckAndSetDefault()
		if err == nil {
			t.Error("Expected error for missing parent handle, got nil")
		}
	})

	t.Run("SealingData with wrong template type", func(t *testing.T) {
		handle := tpmutil.NewHandle(&tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000001),
			Name:   tpm2.TPM2BName{Buffer: []byte("test")},
		})

		cfg := tpmutil.CreateConfig{
			ParentHandle: handle,
			InPublic:     tpmutil.ECCSRKTemplate,
			SealingData:  []byte("secret data"),
		}

		err := cfg.CheckAndSetDefault()
		if err == nil {
			t.Error("Expected error when SealingData is provided with non-KeyedHash template")
		}

		expectedMsg := "invalid input: SealingData can only be provided if InPublic.Type is TPMAlgKeyedHash"
		if err != nil && err.Error() != expectedMsg {
			t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
		}
	})

	t.Run("SealingData with SensitiveDataOrigin set", func(t *testing.T) {
		handle := tpmutil.NewHandle(&tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000001),
			Name:   tpm2.TPM2BName{Buffer: []byte("test")},
		})

		cfg := tpmutil.CreateConfig{
			ParentHandle: handle,
			InPublic: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgKeyedHash,
				ObjectAttributes: tpm2.TPMAObject{
					SensitiveDataOrigin: true,
				},
			},
			SealingData: []byte("secret data"),
		}

		err := cfg.CheckAndSetDefault()
		if err == nil {
			t.Error("Expected error when SealingData is provided with SensitiveDataOrigin set")
		}

		expectedMsg := "invalid input: SealingData cannot be provided if InPublic.ObjectAttributes.SensitiveDataOrigin is set"
		if err != nil && err.Error() != expectedMsg {
			t.Errorf("Expected error message %q, got %q", expectedMsg, err.Error())
		}
	})

}
