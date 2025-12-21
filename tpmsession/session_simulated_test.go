package tpmsession_test

import (
	"crypto"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/loicsikidi/go-tpm-kit/tpmsession"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

// setTestAuthProvider sets a test auth provider and returns a cleanup function
func setTestAuthProvider(authValue []byte, returnErr error) func() {
	testPrompt := func() ([]byte, error) {
		if returnErr != nil {
			return nil, returnErr
		}
		return authValue, nil
	}
	tpmsession.PromptAuthValue.Store(&testPrompt)

	return func() {
		// Restore default by calling init logic manually
		defaultPrompt := func() ([]byte, error) {
			return nil, errors.New("default prompt should not be called in tests")
		}
		tpmsession.PromptAuthValue.Store(&defaultPrompt)
	}
}

// setupTPM creates a TPM simulator and returns it along with a cleanup function.
func setupTPM(t *testing.T) (transport.TPMCloser, func()) {
	t.Helper()
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("failed to open TPM simulator: %v", err)
	}

	cleanup := func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("failed to close TPM simulator: %v", err)
		}
	}

	return tpm, cleanup
}

// getSRK gets or creates a persistent Storage Root Key for testing.
func getSRK(t *testing.T, tpm transport.TPM, handle tpm2.TPMHandle) (name, public []byte) {
	t.Helper()

	h, err := tpmutil.GetSKRHandle(tpm, &tpmutil.ParentConfig{
		Handle:    tpmutil.NewHandle(handle),
		KeyFamily: tpmutil.RSA,
		Hierarchy: tpm2.TPMRHOwner,
	})
	if err != nil {
		t.Fatalf("GetSKRHandle failed: %v", err)
	}

	// Read the public key to get the bytes
	readPubResp, err := tpm2.ReadPublic{
		ObjectHandle: h.Handle(),
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	return readPubResp.Name.Buffer, readPubResp.OutPublic.Bytes()
}

// createSealedObject creates a sealed data object for testing bound sessions.
func createSealedObject(t *testing.T, tpm transport.TPM, handle tpm2.TPMHandle, authValue, data []byte) (name []byte) {
	t.Helper()

	// Define the persistent handle for the sealed object
	persistHandle := tpm2.TPMHandle(0x81000002)

	// Evict existing handle if present
	evictPersistentHandle(t, tpm, persistHandle)

	// Get SRK handle
	srk := tpm2.NamedHandle{
		Handle: handle,
		Name:   tpm2.TPM2BName{},
	}

	// Read SRK name
	readPubResp, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}
	srk.Name = readPubResp.Name

	// Create sealed object
	createResp, err := tpm2.Create{
		ParentHandle: srk,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:     true,
				FixedParent:  true,
				UserWithAuth: true,
				NoDA:         true,
			},
		}),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: authValue,
				},
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{
					Buffer: data,
				}),
			},
		},
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Load the object
	loadResp, err := tpm2.Load{
		ParentHandle: srk,
		InPrivate:    createResp.OutPrivate,
		InPublic:     createResp.OutPublic,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer tpm2.FlushContext{FlushHandle: loadResp.ObjectHandle}.Execute(tpm)

	// Make it persistent
	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
		},
		PersistentHandle: persistHandle,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("EvictControl failed: %v", err)
	}

	// Register cleanup to evict the handle after the test
	t.Cleanup(func() {
		evictPersistentHandle(t, tpm, persistHandle)
	})

	return loadResp.Name.Buffer
}

func TestAuthProvider_ErrorHandling(t *testing.T) {
	tpm, cleanup := setupTPM(t)
	defer cleanup()

	// Create sealed object
	getSRK(t, tpm, 0x81000001)
	authValue := []byte("testpassword")
	sealedData := []byte("secret data")
	objName := createSealedObject(t, tpm, 0x81000001, authValue, sealedData)

	key := tpmsession.SessionKey{
		SessionType: tpmsession.BoundSession,
		Handle:      0x81000002,
		Name:        tpm2.TPM2BName{Buffer: objName},
	}

	t.Run("auth provider returns error", func(t *testing.T) {
		expectedErr := errors.New("auth provider error")
		defer setTestAuthProvider(nil, expectedErr)()

		_, err := tpmsession.NewSessionManager(tpm, &key)
		if err == nil {
			t.Fatal("expected error from auth provider")
		}
		if !errors.Is(err, expectedErr) {
			t.Errorf("expected error to wrap auth provider error, got: %v", err)
		}
	})
}

func TestNewSessionManager_HandleValidation(t *testing.T) {
	tpm, cleanup := setupTPM(t)
	defer cleanup()

	// Create SRK for valid handle tests
	name, _ := getSRK(t, tpm, 0x81000001)

	tests := []struct {
		name        string
		key         tpmsession.SessionKey
		setupAuth   bool
		authValue   []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "persistent handle - valid",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.BoundSession,
				Handle:      0x81000001, // persistent handle
				Name:        tpm2.TPM2BName{Buffer: name},
			},
			setupAuth: true,
			authValue: []byte("test"),
			wantErr:   false,
		},
		{
			name: "transient handle - invalid",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.BoundSession,
				Handle:      0x80000001, // transient handle
				Name:        tpm2.TPM2BName{Buffer: name},
			},
			setupAuth:   true,
			authValue:   []byte("test"),
			wantErr:     true,
			errContains: "must be a persistent TPM handle",
		},
		{
			name: "owner handle - invalid",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.BoundSession,
				Handle:      0x40000001, // owner/platform/null handle range
				Name:        tpm2.TPM2BName{Buffer: name},
			},
			setupAuth:   true,
			authValue:   []byte("test"),
			wantErr:     true,
			errContains: "must be a persistent TPM handle",
		},
		{
			name: "nv index handle - invalid",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.BoundSession,
				Handle:      0x01000001, // NV index handle
				Name:        tpm2.TPM2BName{Buffer: name},
			},
			setupAuth:   true,
			authValue:   []byte("test"),
			wantErr:     true,
			errContains: "must be a persistent TPM handle",
		},
		{
			name: "policy session handle - invalid",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.BoundSession,
				Handle:      0x03000001, // policy session handle
				Name:        tpm2.TPM2BName{Buffer: name},
			},
			setupAuth:   true,
			authValue:   []byte("test"),
			wantErr:     true,
			errContains: "must be a persistent TPM handle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupAuth {
				defer setTestAuthProvider(tt.authValue, nil)()
			}

			_, err := tpmsession.NewSessionManager(tpm, &tt.key)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if tt.errContains != "" && !errors.Is(err, tpmsession.ErrInvalidHandleType) {
					t.Errorf("expected error to be ErrInvalidHandleType, got: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestSessionManager_IntegrationWithTPMCommands(t *testing.T) {
	tpm, cleanup := setupTPM(t)
	defer cleanup()

	// Create SRK
	srkName, srkPublic := getSRK(t, tpm, 0x81000001)
	srkPublicObj := tpm2.BytesAs2B[tpm2.TPMTPublic](srkPublic)

	t.Run("bound session validates successfully", func(t *testing.T) {
		// Create sealed object with auth value
		authValue := []byte("testpassword")
		sealedData := []byte("secret data")
		objName := createSealedObject(t, tpm, 0x81000001, authValue, sealedData)

		key := tpmsession.SessionKey{
			SessionType: tpmsession.BoundSession,
			Handle:      0x81000002,
			Name:        tpm2.TPM2BName{Buffer: objName},
		}

		defer setTestAuthProvider(authValue, nil)()

		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		if sm.GetSession() == nil {
			t.Fatal("expected non-nil session")
		}
	})

	t.Run("salted session validates successfully", func(t *testing.T) {
		key := tpmsession.SessionKey{
			SessionType: tpmsession.SaltedSession,
			Handle:      0x81000001,
			Name:        tpm2.TPM2BName{Buffer: srkName},
			Public:      &srkPublicObj,
		}

		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		if sm.GetSession() == nil {
			t.Fatal("expected non-nil session")
		}
	})

	t.Run("session can be created from JSON", func(t *testing.T) {
		original := tpmsession.SessionKey{
			SessionType: tpmsession.SaltedSession,
			Handle:      0x81000001,
			Name:        tpm2.TPM2BName{Buffer: srkName},
			Public:      &srkPublicObj,
		}

		// Marshal to JSON
		blob, err := original.Marshal()
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		// Unmarshal from JSON
		key, err := tpmsession.ParseSessionKey(blob)
		if err != nil {
			t.Fatalf("ParseSessionKey failed: %v", err)
		}

		// Validate
		if err := key.CheckAndSetDefault(); err != nil {
			t.Fatalf("CheckAndSetDefault failed: %v", err)
		}

		// Create session manager with deserialized key
		sm, err := tpmsession.NewSessionManager(tpm, key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		if sm.GetSession() == nil {
			t.Fatal("expected non-nil session")
		}
	})
}

// TestSessionManager_EncryptedCommands verifies that GetSession() returns
// sessions that work correctly with TPM commands supporting parameter encryption.
// This validates that the session encryption/decryption is properly configured.
func TestSessionManager_EncryptedCommands(t *testing.T) {
	tpm, cleanup := setupTPM(t)
	defer cleanup()

	// Create SRK for salted session
	name, public := getSRK(t, tpm, 0x81000001)
	publicObj := tpm2.BytesAs2B[tpm2.TPMTPublic](public)

	key := tpmsession.SessionKey{
		SessionType: tpmsession.SaltedSession,
		Handle:      0x81000001,
		Name:        tpm2.TPM2BName{Buffer: name},
		Public:      &publicObj,
	}

	t.Run("CreatePrimary with encrypted session", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		session := sm.GetSession()
		if session == nil {
			t.Fatal("expected non-nil session")
		}

		// Use the session with CreatePrimary command using RSA SRK template
		createPrimCmd := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
		}

		createResp, err := createPrimCmd.Execute(tpm, session)
		if err != nil {
			t.Fatalf("CreatePrimary with encrypted session failed: %v", err)
		}

		// Verify we got a valid handle back
		if createResp.ObjectHandle == 0 {
			t.Fatal("expected non-zero object handle")
		}

		// Clean up
		_, err = tpm2.FlushContext{FlushHandle: createResp.ObjectHandle}.Execute(tpm)
		if err != nil {
			t.Errorf("FlushContext failed: %v", err)
		}
	})

	t.Run("CreatePrimary with different hash algorithms", func(t *testing.T) {
		testCases := []struct {
			name     string
			hash     crypto.Hash
			template tpm2.TPMTPublic
		}{
			{"SHA256-AES128-RSA", crypto.SHA256, tpm2.RSASRKTemplate},
			{"SHA512-AES256-ECC", crypto.SHA512, tpm2.ECCSRKTemplate},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				sm, err := tpmsession.NewSessionManager(tpm, &key)
				if err != nil {
					t.Fatalf("NewSessionManager failed: %v", err)
				}

				session := sm.WithHashAlg(tc.hash).GetSession()

				createPrimCmd := tpm2.CreatePrimary{
					PrimaryHandle: tpm2.TPMRHOwner,
					InPublic:      tpm2.New2B(tc.template),
				}

				createResp, err := createPrimCmd.Execute(tpm, session)
				if err != nil {
					t.Fatalf("CreatePrimary failed with %s: %v", tc.name, err)
				}

				if createResp.ObjectHandle == 0 {
					t.Fatal("expected non-zero object handle")
				}

				// Clean up
				tpm2.FlushContext{FlushHandle: createResp.ObjectHandle}.Execute(tpm)
			})
		}
	})

	t.Run("Create with encrypted session", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		session := sm.GetSession()

		// Create a signing key under the SRK using encrypted session
		createCmd := tpm2.Create{
			ParentHandle: tpm2.NamedHandle{
				Handle: 0x81000001,
				Name:   tpm2.TPM2BName{Buffer: name},
			},
			InPublic: tpm2.New2B(tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					SignEncrypt:         true,
					FixedTPM:            true,
					FixedParent:         true,
					SensitiveDataOrigin: true,
					UserWithAuth:        true,
				},
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 2048,
					},
				),
			}),
		}

		createResp, err := createCmd.Execute(tpm, session)
		if err != nil {
			t.Fatalf("Create with encrypted session failed: %v", err)
		}

		// Verify we got valid output
		if len(createResp.OutPrivate.Buffer) == 0 {
			t.Fatal("expected non-empty private area")
		}
		if len(createResp.OutPublic.Bytes()) == 0 {
			t.Fatal("expected non-empty public area")
		}
	})

	t.Run("ReadPublic with encrypted session", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		session := sm.GetSession(tpmsession.EncryptOut)

		readPublicCmd := tpm2.ReadPublic{
			ObjectHandle: tpm2.NamedHandle{
				Handle: key.Handle,
				Name:   key.Name, // Use the name from CreatePrimary
			},
		}

		_, err = readPublicCmd.Execute(tpm, session)
		if err != nil {
			t.Fatalf("ReadPublic with encrypted session failed: %v", err)
		}
	})
}

func TestSessionManager_WithHashAlg(t *testing.T) {
	tpm, cleanup := setupTPM(t)
	defer cleanup()

	// Create SRK
	name, public := getSRK(t, tpm, 0x81000001)
	publicObj := tpm2.BytesAs2B[tpm2.TPMTPublic](public)

	key := tpmsession.SessionKey{
		SessionType: tpmsession.SaltedSession,
		Handle:      0x81000001,
		Name:        tpm2.TPM2BName{Buffer: name},
		Public:      &publicObj,
	}

	t.Run("default is SHA256 with AES-128", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		// Default should work
		if sm.GetSession() == nil {
			t.Fatal("expected non-nil session with defaults")
		}
	})

	t.Run("with SHA384 uses AES-192", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		sm.WithHashAlg(crypto.SHA384)

		session := sm.GetSession()
		if session == nil {
			t.Fatal("expected non-nil session with SHA384")
		}
	})

	t.Run("with SHA512 uses AES-256", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		sm.WithHashAlg(crypto.SHA512)

		session := sm.GetSession()
		if session == nil {
			t.Fatal("expected non-nil session with SHA512")
		}
	})

	t.Run("with SHA1 uses AES-128", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		sm.WithHashAlg(crypto.SHA1)

		session := sm.GetSession()
		if session == nil {
			t.Fatal("expected non-nil session with SHA1")
		}
	})

	t.Run("unsupported hash falls back to SHA256 with AES-128", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		// crypto.MD5 is not supported by TPM, should fallback to SHA256
		sm.WithHashAlg(crypto.MD5)

		session := sm.GetSession()
		if session == nil {
			t.Fatal("expected non-nil session with fallback")
		}
	})

	t.Run("method chaining works", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		// Test that we can chain the method call
		session := sm.WithHashAlg(crypto.SHA384).GetSession()
		if session == nil {
			t.Fatal("expected non-nil session with method chaining")
		}
	})

	t.Run("works with bound sessions too", func(t *testing.T) {
		// Create sealed object
		authValue := []byte("testpassword")
		sealedData := []byte("secret data")
		objName := createSealedObject(t, tpm, 0x81000001, authValue, sealedData)

		boundKey := tpmsession.SessionKey{
			SessionType: tpmsession.BoundSession,
			Handle:      0x81000002,
			Name:        tpm2.TPM2BName{Buffer: objName},
		}

		defer setTestAuthProvider(authValue, nil)()

		sm, err := tpmsession.NewSessionManager(tpm, &boundKey)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		sm.WithHashAlg(crypto.SHA384)

		session := sm.GetSession()
		if session == nil {
			t.Fatal("expected non-nil session for bound session with SHA384")
		}
	})
}

func TestSessionManager_AuditSession(t *testing.T) {
	tpm, cleanup := setupTPM(t)
	defer cleanup()

	// Create SRK
	name, public := getSRK(t, tpm, 0x81000001)
	publicObj := tpm2.BytesAs2B[tpm2.TPMTPublic](public)

	// Create an AK (Attestation Key) for signing audit digests
	akHandle := createAttestationKey(t, tpm, 0x81000001)

	key := tpmsession.SessionKey{
		SessionType: tpmsession.SaltedSession,
		Handle:      0x81000001,
		Name:        tpm2.TPM2BName{Buffer: name},
		Public:      &publicObj,
	}

	t.Run("start and stop audit session", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		// Start audit session with config
		config := &tpmsession.AuditConfig{
			AKHandle: akHandle,
			HashAlg:  tpm2.TPMAlgSHA256,
		}
		err = sm.StartAuditSession(config)
		if err != nil {
			t.Fatalf("StartAuditSession failed: %v", err)
		}

		// Get session (should return audit session)
		session := sm.GetSession()
		if session == nil {
			t.Fatal("expected non-nil session")
		}

		// Execute a command with the audit session
		_, err = tpm2.ReadPublic{
			ObjectHandle: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(0x81000001),
				Name:   key.Name,
			},
		}.Execute(tpm, session)
		if err != nil {
			t.Fatalf("ReadPublic with audit session failed: %v", err)
		}

		// Stop audit session and get attestation
		result, err := sm.StopAuditSession()
		if err != nil {
			t.Fatalf("StopAuditSession failed: %v", err)
		}

		if result == nil {
			t.Fatal("expected non-nil AuditResult")
		}

		if result.Attestation == nil {
			t.Fatal("expected non-nil attestation")
		}

		if result.Signature == nil {
			t.Fatal("expected non-nil signature")
		}
	})

	t.Run("cannot start audit session twice", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		config := &tpmsession.AuditConfig{
			AKHandle: akHandle,
			HashAlg:  tpm2.TPMAlgSHA256,
		}
		err = sm.StartAuditSession(config)
		if err != nil {
			t.Fatalf("StartAuditSession failed: %v", err)
		}

		// Try to start again
		err = sm.StartAuditSession(config)
		if err == nil {
			t.Fatal("expected error when starting audit session twice")
		}

		// Cleanup
		sm.StopAuditSession()
	})

	t.Run("cannot stop without starting", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		_, err = sm.StopAuditSession()
		if err == nil {
			t.Fatal("expected error when stopping without starting audit session")
		}
	})

	t.Run("nil akHandle returns error", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		config := &tpmsession.AuditConfig{
			AKHandle: nil,
			HashAlg:  tpm2.TPMAlgSHA256,
		}
		err = sm.StartAuditSession(config)
		if err == nil {
			t.Fatal("expected error for nil akHandle")
		}
	})

	t.Run("nil config returns error", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		err = sm.StartAuditSession(nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
	})

	t.Run("config with qualifying data", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		config := &tpmsession.AuditConfig{
			AKHandle:       akHandle,
			HashAlg:        tpm2.TPMAlgSHA256,
			QualifyingData: []byte("my-nonce-12345"),
		}
		err = sm.StartAuditSession(config)
		if err != nil {
			t.Fatalf("StartAuditSession failed: %v", err)
		}

		// Execute a command
		session := sm.GetSession()
		_, err = tpm2.ReadPublic{
			ObjectHandle: tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(0x81000001),
				Name:   key.Name,
			},
		}.Execute(tpm, session)
		if err != nil {
			t.Fatalf("ReadPublic with audit session failed: %v", err)
		}

		// Stop audit session and verify
		result, err := sm.StopAuditSession()
		if err != nil {
			t.Fatalf("StopAuditSession failed: %v", err)
		}

		if result == nil {
			t.Fatal("expected non-nil AuditResult")
		}
	})
}

// evictPersistentHandle removes a persistent handle if it exists.
func evictPersistentHandle(t *testing.T, tpm transport.TPM, handle tpm2.TPMHandle) {
	t.Helper()

	// Try to read the handle to see if it exists
	readPubResp, err := tpm2.ReadPublic{
		ObjectHandle: handle,
	}.Execute(tpm)
	if err != nil {
		// Handle doesn't exist, nothing to evict
		return
	}

	// Evict the handle
	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: handle,
			Name:   readPubResp.Name,
		},
		PersistentHandle: handle,
	}.Execute(tpm)
	if err != nil {
		t.Logf("Warning: failed to evict handle 0x%x: %v", handle, err)
	}
}

// createAttestationKey creates an attestation key for testing audit sessions.
func createAttestationKey(t *testing.T, tpm transport.TPM, srkHandle tpm2.TPMHandle) tpmutil.Handle {
	t.Helper()

	// Define the persistent handle for the AK
	akHandle := tpm2.TPMHandle(0x81000003)

	// Evict existing handle if present
	evictPersistentHandle(t, tpm, akHandle)

	// Read SRK name
	readPubResp, err := tpm2.ReadPublic{
		ObjectHandle: srkHandle,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	srk := tpm2.NamedHandle{
		Handle: srkHandle,
		Name:   readPubResp.Name,
	}

	// Create AK (RSA signing key)
	createResp, err := tpm2.Create{
		ParentHandle: srk,
		InPublic: tpm2.New2B(tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				Restricted:          true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgRSASSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgRSASSA,
							&tpm2.TPMSSigSchemeRSASSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
					KeyBits: 2048,
				},
			),
		}),
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("Create AK failed: %v", err)
	}

	// Load the AK
	loadResp, err := tpm2.Load{
		ParentHandle: srk,
		InPrivate:    createResp.OutPrivate,
		InPublic:     createResp.OutPublic,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("Load AK failed: %v", err)
	}

	// Make it persistent
	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: loadResp.ObjectHandle,
			Name:   loadResp.Name,
		},
		PersistentHandle: akHandle,
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("EvictControl failed: %v", err)
	}

	// Register cleanup to evict the handle after the test
	t.Cleanup(func() {
		evictPersistentHandle(t, tpm, akHandle)
	})

	return tpmutil.NewHandle(akHandle)
}
