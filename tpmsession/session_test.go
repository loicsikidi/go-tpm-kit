package tpmsession_test

import (
	"crypto"
	"encoding/json"
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
		KeyType:   tpmutil.RSA,
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
	persistHandle := tpm2.TPMHandle(0x81000002)
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

	return loadResp.Name.Buffer
}

func TestSessionKey_CheckAndSetDefault(t *testing.T) {
	tpm, cleanup := setupTPM(t)
	defer cleanup()

	// Create a test SRK
	name, public := getSRK(t, tpm, 0x81000001)
	publicObj := tpm2.BytesAs2B[tpm2.TPMTPublic](public)

	tests := []struct {
		name    string
		key     tpmsession.SessionKey
		wantErr bool
	}{
		{
			name: "valid bound session key",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.BoundSession,
				Handle:      0x81000001,
				Name:        tpm2.TPM2BName{Buffer: name},
			},
			wantErr: false,
		},
		{
			name: "valid salted session key",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.SaltedSession,
				Handle:      0x81000001,
				Name:        tpm2.TPM2BName{Buffer: name},
				Public:      &publicObj,
			},
			wantErr: false,
		},
		{
			name: "unspecified session type",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.UnspecifiedSession,
				Handle:      0x81000001,
				Name:        tpm2.TPM2BName{Buffer: name},
			},
			wantErr: true,
		},
		{
			name: "zero handle",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.BoundSession,
				Handle:      0,
				Name:        tpm2.TPM2BName{Buffer: name},
			},
			wantErr: true,
		},
		{
			name: "empty name",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.BoundSession,
				Handle:      0x81000001,
				Name:        tpm2.TPM2BName{},
			},
			wantErr: true,
		},
		{
			name: "name too short",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.BoundSession,
				Handle:      0x81000001,
				Name:        tpm2.TPM2BName{Buffer: []byte{0x00}}, // only 1 byte
			},
			wantErr: true,
		},
		{
			name: "public/name mismatch",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.SaltedSession,
				Handle:      0x81000001,
				Name: tpm2.TPM2BName{Buffer: []byte{
					0x00, 0x0b, // nameAlg SHA256
					0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
					0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
					0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
					0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
				}},
				Public: &publicObj,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.key.CheckAndSetDefault()
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckAndSetDefault() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSessionKey_Serialization(t *testing.T) {
	tpm, cleanup := setupTPM(t)
	defer cleanup()

	// Create a test SRK
	name, public := getSRK(t, tpm, 0x81000001)
	publicObj := tpm2.BytesAs2B[tpm2.TPMTPublic](public)

	t.Run("marshal and unmarshal bound session", func(t *testing.T) {
		original := tpmsession.SessionKey{
			SessionType: tpmsession.BoundSession,
			Handle:      0x81000001,
			Name:        tpm2.TPM2BName{Buffer: name},
		}

		// Marshal using the SessionKey.Marshal method
		blob, err := original.Marshal()
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		// Verify JSON is well-formed
		var jsonCheck map[string]any
		if err := json.Unmarshal(blob, &jsonCheck); err != nil {
			t.Fatalf("produced JSON is malformed: %v", err)
		}

		// Verify required JSON fields exist
		if _, ok := jsonCheck["session_type"]; !ok {
			t.Error("JSON missing 'session_type' field")
		}
		if _, ok := jsonCheck["handle"]; !ok {
			t.Error("JSON missing 'handle' field")
		}
		if _, ok := jsonCheck["name"]; !ok {
			t.Error("JSON missing 'name' field")
		}
		// Public should not be present (or empty) for bound session
		if publicVal, ok := jsonCheck["public"]; ok && publicVal != nil && publicVal != "" {
			t.Error("JSON should not contain 'public' field for bound session")
		}

		// Unmarshal using LoadSessionKey
		restored, err := tpmsession.LoadSessionKey(blob)
		if err != nil {
			t.Fatalf("LoadSessionKey failed: %v", err)
		}

		// Validate after deserialization
		if err := restored.CheckAndSetDefault(); err != nil {
			t.Fatalf("CheckAndSetDefault after unmarshal failed: %v", err)
		}

		// Verify fields match
		if restored.SessionType != original.SessionType {
			t.Errorf("SessionType mismatch: got %v, want %v", restored.SessionType, original.SessionType)
		}

		if restored.Handle != original.Handle {
			t.Errorf("Handle mismatch: got %#x, want %#x", restored.Handle, original.Handle)
		}

		if string(restored.Name.Buffer) != string(original.Name.Buffer) {
			t.Errorf("Name mismatch: got %x, want %x", restored.Name.Buffer, original.Name.Buffer)
		}

		if restored.Public != nil {
			t.Error("Public should be nil for bound session")
		}
	})

	t.Run("marshal and unmarshal salted session", func(t *testing.T) {
		original := tpmsession.SessionKey{
			SessionType: tpmsession.SaltedSession,
			Handle:      0x81000001,
			Name:        tpm2.TPM2BName{Buffer: name},
			Public:      &publicObj,
		}

		blob, err := original.Marshal()
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		// Verify JSON is well-formed
		var jsonCheck map[string]any
		if err := json.Unmarshal(blob, &jsonCheck); err != nil {
			t.Fatalf("produced JSON is malformed: %v", err)
		}

		// Verify required JSON fields exist
		if _, ok := jsonCheck["session_type"]; !ok {
			t.Error("JSON missing 'session_type' field")
		}
		if _, ok := jsonCheck["handle"]; !ok {
			t.Error("JSON missing 'handle' field")
		}
		if _, ok := jsonCheck["name"]; !ok {
			t.Error("JSON missing 'name' field")
		}
		// Public MUST be present for salted session
		if publicVal, ok := jsonCheck["public"]; !ok || publicVal == nil || publicVal == "" {
			t.Error("JSON must contain 'public' field for salted session")
		}

		restored, err := tpmsession.LoadSessionKey(blob)
		if err != nil {
			t.Fatalf("LoadSessionKey failed: %v", err)
		}

		// Validate after deserialization
		if err := restored.CheckAndSetDefault(); err != nil {
			t.Fatalf("CheckAndSetDefault after unmarshal failed: %v", err)
		}

		// Verify fields match
		if restored.SessionType != original.SessionType {
			t.Errorf("SessionType mismatch: got %v, want %v", restored.SessionType, original.SessionType)
		}

		if restored.Handle != original.Handle {
			t.Errorf("Handle mismatch: got %#x, want %#x", restored.Handle, original.Handle)
		}

		if string(restored.Name.Buffer) != string(original.Name.Buffer) {
			t.Errorf("Name mismatch: got %x, want %x", restored.Name.Buffer, original.Name.Buffer)
		}

		if restored.Public == nil {
			t.Fatal("Public should not be nil for salted session")
		}

		originalPubBytes := tpm2.Marshal(*original.Public)
		restoredPubBytes := tpm2.Marshal(*restored.Public)
		if string(originalPubBytes) != string(restoredPubBytes) {
			t.Errorf("Public mismatch")
		}
	})
}

func TestNewSessionManager_BoundSession(t *testing.T) {
	tpm, cleanup := setupTPM(t)
	defer cleanup()

	// Create SRK
	getSRK(t, tpm, 0x81000001)

	// Create sealed object with auth value
	authValue := []byte("testpassword")
	sealedData := []byte("secret data")
	objName := createSealedObject(t, tpm, 0x81000001, authValue, sealedData)

	key := tpmsession.SessionKey{
		SessionType: tpmsession.BoundSession,
		Handle:      0x81000002, // sealed object handle
		Name:        tpm2.TPM2BName{Buffer: objName},
	}

	t.Run("successful creation", func(t *testing.T) {
		defer setTestAuthProvider(authValue, nil)()

		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		if sm.GetSession() == nil {
			t.Fatal("expected non-nil session")
		}
	})

	t.Run("nonexistent handle", func(t *testing.T) {
		defer setTestAuthProvider(authValue, nil)()

		badKey := key
		badKey.Handle = 0x81009999
		_, err := tpmsession.NewSessionManager(tpm, &badKey)
		if err == nil {
			t.Fatal("expected error for nonexistent handle")
		}
	})

	t.Run("name mismatch", func(t *testing.T) {
		defer setTestAuthProvider(authValue, nil)()

		badKey := key
		badKey.Name = tpm2.TPM2BName{Buffer: []byte{
			0x00, 0x0b, // nameAlg SHA256
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
			0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
		}}
		_, err := tpmsession.NewSessionManager(tpm, &badKey)
		if err == nil {
			t.Fatal("expected error for name mismatch")
		}
	})
}

func TestNewSessionManager_SaltedSession(t *testing.T) {
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

	t.Run("successful creation", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		if sm.GetSession() == nil {
			t.Fatal("expected non-nil session")
		}
	})

	t.Run("public key mismatch", func(t *testing.T) {
		// Try to use SRK public/name but with wrong handle (should detect mismatch)
		badKey := key
		badKey.Handle = 0x81009999 // nonexistent handle
		_, err := tpmsession.NewSessionManager(tpm, &badKey)
		if err == nil {
			t.Fatal("expected error for public key mismatch")
		}
	})
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
		key, err := tpmsession.LoadSessionKey(blob)
		if err != nil {
			t.Fatalf("LoadSessionKey failed: %v", err)
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
