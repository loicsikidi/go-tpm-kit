package tpmsession_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmsession"
)

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
			name: "salted session missing public",
			key: tpmsession.SessionKey{
				SessionType: tpmsession.SaltedSession,
				Handle:      0x81000001,
				Name:        tpm2.TPM2BName{Buffer: name},
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

		// Unmarshal using ParseSessionKey
		restored, err := tpmsession.ParseSessionKey(blob)
		if err != nil {
			t.Fatalf("ParseSessionKey failed: %v", err)
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

		restored, err := tpmsession.ParseSessionKey(blob)
		if err != nil {
			t.Fatalf("ParseSessionKey failed: %v", err)
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

func TestCreateSessionKey(t *testing.T) {
	tpm, cleanup := setupTPM(t)
	defer cleanup()

	// Create SRK for testing
	name, public := getSRK(t, tpm, 0x81000001)

	t.Run("create bound session key", func(t *testing.T) {
		key, err := tpmsession.CreateSessionKey(tpm, tpmsession.BoundSession, 0x81000001)
		if err != nil {
			t.Fatalf("CreateSessionKey failed: %v", err)
		}

		if key.SessionType != tpmsession.BoundSession {
			t.Errorf("expected BoundSession, got %v", key.SessionType)
		}

		if key.Handle != 0x81000001 {
			t.Errorf("expected handle 0x81000001, got 0x%08X", key.Handle)
		}

		if !bytes.Equal(key.Name.Buffer, name) {
			t.Errorf("name mismatch: got %x, want %x", key.Name.Buffer, name)
		}

		if key.Public != nil {
			t.Error("Public should be nil for bound session")
		}
	})

	t.Run("create salted session key", func(t *testing.T) {
		key, err := tpmsession.CreateSessionKey(tpm, tpmsession.SaltedSession, 0x81000001)
		if err != nil {
			t.Fatalf("CreateSessionKey failed: %v", err)
		}

		if key.SessionType != tpmsession.SaltedSession {
			t.Errorf("expected SaltedSession, got %v", key.SessionType)
		}

		if key.Handle != 0x81000001 {
			t.Errorf("expected handle 0x81000001, got 0x%08X", key.Handle)
		}

		if !bytes.Equal(key.Name.Buffer, name) {
			t.Errorf("name mismatch: got %x, want %x", key.Name.Buffer, name)
		}

		if key.Public == nil {
			t.Fatal("Public should not be nil for salted session")
		}

		// Verify Public matches what we expect
		publicObj := tpm2.BytesAs2B[tpm2.TPMTPublic](public)
		expectedBytes := tpm2.Marshal(publicObj)
		actualBytes := tpm2.Marshal(*key.Public)
		if !bytes.Equal(actualBytes, expectedBytes) {
			t.Error("Public area mismatch")
		}
	})

	t.Run("invalid session type", func(t *testing.T) {
		_, err := tpmsession.CreateSessionKey(tpm, tpmsession.UnspecifiedSession, 0x81000001)
		if err == nil {
			t.Fatal("expected error for unspecified session type")
		}
	})

	t.Run("nonexistent handle", func(t *testing.T) {
		_, err := tpmsession.CreateSessionKey(tpm, tpmsession.BoundSession, 0x81009999)
		if err == nil {
			t.Fatal("expected error for nonexistent handle")
		}
	})

	t.Run("invalid handle type - transient", func(t *testing.T) {
		_, err := tpmsession.CreateSessionKey(tpm, tpmsession.BoundSession, 0x80000001)
		if err == nil {
			t.Fatal("expected error for transient handle")
		}
		if !errors.Is(err, tpmsession.ErrInvalidHandleType) {
			t.Errorf("expected ErrInvalidHandleType, got: %v", err)
		}
	})

	t.Run("created key can be marshaled and used", func(t *testing.T) {
		// Create a salted session key
		key, err := tpmsession.CreateSessionKey(tpm, tpmsession.SaltedSession, 0x81000001)
		if err != nil {
			t.Fatalf("CreateSessionKey failed: %v", err)
		}

		// Marshal it
		blob, err := key.Marshal()
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}

		// Unmarshal it
		restored, err := tpmsession.ParseSessionKey(blob)
		if err != nil {
			t.Fatalf("ParseSessionKey failed: %v", err)
		}

		// Create session manager with restored key
		sm, err := tpmsession.NewSessionManager(tpm, restored)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		if sm.GetSession() == nil {
			t.Fatal("expected non-nil session")
		}
	})
}
