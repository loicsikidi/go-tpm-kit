package tpmutil

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm/tpm2"
	tpmkit "github.com/loicsikidi/go-tpm-kit"
	"github.com/loicsikidi/go-tpm-kit/internal/utils/testutil"
)

func TestHandleType_String(t *testing.T) {
	tests := []struct {
		name     string
		ht       HandleType
		expected string
	}{
		{"NVIndex", NVIndexHandle, "NVIndex"},
		{"PolicySession", PolicySessionHandle, "PolicySession"},
		{"Permanent", PermanentHandle, "Permanent"},
		{"Persistent", PersistentHandle, "Persistent"},
		{"Transient", TransientHandle, "Transient"},
		{"Unspecified", UnspecifiedHandle, "unknown(0)"},
		{"Unknown", HandleType(99), "unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ht.String()
			if got != tt.expected {
				t.Errorf("HandleType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsMso(t *testing.T) {
	tests := []struct {
		name     string
		handle   tpm2.TPMHandle
		mso      uint32
		expected bool
	}{
		{
			name:     "NVIndex handle matches NVIndex MSO",
			handle:   tpm2.TPMHandle(0x01000001),
			mso:      uint32(tpm2.TPMHTNVIndex),
			expected: true,
		},
		{
			name:     "Transient handle matches Transient MSO",
			handle:   tpm2.TPMHandle(0x80000001),
			mso:      uint32(tpm2.TPMHTTransient),
			expected: true,
		},
		{
			name:     "Persistent handle matches Persistent MSO",
			handle:   tpmkit.SRKHandle,
			mso:      uint32(tpm2.TPMHTPersistent),
			expected: true,
		},
		{
			name:     "Handle does not match MSO",
			handle:   tpm2.TPMHandle(0x01000001),
			mso:      uint32(tpm2.TPMHTTransient),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMso(tt.handle, tt.mso)
			if got != tt.expected {
				t.Errorf("isMso() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIdentifyHandleType(t *testing.T) {
	tests := []struct {
		name         string
		handleValue  uint32
		expectedType HandleType
	}{
		{"NVIndex", 0x01000001, NVIndexHandle},
		{"PolicySession", 0x03000001, PolicySessionHandle},
		{"Permanent", 0x40000001, PermanentHandle},
		{"Persistent", 0x81000001, PersistentHandle},
		{"Transient", 0x80000001, TransientHandle},
		{"Unspecified", 0x00000001, UnspecifiedHandle},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namedHandle := tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(tt.handleValue),
				Name:   tpm2.TPM2BName{Buffer: []byte("test")},
			}
			h := NewHandle(&namedHandle)
			got := h.Type()
			if got != tt.expectedType {
				t.Errorf("GetType() = %v, want %v", got, tt.expectedType)
			}
		})
	}
}

func TestIsHandleOfType(t *testing.T) {
	tests := []struct {
		name         string
		handleValue  uint32
		checkType    HandleType
		expectedBool bool
	}{
		{"NVIndex is NVIndex", 0x01000001, NVIndexHandle, true},
		{"NVIndex is not Transient", 0x01000001, TransientHandle, false},
		{"Transient is Transient", 0x80000001, TransientHandle, true},
		{"Persistent is Persistent", 0x81000001, PersistentHandle, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namedHandle := tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(tt.handleValue),
				Name:   tpm2.TPM2BName{Buffer: []byte("test")},
			}
			h := NewHandle(&namedHandle)
			got := IsHandleOfType(h, tt.checkType)
			if got != tt.expectedBool {
				t.Errorf("IsHandleOfType() = %v, want %v", got, tt.expectedBool)
			}
		})
	}
}

func TestNewHandle(t *testing.T) {
	t.Run("NamedHandle", func(t *testing.T) {
		namedHandle := tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000001),
			Name:   tpm2.TPM2BName{Buffer: []byte("test-handle")},
		}

		h := NewHandle(&namedHandle)
		if h == nil {
			t.Fatal("NewHandle() returned nil")
		}
		if h.Handle() != tpm2.TPMHandle(0x80000001) {
			t.Errorf("Handle() = %v, want %v", h.Handle(), tpm2.TPMHandle(0x80000001))
		}
		if !bytes.Equal(h.Name().Buffer, []byte("test-handle")) {
			t.Errorf("Name() = %v, want %v", h.Name().Buffer, []byte("test-handle"))
		}
		if h.IsAuth() {
			t.Error("IsAuth() = true, want false")
		}
		if h.Type() != TransientHandle {
			t.Errorf("GetType() = %v, want %v", h.Type(), TransientHandle)
		}
	})
	t.Run("AuthHandle", func(t *testing.T) {
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(0x40000001),
			Name:   tpm2.TPM2BName{Buffer: []byte("auth-handle")},
		}

		h := NewHandle(&authHandle)
		if h == nil {
			t.Fatal("NewHandle() returned nil")
		}
		if h.Handle() != tpm2.TPMHandle(0x40000001) {
			t.Errorf("Handle() = %v, want %v", h.Handle(), tpm2.TPMHandle(0x40000001))
		}
		if !h.IsAuth() {
			t.Error("IsAuth() = false, want true")
		}
		if h.Type() != PermanentHandle {
			t.Errorf("GetType() = %v, want %v", h.Type(), PermanentHandle)
		}
	})

}

func TestNewHandleCloser(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}

	rsp, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary() failed: %v", err)
	}

	h := NewHandleCloser(thetpm, &rsp.ObjectHandle)
	if h == nil {
		t.Fatal("NewHandleCloser() returned nil")
	}
	if h.Type() != TransientHandle {
		t.Errorf("GetType() = %v, want %v", h.Type(), TransientHandle)
	}
	if h.IsAuth() {
		t.Error("IsAuth() = true, want false")
	}

	err = h.Close()
	if err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

func TestHandleCloser_CloseWithoutTPM(t *testing.T) {
	namedHandle := tpm2.NamedHandle{
		Handle: tpm2.TPMHandle(0x80000001),
		Name:   tpm2.TPM2BName{Buffer: []byte("test")},
	}

	h := &tpmHandle{
		handle: &namedHandle,
		tpm:    nil,
		isAuth: false,
	}

	err := h.Close()
	if err == nil {
		t.Error("Close() succeeded, want error")
	}
	if err != ErrMissingTpm {
		t.Errorf("Close() error = %v, want %v", err, ErrMissingTpm)
	}
}

func TestIsAuthHandle(t *testing.T) {
	tests := []struct {
		name     string
		handle   handle
		expected bool
	}{
		{
			name: "AuthHandle pointer",
			handle: &tpm2.AuthHandle{
				Handle: tpm2.TPMRHOwner,
				Name:   tpm2.TPM2BName{Buffer: []byte("owner")},
			},
			expected: true,
		},
		{
			name: "NamedHandle pointer",
			handle: &tpm2.NamedHandle{
				Handle: tpm2.TPMHandle(0x80000001),
				Name:   tpm2.TPM2BName{Buffer: []byte("test")},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAuthHandle(tt.handle)
			if got != tt.expected {
				t.Errorf("isAuthHandle() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAsHandle(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	t.Run("from TPMHandle", func(t *testing.T) {
		// Create a primary key to get a valid handle
		createPrimary := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
		}

		rsp, err := createPrimary.Execute(thetpm)
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer func() {
			tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(thetpm)
		}()

		h, err := ToHandle(thetpm, rsp.ObjectHandle)
		if err != nil {
			t.Fatalf("AsHandle() failed: %v", err)
		}
		if h == nil {
			t.Fatal("AsHandle() returned nil")
		}
		if h.Handle() != rsp.ObjectHandle {
			t.Errorf("Handle() = %v, want %v", h.Handle(), rsp.ObjectHandle)
		}
		if h.Type() != TransientHandle {
			t.Errorf("Type() = %v, want %v", h.Type(), TransientHandle)
		}
	})

	t.Run("from Handle interface", func(t *testing.T) {
		namedHandle := tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000001),
			Name:   tpm2.TPM2BName{Buffer: []byte("test-handle")},
		}
		originalHandle := NewHandle(&namedHandle)

		h, err := ToHandle(thetpm, originalHandle)
		if err != nil {
			t.Fatalf("AsHandle() failed: %v", err)
		}
		if h != originalHandle {
			t.Error("AsHandle() should return the same Handle when input is already a Handle")
		}
	})

	t.Run("invalid type", func(t *testing.T) {
		_, err := ToHandle(thetpm, "invalid-type")
		if err == nil {
			t.Error("AsHandle() succeeded with invalid type, want error")
		}
	})

	t.Run("invalid TPMHandle", func(t *testing.T) {
		// Use an invalid/non-existent handle
		_, err := ToHandle(thetpm, tpm2.TPMHandle(0x80999999))
		if err == nil {
			t.Error("AsHandle() succeeded with invalid TPMHandle, want error")
		}
	})
}

func TestTpmHandleMethods(t *testing.T) {
	t.Run("Handle() method", func(t *testing.T) {
		namedHandle := tpm2.NamedHandle{
			Handle: tpmkit.SRKHandle,
			Name:   tpm2.TPM2BName{Buffer: []byte("persistent-key")},
		}
		h := NewHandle(&namedHandle)

		if h.Handle() != tpmkit.SRKHandle {
			t.Errorf("Handle() = %v, want %v", h.Handle(), tpmkit.SRKHandle)
		}
	})

	t.Run("Name() method", func(t *testing.T) {
		expectedName := tpm2.TPM2BName{Buffer: []byte("my-key-name")}
		namedHandle := tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000001),
			Name:   expectedName,
		}
		h := NewHandle(&namedHandle)

		gotName := h.Name()
		if !bytes.Equal(gotName.Buffer, expectedName.Buffer) {
			t.Errorf("Name() = %v, want %v", gotName.Buffer, expectedName.Buffer)
		}
	})

	t.Run("IsAuth() method - NamedHandle", func(t *testing.T) {
		namedHandle := tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000001),
			Name:   tpm2.TPM2BName{Buffer: []byte("test")},
		}
		h := NewHandle(&namedHandle)

		if h.IsAuth() {
			t.Error("IsAuth() = true for NamedHandle, want false")
		}
	})

	t.Run("IsAuth() method - AuthHandle", func(t *testing.T) {
		authHandle := tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Name:   tpm2.TPM2BName{Buffer: []byte("owner")},
		}
		h := NewHandle(&authHandle)

		if !h.IsAuth() {
			t.Error("IsAuth() = false for AuthHandle, want true")
		}
	})

	t.Run("Type() method - various types", func(t *testing.T) {
		tests := []struct {
			name         string
			handleValue  uint32
			expectedType HandleType
		}{
			{"NVIndex", 0x01000001, NVIndexHandle},
			{"PolicySession", 0x03000001, PolicySessionHandle},
			{"Permanent", 0x40000001, PermanentHandle},
			{"Persistent", 0x81000001, PersistentHandle},
			{"Transient", 0x80000001, TransientHandle},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				namedHandle := tpm2.NamedHandle{
					Handle: tpm2.TPMHandle(tt.handleValue),
					Name:   tpm2.TPM2BName{Buffer: []byte("test")},
				}
				h := NewHandle(&namedHandle)

				if h.Type() != tt.expectedType {
					t.Errorf("Type() = %v, want %v", h.Type(), tt.expectedType)
				}
			})
		}
	})

	t.Run("Public() method - with public", func(t *testing.T) {
		thetpm := testutil.OpenSimulator(t)

		createPrimary := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
		}

		rsp, err := createPrimary.Execute(thetpm)
		if err != nil {
			t.Fatalf("CreatePrimary() failed: %v", err)
		}
		defer func() {
			tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(thetpm)
		}()

		public, err := rsp.OutPublic.Contents()
		if err != nil {
			t.Fatalf("OutPublic.Contents() failed: %v", err)
		}

		h := &tpmHandle{
			handle: &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name},
			tpm:    thetpm,
			isAuth: false,
			public: public,
		}

		if !h.HasPublic() {
			t.Error("HasPublic() = false, want true")
		}

		gotPublic := h.Public()
		if gotPublic == nil {
			t.Fatal("Public() returned nil, want non-nil")
		}

		if gotPublic.Type != tpm2.TPMAlgECC {
			t.Errorf("Public().Type = %v, want %v", gotPublic.Type, tpm2.TPMAlgECC)
		}
	})

	t.Run("Public() method - without public", func(t *testing.T) {
		namedHandle := tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(0x80000001),
			Name:   tpm2.TPM2BName{Buffer: []byte("test")},
		}
		h := NewHandle(&namedHandle)

		if h.HasPublic() {
			t.Error("HasPublic() = true, want false")
		}

		if h.Public() != nil {
			t.Error("Public() returned non-nil, want nil")
		}
	})
}
