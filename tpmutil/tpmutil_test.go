package tpmutil_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	tpmkit "github.com/loicsikidi/go-tpm-kit"
	"github.com/loicsikidi/go-tpm-kit/internal/utils/testutil"
	"github.com/loicsikidi/go-tpm-kit/tpmcrypto"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestNVWrite(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	index := tpm2.TPMHandle(0x01800001)
	maxBufferSize := 1024

	tests := []struct {
		name        string
		payloadSize int
		wantErr     bool
	}{
		{"ok w/ small_payload", 10, false},
		{"ok w/ size equals max_buffer_size", maxBufferSize, false},
		{"ok w/ size above max_buffer_size", maxBufferSize + 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tpmutil.MustGenerateIV(tt.payloadSize)

			cfg := tpmutil.NVWriteConfig{
				Index: index,
				Data:  data,
			}

			got := tpmutil.NVWrite(thetpm, cfg)
			if (got != nil) != tt.wantErr {
				t.Errorf("NVWrite() error = %v, wantErr %v", got, tt.wantErr)
			}

			if got == nil {
				readCfg := tpmutil.NVReadConfig{
					Index: index,
				}
				gotData, err := tpmutil.NVRead(thetpm, readCfg)
				if err != nil {
					t.Fatalf("NVRead() failed: %v", err)
				}

				if !reflect.DeepEqual(data, gotData) {
					t.Errorf("data read from NV index should match data written: expected %v, got %v", data, gotData)
				}

				// remove the NV index after the test
				t.Cleanup(func() {
					readPub := tpm2.NVReadPublic{
						NVIndex: index,
					}
					readRsp, err := readPub.Execute(thetpm)
					if err != nil {
						t.Fatalf("could not read NV index public info: %v", err)
					}
					undefine := tpm2.NVUndefineSpace{
						AuthHandle: tpm2.TPMRHOwner,
						NVIndex: tpm2.NamedHandle{
							Handle: index,
							Name:   readRsp.NVName,
						},
					}
					if _, err := undefine.Execute(thetpm); err != nil {
						t.Errorf("could not undefine NV index: %v", err)
					}
				})
			}
		})
	}
}

func TestHashDefault(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	run := func(t *testing.T, bufferSize int, hierarchy tpm2.TPMHandle, transport transport.TPM) {
		data := make([]byte, bufferSize)
		rand.Read(data)
		wantDigest := sha256.Sum256(data)

		cfg := tpmutil.HashConfig{
			Hierarchy: hierarchy,
			BlockSize: bufferSize,
			HashAlg:   crypto.SHA256,
			Data:      data,
		}
		result, err := tpmutil.Hash(transport, cfg)
		if err != nil {
			t.Fatalf("Hash() failed: %v", err)
		}
		if result == nil {
			t.Fatal("Hash() returned nil result")
		}

		if !bytes.Equal(result.Digest, wantDigest[:]) {
			t.Errorf("The resulting digest %x, is not expected %x", result.Digest, wantDigest)
		}

		if hierarchy == tpm2.TPMRHNull {
			if len(result.Validation.Digest.Buffer) > 0 {
				t.Errorf("Expected empty digest for Null hierarchy, got %x", result.Validation.Digest.Buffer)
			}
		}
	}
	bufferSizes := []int{512, 1024, 2048, 4096}
	for _, bufferSize := range bufferSizes {
		t.Run(fmt.Sprintf("Null hierarchy [bufferSize=%d]", bufferSize), func(t *testing.T) {
			run(t, bufferSize, tpm2.TPMRHNull, thetpm)
		})
		t.Run(fmt.Sprintf("Owner hierarchy [bufferSize=%d]", bufferSize), func(t *testing.T) {
			run(t, bufferSize, tpm2.TPMRHOwner, thetpm)
		})
	}
}

func TestTPMHashMsgTooShort(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	// TPM will refuse to hash a message that is too short.
	sizes := []int{0, 1, 2}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			msg := make([]byte, size)
			cfg := tpmutil.HashConfig{Data: msg}
			result, err := tpmutil.Hash(thetpm, cfg)
			if err == nil {
				t.Errorf("Hash() succeeded, want error")
			}
			if result != nil {
				t.Errorf("Expected nil result on error, got %v", result)
			}
		})
	}
}

func TestTPMHash(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	sizes := []int{
		tpmkit.MaxBufferSize / 2,
		tpmkit.MaxBufferSize - 1,
		tpmkit.MaxBufferSize,
		tpmkit.MaxBufferSize + 1,
		int(float64(tpmkit.MaxBufferSize) * 1.5),
		tpmkit.MaxBufferSize*2 - 1,
		tpmkit.MaxBufferSize * 2,
		tpmkit.MaxBufferSize*2 + 1,
	}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			msg := make([]byte, size)
			rand.Read(msg)

			cfg := tpmutil.HashConfig{Data: msg}
			result, err := tpmutil.Hash(thetpm, cfg)
			if err != nil {
				t.Fatalf("Hash() failed: %v", err)
			}
			if result == nil {
				t.Fatal("Hash() returned nil result")
			}

			trueDigest := sha256.Sum256(msg)
			if !bytes.Equal(result.Digest, trueDigest[:]) {
				t.Errorf("Hash() = %v, want %v", result.Digest, trueDigest[:])
			}

			if result.Validation.Hierarchy == tpm2.TPMRHNull {
				t.Errorf("Hash() validation.Hierarchy = tpm2.HandleNull")
			}
		})
	}
}

func TestHash(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	data := []byte("hello world")
	cfg := tpmutil.HashConfig{
		Hierarchy: tpm2.TPMRHOwner,
		Password:  "",
		BlockSize: 1024,
		HashAlg:   crypto.SHA256,
		Data:      data,
	}
	result, err := tpmutil.Hash(thetpm, cfg)
	if err != nil {
		t.Fatalf("Hash() failed: %v", err)
	}
	if result == nil {
		t.Fatal("Hash() returned nil result")
	}

	if len(result.Digest) != 32 {
		t.Errorf("Expected digest length 32, got %d", len(result.Digest))
	}
	if result.Validation.Hierarchy != 1073741825 {
		t.Errorf("Expected ticket hierarchy 1073741825, got %d", result.Validation.Hierarchy)
	}
}

func TestHashWithCustomConfig(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	cfg := tpmutil.HashConfig{
		Hierarchy: tpm2.TPMRHOwner,
		Password:  "custom-password",
		BlockSize: 512,
		HashAlg:   crypto.SHA256,
		Data:      []byte("hello world"),
	}

	result, err := tpmutil.Hash(thetpm, cfg)
	if err != nil {
		t.Fatalf("Hash() failed: %v", err)
	}
	if result == nil {
		t.Fatal("Hash() returned nil result")
	}

	if len(result.Digest) != 32 {
		t.Errorf("Expected digest length 32, got %d", len(result.Digest))
	}
}

func TestSign(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	// Create a primary signing key
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

	createPrimary := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(signingTemplate),
	}

	rsp, err := createPrimary.Execute(thetpm)
	if err != nil {
		t.Fatalf("CreatePrimary() failed: %v", err)
	}
	defer func() {
		flushContext := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}
		if _, err := flushContext.Execute(thetpm); err != nil {
			t.Errorf("FlushContext() failed: %v", err)
		}
	}()

	// Get the public key
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		t.Fatalf("OutPublic.Contents() failed: %v", err)
	}

	pubKey, err := tpmcrypto.PublicKey(pub)
	if err != nil {
		t.Fatalf("PublicKey() failed: %v", err)
	}

	// Hash some data (required for signing)
	hashCfg := tpmutil.HashConfig{Data: []byte("sign this message")}
	result, err := tpmutil.Hash(thetpm, hashCfg)
	if err != nil {
		t.Fatalf("Hash() failed: %v", err)
	}
	if result == nil {
		t.Fatal("Hash() returned nil result")
	}

	// Sign the digest
	handle := tpmutil.NewHandle(&tpm2.NamedHandle{
		Handle: rsp.ObjectHandle,
		Name:   rsp.Name,
	})

	cfg := tpmutil.SignConfig{
		KeyHandle:  handle,
		Digest:     result.Digest,
		PublicKey:  pubKey,
		SignerOpts: crypto.SHA256,
		Validation: result.Validation,
	}

	signature, err := tpmutil.Sign(thetpm, cfg)
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) < 70 || len(signature) > 73 {
		t.Errorf("Expected signature length between 70-73, got %d", len(signature))
	}
}

func TestNVRead(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	index := tpm2.TPMHandle(0x01800001)
	data := []byte("test data")

	// Write data first with nil config (uses defaults)
	writeCfg := tpmutil.NVWriteConfig{
		Index: index,
		Data:  data,
	}
	err := tpmutil.NVWrite(thetpm, writeCfg)
	if err != nil {
		t.Fatalf("NVWrite() failed: %v", err)
	}
	defer func() {
		readPub := tpm2.NVReadPublic{NVIndex: index}
		readRsp, err := readPub.Execute(thetpm)
		if err != nil {
			t.Errorf("NVReadPublic() failed: %v", err)
			return
		}
		undefine := tpm2.NVUndefineSpace{
			AuthHandle: tpm2.TPMRHOwner,
			NVIndex:    tpm2.NamedHandle{Handle: index, Name: readRsp.NVName},
		}
		if _, err := undefine.Execute(thetpm); err != nil {
			t.Errorf("NVUndefineSpace() failed: %v", err)
		}
	}()

	// Read the data back with nil config (uses defaults)
	readCfg := tpmutil.NVReadConfig{
		Index: index,
	}
	readData, err := tpmutil.NVRead(thetpm, readCfg)
	if err != nil {
		t.Fatalf("NVRead() failed: %v", err)
	}

	if len(readData) != 9 {
		t.Errorf("Expected to read 9 bytes, got %d", len(readData))
	}
}

func TestGenerateIV(t *testing.T) {
	tests := []struct {
		name      string
		blockSize int
		wantErr   bool
	}{
		{
			name:      "valid AES block size (16 bytes)",
			blockSize: 16,
			wantErr:   false,
		},
		{
			name:      "valid custom block size (32 bytes)",
			blockSize: 32,
			wantErr:   false,
		},
		{
			name:      "valid small block size (8 bytes)",
			blockSize: 8,
			wantErr:   false,
		},
		{
			name:      "invalid zero block size",
			blockSize: 0,
			wantErr:   true,
		},
		{
			name:      "invalid negative block size",
			blockSize: -1,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			iv, err := tpmutil.GenerateIV(tt.blockSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateIV() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(iv) != tt.blockSize {
					t.Errorf("GenerateIV() returned IV of length %d, want %d", len(iv), tt.blockSize)
				}
			}
		})
	}
}

func TestMustGenerateIV(t *testing.T) {
	tests := []struct {
		name        string
		blockSize   int
		shouldPanic bool
	}{
		{
			name:        "valid block size",
			blockSize:   16,
			shouldPanic: false,
		},
		{
			name:        "invalid zero block size",
			blockSize:   0,
			shouldPanic: true,
		},
		{
			name:        "invalid negative block size",
			blockSize:   -1,
			shouldPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if (r != nil) != tt.shouldPanic {
					t.Errorf("tpmutil.MustGenerateIV() panic = %v, shouldPanic %v", r != nil, tt.shouldPanic)
				}
			}()

			iv := tpmutil.MustGenerateIV(tt.blockSize)
			if !tt.shouldPanic && len(iv) != tt.blockSize {
				t.Errorf("tpmutil.MustGenerateIV() returned IV of length %d, want %d", len(iv), tt.blockSize)
			}
		})
	}
}

func TestSymEncryptDecrypt(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	primary, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgSymCipher,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				UserWithAuth:        true,
				SensitiveDataOrigin: true,
				Decrypt:             true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgSymCipher,
				&tpm2.TPMSSymCipherParms{
					Sym: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
						KeyBits: tpm2.NewTPMUSymKeyBits(
							tpm2.TPMAlgAES,
							tpm2.TPMKeyBits(128),
						),
					},
				},
			),
		},
	})
	if err != nil {
		t.Fatalf("CreatePrimary() failed: %v", err)
	}
	defer primary.Close()

	tests := []struct {
		name      string
		dataSize  int
		blockSize int
	}{
		{
			name:     "small message",
			dataSize: 6,
		},
		{
			name:     "medium message",
			dataSize: 512,
		},
		{
			name:     "size below max buffer",
			dataSize: tpmkit.MaxBufferSize - 1,
		},
		{
			name:     "size equals max buffer",
			dataSize: tpmkit.MaxBufferSize,
		},
		{
			name:     "size above max buffer",
			dataSize: tpmkit.MaxBufferSize + 1,
		},
		{
			name:     "double max buffer size",
			dataSize: tpmkit.MaxBufferSize * 2,
		},
		{
			name:     "large message",
			dataSize: tpmkit.MaxBufferSize*2 + 100,
		},
		{
			name:     "2KB message",
			dataSize: 2048,
		},
		{
			name:      "custom block size",
			dataSize:  2048,
			blockSize: 512,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := tpmutil.MustGenerateIV(tt.dataSize)
			iv := tpmutil.MustGenerateIV(16)

			encryptCfg := tpmutil.SymEncryptDecryptConfig{
				KeyHandle: primary,
				Data:      message,
				IV:        iv,
				Mode:      tpm2.TPMAlgCFB,
				Decrypt:   false,
			}
			if tt.blockSize > 0 {
				encryptCfg.BlockSize = tt.blockSize
			}

			encrypted, err := tpmutil.SymEncryptDecrypt(thetpm, encryptCfg)
			if err != nil {
				t.Fatalf("SymEncryptDecrypt() encrypt failed: %v", err)
			}

			if bytes.Equal(message, encrypted) {
				t.Error("Encrypted data should differ from original")
			}

			decryptCfg := tpmutil.SymEncryptDecryptConfig{
				KeyHandle: primary,
				Data:      encrypted,
				IV:        iv,
				Mode:      tpm2.TPMAlgCFB,
				Decrypt:   true,
			}
			if tt.blockSize > 0 {
				decryptCfg.BlockSize = tt.blockSize
			}

			decrypted, err := tpmutil.SymEncryptDecrypt(thetpm, decryptCfg)
			if err != nil {
				t.Fatalf("SymEncryptDecrypt() decrypt failed: %v", err)
			}

			if !bytes.Equal(message, decrypted) {
				t.Errorf("Decrypted data doesn't match original (size=%d, blockSize=%d)", tt.dataSize, tt.blockSize)
			}
		})
	}
}

func TestSymEncryptDecryptValidation(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	primary, err := tpmutil.CreatePrimary(thetpm, tpmutil.CreatePrimaryConfig{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic: tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgSymCipher,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				UserWithAuth:        true,
				SensitiveDataOrigin: true,
				Decrypt:             true,
				SignEncrypt:         true,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgSymCipher,
				&tpm2.TPMSSymCipherParms{
					Sym: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
						KeyBits: tpm2.NewTPMUSymKeyBits(
							tpm2.TPMAlgAES,
							tpm2.TPMKeyBits(128),
						),
					},
				},
			),
		},
	})
	if err != nil {
		t.Fatalf("CreatePrimary() failed: %v", err)
	}
	defer primary.Close()

	tests := []struct {
		name    string
		cfg     tpmutil.SymEncryptDecryptConfig
		wantErr bool
	}{
		{
			name: "missing handle",
			cfg: tpmutil.SymEncryptDecryptConfig{
				Data: []byte("data"),
				IV:   tpmutil.MustGenerateIV(16),
			},
			wantErr: true,
		},
		{
			name: "missing data",
			cfg: tpmutil.SymEncryptDecryptConfig{
				KeyHandle: primary,
				IV:        tpmutil.MustGenerateIV(16),
			},
			wantErr: true,
		},
		{
			name: "missing IV",
			cfg: tpmutil.SymEncryptDecryptConfig{
				KeyHandle: primary,
				Data:      []byte("data"),
			},
			wantErr: true,
		},
		{
			name: "invalid block size",
			cfg: tpmutil.SymEncryptDecryptConfig{
				KeyHandle: primary,
				Data:      []byte("data"),
				IV:        tpmutil.MustGenerateIV(16),
				BlockSize: -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tpmutil.SymEncryptDecrypt(thetpm, tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("SymEncryptDecrypt() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
