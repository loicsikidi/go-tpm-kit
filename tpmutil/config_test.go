// Copyright (c) 2025, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/tpmtest"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestNVReadConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     tpmutil.NVReadConfig
		wantErr error
	}{
		{
			name:    "missing Index",
			cfg:     tpmutil.NVReadConfig{},
			wantErr: tpmutil.ErrMissingIndex,
		},
		{
			name: "negative BlockSize",
			cfg: tpmutil.NVReadConfig{
				Index:     tpm2.TPMHandle(0x01800001),
				BlockSize: -1,
			},
			wantErr: tpmutil.ErrInvalidBlockSize,
		},
		{
			name: "BlockSize exceeds maximum gets capped",
			cfg: tpmutil.NVReadConfig{
				Index:     tpm2.TPMHandle(0x01800001),
				BlockSize: 2000,
			},
			wantErr: nil,
		},
		{
			name: "zero BlockSize uses default",
			cfg: tpmutil.NVReadConfig{
				Index:     tpm2.TPMHandle(0x01800001),
				BlockSize: 0,
			},
			wantErr: nil,
		},
		{
			name: "valid custom BlockSize",
			cfg: tpmutil.NVReadConfig{
				Index:     tpm2.TPMHandle(0x01800001),
				BlockSize: 512,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.CheckAndSetDefault()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if tt.cfg.BlockSize <= 0 || tt.cfg.BlockSize > 1024 {
					t.Errorf("expected BlockSize to be capped at 1024, got %d", tt.cfg.BlockSize)
				}
				if tt.cfg.Hierarchy == 0 {
					t.Error("expected Hierarchy to be set to default")
				}
				if tt.cfg.Auth == nil {
					t.Error("expected Auth to be set to default")
				}
			}
		})
	}
}

func TestNVWriteConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     tpmutil.NVWriteConfig
		wantErr error
	}{
		{
			name:    "missing Index",
			cfg:     tpmutil.NVWriteConfig{Data: []byte("test")},
			wantErr: tpmutil.ErrMissingIndex,
		},
		{
			name:    "missing Data",
			cfg:     tpmutil.NVWriteConfig{Index: tpm2.TPMHandle(0x01800001)},
			wantErr: tpmutil.ErrMissingData,
		},
		{
			name: "valid config with defaults",
			cfg: tpmutil.NVWriteConfig{
				Index: tpm2.TPMHandle(0x01800001),
				Data:  []byte("test"),
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.CheckAndSetDefault()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if tt.cfg.Hierarchy == 0 {
					t.Error("expected Hierarchy to be set to default")
				}
				if tt.cfg.Auth == nil {
					t.Error("expected Auth to be set to default")
				}
				if tt.cfg.Attributes == (tpm2.TPMANV{}) {
					t.Error("expected Attributes to be set to default")
				}
			}
		})
	}
}

func TestSignConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     tpmutil.SignConfig
		wantErr error
	}{
		{
			name:    "nil KeyHandle",
			cfg:     tpmutil.SignConfig{Digest: []byte("test"), PublicKey: &ecdsa.PublicKey{}},
			wantErr: tpmutil.ErrMissingHandle,
		},
		{
			name:    "nil Digest",
			cfg:     tpmutil.SignConfig{KeyHandle: tpmutil.NewHandle(&tpm2.NamedHandle{}), PublicKey: &ecdsa.PublicKey{}},
			wantErr: tpmutil.ErrMissingData,
		},
		{
			name:    "nil PublicKey",
			cfg:     tpmutil.SignConfig{KeyHandle: tpmutil.NewHandle(&tpm2.NamedHandle{}), Digest: []byte("test")},
			wantErr: tpmutil.ErrMissingPublicKey,
		},
		{
			name: "nil SignerOpts uses default",
			cfg: tpmutil.SignConfig{
				KeyHandle: tpmutil.NewHandle(&tpm2.NamedHandle{}),
				Digest:    []byte("test"),
				PublicKey: &ecdsa.PublicKey{},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.CheckAndSetDefault()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if tt.cfg.SignerOpts == nil {
					t.Error("expected SignerOpts to be set to default")
				}
			}
		})
	}
}

func TestHashConfigValidation(t *testing.T) {
	thetpm := tpmtest.OpenSimulator(t)

	data := []byte("test data")

	tests := []struct {
		name      string
		cfg       []tpmutil.HashConfig
		wantError error
	}{
		{
			name:      "nil config",
			cfg:       nil,
			wantError: tpmutil.ErrMissingData,
		},
		{
			name: "negative blockSize",
			cfg: []tpmutil.HashConfig{
				{
					BlockSize: -1,
					HashAlg:   crypto.SHA256,
					Data:      data,
				},
			},
			wantError: tpmutil.ErrInvalidBlockSize,
		},
		{
			name: "blockSize exceeds maximum gets capped",
			cfg: []tpmutil.HashConfig{
				{
					BlockSize: 2048,
					HashAlg:   crypto.SHA256,
					Data:      data,
				},
			},
			wantError: nil,
		},
		{
			name: "zero blockSize uses default",
			cfg: []tpmutil.HashConfig{
				{
					BlockSize: 0,
					HashAlg:   crypto.SHA256,
					Data:      data,
				},
			},
			wantError: nil,
		},
		{
			name: "valid custom blockSize",
			cfg: []tpmutil.HashConfig{
				{
					BlockSize: 512,
					HashAlg:   crypto.SHA256,
					Data:      data,
				},
			},
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tpmutil.Hash(thetpm, tt.cfg...)
			if tt.wantError != nil {
				if err == nil {
					t.Errorf("Expected error %v, got nil", tt.wantError)
				} else if !errors.Is(err, tt.wantError) {
					t.Errorf("Expected error %v, got %v", tt.wantError, err)
				}
				if result != nil {
					t.Errorf("Expected nil result on error, got %v", result)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
				if result == nil {
					t.Error("Expected non-nil result, got nil")
				}
			}
		})
	}
}

func TestGetKeyHandleConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     tpmutil.GetPersistedKeyHandleConfig
		wantErr bool
	}{
		{
			name:    "missing Handle",
			cfg:     tpmutil.GetPersistedKeyHandleConfig{},
			wantErr: true,
		},
		{
			name: "non-persistent Handle (transient)",
			cfg: tpmutil.GetPersistedKeyHandleConfig{
				Handle: tpmutil.NewHandle(tpm2.TPMHandle(0x80000001)),
			},
			wantErr: true,
		},
		{
			name: "non-persistent Handle (NV index)",
			cfg: tpmutil.GetPersistedKeyHandleConfig{
				Handle: tpmutil.NewHandle(tpm2.TPMHandle(0x01800001)),
			},
			wantErr: true,
		},
		{
			name: "non-persistent Handle (permanent)",
			cfg: tpmutil.GetPersistedKeyHandleConfig{
				Handle: tpmutil.NewHandle(tpm2.TPMRHOwner),
			},
			wantErr: true,
		},
		{
			name: "valid persistent Handle",
			cfg: tpmutil.GetPersistedKeyHandleConfig{
				Handle: tpmutil.NewHandle(tpm2.TPMHandle(0x81000001)),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.CheckAndSetDefault()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestHmacConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     tpmutil.HmacConfig
		wantErr error
	}{
		{
			name:    "missing KeyHandle",
			cfg:     tpmutil.HmacConfig{Data: []byte("test")},
			wantErr: tpmutil.ErrMissingHandle,
		},
		{
			name: "missing Data",
			cfg: tpmutil.HmacConfig{
				KeyHandle: tpmutil.NewHandle(&tpm2.NamedHandle{}),
			},
			wantErr: tpmutil.ErrMissingData,
		},
		{
			name: "negative BlockSize",
			cfg: tpmutil.HmacConfig{
				KeyHandle: tpmutil.NewHandle(&tpm2.NamedHandle{}),
				Data:      []byte("test"),
				BlockSize: -1,
			},
			wantErr: tpmutil.ErrInvalidBlockSize,
		},
		{
			name: "BlockSize exceeds maximum gets capped",
			cfg: tpmutil.HmacConfig{
				KeyHandle: tpmutil.NewHandle(&tpm2.NamedHandle{}),
				Data:      []byte("test"),
				BlockSize: 2000,
			},
			wantErr: nil,
		},
		{
			name: "zero BlockSize uses default",
			cfg: tpmutil.HmacConfig{
				KeyHandle: tpmutil.NewHandle(&tpm2.NamedHandle{}),
				Data:      []byte("test"),
				BlockSize: 0,
			},
			wantErr: nil,
		},
		{
			name: "valid custom BlockSize",
			cfg: tpmutil.HmacConfig{
				KeyHandle: tpmutil.NewHandle(&tpm2.NamedHandle{}),
				Data:      []byte("test"),
				BlockSize: 512,
			},
			wantErr: nil,
		},
		{
			name: "valid config with all defaults",
			cfg: tpmutil.HmacConfig{
				KeyHandle: tpmutil.NewHandle(&tpm2.NamedHandle{}),
				Data:      []byte("test"),
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.CheckAndSetDefault()
			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if err != tt.wantErr {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if tt.cfg.BlockSize <= 0 || tt.cfg.BlockSize > 1024 {
					t.Errorf("expected BlockSize to be capped at 1024, got %d", tt.cfg.BlockSize)
				}
				if tt.cfg.Hierarchy == 0 {
					t.Error("expected Hierarchy to be set to default")
				}
				if tt.cfg.Auth == nil {
					t.Error("expected Auth to be set to default")
				}
			}
		})
	}
}
