//go:build linux && localtest

// Copyright (c) 2025, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmsession_test

import (
	"crypto"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/loicsikidi/go-tpm-kit/tpmsession"
)

// openTPM creates a TPM  and returns it along with a cleanup function.
func openTPM(t *testing.T) transport.TPMCloser {
	t.Helper()
	tpm, err := linuxtpm.Open("/dev/tpmrm0")
	if err != nil {
		t.Fatalf("failed to open TPM: %v", err)
	}

	t.Cleanup(func() {
		if err := tpm.Close(); err != nil {
			t.Errorf("failed to close TPM: %v", err)
		}
	})

	return tpm
}

func TestSessionManager_ConcurrentAccess(t *testing.T) {
	tpm := openTPM(t)

	// Create SRK
	name, public := getSRK(t, tpm, 0x81000001)
	publicObj := tpm2.BytesAs2B[tpm2.TPMTPublic](public)

	key := tpmsession.SessionKey{
		SessionType: tpmsession.SaltedSession,
		Handle:      0x81000001,
		Name:        tpm2.TPM2BName{Buffer: name},
		Public:      &publicObj,
	}

	t.Run("concurrent GetSession calls", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		const numGoroutines = 10
		done := make(chan bool, numGoroutines)

		for range numGoroutines {
			go func() {
				defer func() { done <- true }()
				session := sm.GetSession()
				if session == nil {
					t.Error("expected non-nil session")
				}
			}()
		}

		for range numGoroutines {
			<-done
		}
	})

	t.Run("concurrent WithHashAlg and GetSession", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		const numGoroutines = 10
		done := make(chan bool, numGoroutines*2)

		// Start goroutines that call WithHashAlg
		for range numGoroutines {
			go func() {
				defer func() { done <- true }()
				sm.WithHashAlg(crypto.SHA384)
			}()
		}

		// Start goroutines that call GetSession
		for range numGoroutines {
			go func() {
				defer func() { done <- true }()
				session := sm.GetSession()
				if session == nil {
					t.Error("expected non-nil session")
				}
			}()
		}

		for range numGoroutines * 2 {
			<-done
		}
	})

	t.Run("concurrent GetSession with active audit", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		// Create AK
		akHandle := createAttestationKey(t, tpm, 0x81000001)

		config := &tpmsession.AuditConfig{
			AKHandle: akHandle,
			HashAlg:  tpm2.TPMAlgSHA256,
		}

		// Start audit session
		err = sm.StartAuditSession(config)
		if err != nil {
			t.Fatalf("StartAuditSession failed: %v", err)
		}
		defer sm.StopAuditSession()

		const numGoroutines = 10
		done := make(chan bool, numGoroutines)

		// Multiple goroutines call GetSession while audit is active
		for range numGoroutines {
			go func() {
				defer func() { done <- true }()
				session := sm.GetSession()
				if session == nil {
					t.Error("expected non-nil session")
				}
			}()
		}

		for range numGoroutines {
			<-done
		}
	})

	t.Run("concurrent StartAuditSession attempts", func(t *testing.T) {
		sm, err := tpmsession.NewSessionManager(tpm, &key)
		if err != nil {
			t.Fatalf("NewSessionManager failed: %v", err)
		}

		// Create AK - use different handle to avoid conflicts
		akHandle := createAttestationKey(t, tpm, 0x81000001)

		config := &tpmsession.AuditConfig{
			AKHandle: akHandle,
			HashAlg:  tpm2.TPMAlgSHA256,
		}

		const numGoroutines = 10
		done := make(chan error, numGoroutines)

		// Multiple goroutines try to start audit session
		for range numGoroutines {
			go func() {
				done <- sm.StartAuditSession(config)
			}()
		}

		successCount := 0
		errorCount := 0
		for range numGoroutines {
			err := <-done
			if err == nil {
				successCount++
			} else {
				errorCount++
			}
		}

		// Exactly one should succeed, rest should fail
		if successCount != 1 {
			t.Errorf("expected exactly 1 success, got %d", successCount)
		}
		if errorCount != numGoroutines-1 {
			t.Errorf("expected %d errors, got %d", numGoroutines-1, errorCount)
		}

		// Cleanup
		sm.StopAuditSession()
	})
}
