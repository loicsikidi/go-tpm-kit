// Copyright (c) 2025, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil

import (
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/loicsikidi/go-tpm-kit/internal/utils"
)

// HandleType represents the different types of handles in TPM 2.0.
type HandleType int

const (
	// UnspecifiedHandle represents an unknown or unidentified handle type.
	UnspecifiedHandle HandleType = iota
	// NVIndexHandle represents a handle for Non-Volatile (NV) memory indices.
	// These handles reference persistent storage areas in the TPM.
	NVIndexHandle
	// PolicySessionHandle represents a handle for policy sessions.
	// These are used for complex authorization scenarios.
	PolicySessionHandle
	// PermanentHandle represents a handle for permanent TPM entities.
	// These are built-in handles like TPM_RH_OWNER, TPM_RH_PLATFORM, etc.
	PermanentHandle
	// PersistentHandle represents a handle for persistent objects.
	// These objects remain in TPM memory across power cycles.
	PersistentHandle
	// TransientHandle represents a handle for transient objects.
	// These objects exist only in TPM volatile memory and are lost on reboot.
	TransientHandle
)

func (ht HandleType) String() string {
	switch ht {
	case NVIndexHandle:
		return "NVIndex"
	case PolicySessionHandle:
		return "PolicySession"
	case PermanentHandle:
		return "Permanent"
	case PersistentHandle:
		return "Persistent"
	case TransientHandle:
		return "Transient"
	default:
		return fmt.Sprintf("unknown(%d)", ht)
	}
}

// copy private interface from tpm2 package
type handle interface {
	// HandleValue is the numeric concrete handle value in the TPM.
	HandleValue() uint32
	// KnownName is the TPM Name of the associated entity. See Part 1, section 16.
	KnownName() *tpm2.TPM2BName
}

// Handle provides a layer of abstraction over TPM handles.
// Typically, users will interact with two types of handles:
//   - Authorization handles (e.g., for sessions, passwords) [tpm2.AuthHandle]
//   - Object handles (e.g., for keys, NV indices) [tpm2.NamedHandle]
//
// Handle allows users to work with both types uniformly.
type Handle interface {
	handle
	// Handle returns the underlying TPM handle value.
	Handle() tpm2.TPMHandle
	// Name returns the TPM Name associated with the handle.
	Name() tpm2.TPM2BName
	// IsAuth indicates if the handle is an authorization handle.
	IsAuth() bool
	// Type returns the type of the handle.
	Type() HandleType
}

// HandleCloser extends Handle with the ability to release resources.
// When a HandleCloser is no longer needed, calling Close() will flush the handle
//
// For convenience, [HandleCloser] includes the [PublicGetter] interface in order to
// access the public area of the associated key. Implementations should have no
// difficulty to implement this interface, because [HandleCloser] ensures to
// have access to a TPM transport.
type HandleCloser interface {
	Handle
	PublicGetter
	io.Closer
}

// PublicGetter provides access to the public area of a key handle.
//
// Note: APIs which accept [Handle], may try to do an interface upgrade with [PublicGetter] to access the public area.
type PublicGetter interface {
	// Public returns the public area associated with the handle.
	// Returns nil if no public area is available.
	Public() *tpm2.TPMTPublic
	// HasPublic indicates if the handle has an associated public area.
	//
	// EXPERIMENTAL: This method is experimental and may be removed in future releases.
	HasPublic() bool
}

// tpmHandle is an implementation of the HandleCloser interface.
// It wraps a TPM handle and provides methods to interact with it.
type tpmHandle struct {
	handle
	tpm    transport.TPM
	isAuth bool
	public *tpm2.TPMTPublic
}

var _ HandleCloser = (*tpmHandle)(nil)
var _ PublicGetter = (*tpmHandle)(nil)

// NewHandle creates a new Handle from the given TPM handle.
//
// Examples:
//
//	// Create a handle from a Command Response
//	h := &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}
//	handle := tpmutil.NewHandle(h)
//
//	// Create a handle from a TPM persistent handle
//	handle := tpmutil.NewHandle(tpm2.TPMHandle(0x81000001))
//
//	fmt.Printf("Handle type: %s\n", h.Type())
//
// Note: [tpm2.TPMHandle], [tpm2.AuthHandle] and [tpm2.NamedHandle] can be used as input.
func NewHandle(h handle) Handle {
	return &tpmHandle{handle: h, isAuth: isAuthHandle(h)}
}

// NewHandleCloser creates a new HandleCloser from the given TPM handle.
// The returned handle can be closed to flush the TPM resource.
//
// Example:
//
//	// Create a closable handle for a transient key
//	keyHandle := tpmutil.NewHandleCloser(tpm, &tpm2.NamedHandle{
//		Handle: createRsp.ObjectHandle,
//		Name:   createRsp.Name,
//	})
//	defer keyHandle.Close()
//	// Use keyHandle for TPM operations
//
// Note: [tpm2.TPMHandle], [tpm2.AuthHandle] and [tpm2.NamedHandle] can be used as input.
func NewHandleCloser(tpm transport.TPM, h handle) HandleCloser {
	return &tpmHandle{handle: h, tpm: tpm, isAuth: isAuthHandle(h)}
}

// Handle returns the underlying TPM handle value.
func (h *tpmHandle) Handle() tpm2.TPMHandle {
	return tpm2.TPMHandle(h.HandleValue())
}

// Name returns the TPM Name associated with the handle.
func (h *tpmHandle) Name() tpm2.TPM2BName {
	return *h.KnownName()
}

// IsAuth indicates if the handle is an authorization handle.
func (h *tpmHandle) IsAuth() bool {
	return h.isAuth
}

// Type returns the type of the handle.
func (h *tpmHandle) Type() HandleType {
	return identifyHandleType(h)
}

// Public returns the public area associated with the handle.
func (h *tpmHandle) Public() *tpm2.TPMTPublic {
	return h.public
}

// HasPublic indicates if the handle has an associated public area.
func (h *tpmHandle) HasPublic() bool {
	return h.public != nil
}

// Close flushes the handle from the TPM.
func (h *tpmHandle) Close() error {
	if h.tpm == nil {
		return ErrMissingTpm
	}
	_, err := tpm2.FlushContext{
		FlushHandle: h.handle,
	}.Execute(h.tpm)
	return err
}

func (h *tpmHandle) toAuthHandle() tpm2.AuthHandle {
	if authHandle, ok := h.handle.(*tpm2.AuthHandle); ok {
		return *authHandle
	}
	if authHandle, ok := h.handle.(tpm2.AuthHandle); ok {
		return authHandle
	}
	return tpm2.AuthHandle{
		Handle: h.Handle(),
		Name:   h.Name(),
		Auth:   NoAuth,
	}
}

// IsHandleOfType checks if the given handle is of the specified type.
//
// Example:
//
//	// Check if a handle is a persistent handle
//	if tpmutil.IsHandleOfType(handle, tpmutil.PersistentHandle) {
//		fmt.Println("This is a persistent handle")
//	}
func IsHandleOfType(h Handle, ht HandleType) bool {
	return identifyHandleType(h) == ht
}

// ToHandle converts an input to a [Handle].
//
// Example:
//
//	// Convert a raw TPM handle to a Handle
//	h, err := tpmutil.ToHandle(tpm, tpm2.TPMHandle(0x81000001))
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Handle: 0x%x, Type: %s\n", h.Handle(), h.Type())
//
// Note: if the input is a raw TPM handle, a TPM2_ReadPublic command is issued
// to retrieve the associated Name.
func ToHandle(t transport.TPM, handle any) (Handle, error) {
	switch h := handle.(type) {
	case tpm2.TPMHandle:
		pa, err := getPublicArea(t, h)
		if err != nil {
			return nil, err
		}
		return &tpmHandle{
			handle: &tpm2.NamedHandle{Handle: h, Name: pa.Name},
			tpm:    t,
			public: pa.public,
		}, nil
	case Handle:
		return h, nil
	default:
		return nil, fmt.Errorf("expected tpm2.TPMHandle or a struct implementing tpmutil.Handle, got %T", h)
	}
}

// ToHandleCloser converts an input to a [HandleCloser].
//
// The handle argument accepts the following types:
//   - [tpm2.TPMHandle]: a TPM2_ReadPublic command is issued to retrieve the
//     associated Name and public area.
//   - [HandleCloser]: returned as-is. If the underlying [*tpmHandle] is missing
//     its public area, a TPM2_ReadPublic is issued to populate it.
//   - [Handle]: a TPM2_ReadPublic command is issued to build a full [HandleCloser]
//     with the associated Name and public area.
//
// The returned [HandleCloser] is guaranteed to have a public area available
// via [HandleCloser.Public].
//
// Example:
//
//	// Convert a raw TPM handle to a HandleCloser
//	hc, err := tpmutil.ToHandleCloser(tpm, tpm2.TPMHandle(0x81000001))
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer hc.Close()
//	fmt.Printf("Handle: 0x%x, Type: %s\n", hc.Handle(), hc.Type())
func ToHandleCloser(t transport.TPM, handle any) (HandleCloser, error) {
	switch h := handle.(type) {
	case tpm2.TPMHandle:
		hh, err := ToHandle(t, h)
		if err != nil {
			return nil, err
		}
		return ToHandleCloser(t, hh)
	case HandleCloser:
		tpmh, ok := h.(*tpmHandle)
		if !ok {
			return h, nil
		}
		if !tpmh.HasPublic() {
			pa, err := getPublicArea(t, tpmh)
			if err != nil {
				return nil, err
			}
			tpmh.public = pa.public
		}
		return h, nil
	case Handle:
		pa, err := getPublicArea(t, h)
		if err != nil {
			return nil, err
		}
		return &tpmHandle{
			handle: h,
			tpm:    t,
			public: pa.public,
		}, nil
	default:
		return nil, fmt.Errorf("expected tpm2.TPMHandle or a struct implementing tpmutil.Handle/tpmutil.HandleCloser, got %T", h)
	}
}

// ToAuthHandle converts a Handle to an authorization Handle with the given session.
//
// This function is a hack in order to deals with Authorization Handles because
// internally go-tpm is able to interpret Authz only as [tpm2.AuthHandle].
//
// Note: if no session is provided, NoAuth is used by default.
//
// EXPERIMENTAL: this function may change or be removed in future releases.
func ToAuthHandle(h Handle, optionalAuth ...tpm2.Session) tpm2.AuthHandle {
	if h.IsAuth() && len(optionalAuth) == 0 {
		if th, ok := h.(*tpmHandle); ok {
			return th.toAuthHandle()
		}
	}
	auth := utils.OptionalArgWithDefault(optionalAuth, NoAuth)
	return tpm2.AuthHandle{
		Handle: h.Handle(),
		Name:   h.Name(),
		Auth:   auth,
	}
}

// isAuthHandle checks if the given handle is an authorization handle.
func isAuthHandle(h handle) bool {
	_, ok := h.(*tpm2.AuthHandle)
	_, ok2 := h.(tpm2.AuthHandle)
	return ok || ok2
}

// identifyHandleType determines the type of the given handle.
func identifyHandleType(h Handle) HandleType {
	switch {
	case isMso(h.Handle(), uint32(tpm2.TPMHTNVIndex)):
		return NVIndexHandle
	case isMso(h.Handle(), uint32(tpm2.TPMHTPolicySession)):
		return PolicySessionHandle
	case isMso(h.Handle(), uint32(tpm2.TPMHTPermanent)):
		return PermanentHandle
	case isMso(h.Handle(), uint32(tpm2.TPMHTPersistent)):
		return PersistentHandle
	case isMso(h.Handle(), uint32(tpm2.TPMHTTransient)):
		return TransientHandle
	default:
		return UnspecifiedHandle
	}
}

// isMso checks if the given handle belongs to the specified MSO (Major Structure Object) type.
func isMso(h tpm2.TPMHandle, mso uint32) bool {
	return (uint32(h) >> 24) == mso
}
