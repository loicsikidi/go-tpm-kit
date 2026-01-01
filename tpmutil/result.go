package tpmutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/internal/utils"
)

// Target represents the marshaling format for [CreateResult].
type Target int

const (
	UnspecifiedTarget Target = iota
	// JSON marshals to JSON format.
	JSON
	// KeyFiles marshals to key-files format (not yet implemented).
	KeyFiles
)

func (t Target) String() string {
	switch t {
	case UnspecifiedTarget:
		return "unspecified"
	case JSON:
		return "json"
	case KeyFiles:
		return "key-files"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

func isValidTarget(t Target) bool {
	return slices.Contains([]Target{JSON, KeyFiles}, t)
}

func (t Target) Check() error {
	if !isValidTarget(t) {
		return fmt.Errorf("invalid target: %s", t)
	}
	return nil
}

// CreateResult contains the result of a TPM Create operation.
type CreateResult struct {
	// OutPrivate is the encrypted private portion of the created object.
	OutPrivate tpm2.TPM2BPrivate
	// OutPublic is the public portion of the created object.
	OutPublic tpm2.TPM2BPublic
	// CreationHash is the digest of the creation data.
	CreationHash tpm2.TPM2BDigest
	// CreationTicket is the ticket that proves the association between the object and its creation data.
	CreationTicket tpm2.TPMTTKCreation
}

// marshaledCreateResult is the JSON representation of [CreateResult].
type marshaledCreateResult struct {
	OutPrivate     []byte `json:"outPrivate"`
	OutPublic      []byte `json:"outPublic"`
	CreationHash   []byte `json:"creationHash"`
	CreationTicket []byte `json:"creationTicket"`
}

// Marshal marshals the [CreateResult] to the specified target format.
//
// If target is not provided, it defaults to [JSON].
//
// Example:
//
//	result := CreateResult{...}
//	data, err := result.Marshal(JSON)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	os.WriteFile("key.json", data, 0644)
func (r CreateResult) Marshal(optionalTarget ...Target) ([]byte, error) {
	target := utils.OptionalArgWithDefault(optionalTarget, JSON)
	if err := target.Check(); err != nil {
		return nil, err
	}

	switch target {
	case KeyFiles:
		return nil, errors.ErrUnsupported
	case JSON:
		fallthrough
	default:
		marshaled := marshaledCreateResult{
			OutPrivate:     tpm2.Marshal(r.OutPrivate),
			OutPublic:      tpm2.Marshal(r.OutPublic),
			CreationHash:   tpm2.Marshal(r.CreationHash),
			CreationTicket: tpm2.Marshal(r.CreationTicket),
		}
		return json.Marshal(marshaled)
	}
}

// LoadCreateResult loads a [CreateResult] from the specified file path.
//
// The file must contain JSON data created by [CreateResult.Marshal].
//
// Example:
//
//	result, err := LoadCreateResult("key.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
func LoadCreateResult(path string) (*CreateResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var marshaled marshaledCreateResult
	if err := json.Unmarshal(data, &marshaled); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	outPrivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](marshaled.OutPrivate)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal OutPrivate: %w", err)
	}
	outPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](marshaled.OutPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal OutPublic: %w", err)
	}
	creationHash, err := tpm2.Unmarshal[tpm2.TPM2BDigest](marshaled.CreationHash)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CreationHash: %w", err)
	}
	creationTicket, err := tpm2.Unmarshal[tpm2.TPMTTKCreation](marshaled.CreationTicket)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CreationTicket: %w", err)
	}

	return &CreateResult{
		OutPrivate:     *outPrivate,
		OutPublic:      *outPublic,
		CreationHash:   *creationHash,
		CreationTicket: *creationTicket,
	}, nil
}

// CreatePrimaryResult contains the result of a TPM CreatePrimary operation.
type CreatePrimaryResult struct {
	// ObjectHandle is the handle of the created primary object.
	ObjectHandle tpm2.TPMHandle
	// OutPublic is the public portion of the created object.
	OutPublic tpm2.TPM2BPublic
	// CreationHash is the digest of the creation data.
	CreationHash tpm2.TPM2BDigest
	// CreationTicket is the ticket that proves the association between the object and its creation data.
	CreationTicket tpm2.TPMTTKCreation
	// Name is the name of the created object.
	Name tpm2.TPM2BName
}

// marshaledCreatePrimaryResult is the JSON representation of [CreatePrimaryResult].
//
// Note: ObjectHandle is not marshaled as it is a transient handle.
type marshaledCreatePrimaryResult struct {
	OutPublic      []byte `json:"outPublic"`
	CreationHash   []byte `json:"creationHash"`
	CreationTicket []byte `json:"creationTicket"`
	Name           []byte `json:"name"`
}

// Marshal marshals the [CreatePrimaryResult] to the specified target format.
//
// If target is not provided, it defaults to [JSON].
//
// Note: ObjectHandle is not marshaled as it is a transient handle that is only valid
// during the current TPM session.
//
// Example:
//
//	result := CreatePrimaryResult{...}
//	data, err := result.Marshal(JSON)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	os.WriteFile("primary-key.json", data, 0644)
func (r CreatePrimaryResult) Marshal(optionalTarget ...Target) ([]byte, error) {
	target := utils.OptionalArgWithDefault(optionalTarget, JSON)
	if err := target.Check(); err != nil {
		return nil, err
	}

	switch target {
	case KeyFiles:
		return nil, errors.ErrUnsupported
	case JSON:
		fallthrough
	default:
		marshaled := marshaledCreatePrimaryResult{
			OutPublic:      tpm2.Marshal(r.OutPublic),
			CreationHash:   tpm2.Marshal(r.CreationHash),
			CreationTicket: tpm2.Marshal(r.CreationTicket),
			Name:           tpm2.Marshal(r.Name),
		}
		return json.Marshal(marshaled)
	}
}

// LoadCreatePrimaryResult loads a [CreatePrimaryResult] from the specified file path.
//
// The file must contain JSON data created by [CreatePrimaryResult.Marshal].
//
// Note: ObjectHandle is not loaded from the file as it was not marshaled.
// The returned [CreatePrimaryResult] will have ObjectHandle set to 0.
//
// Example:
//
//	result, err := LoadCreatePrimaryResult("primary-key.json")
//	if err != nil {
//	    log.Fatal(err)
//	}
func LoadCreatePrimaryResult(path string) (*CreatePrimaryResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var marshaled marshaledCreatePrimaryResult
	if err := json.Unmarshal(data, &marshaled); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	outPublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](marshaled.OutPublic)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal OutPublic: %w", err)
	}
	creationHash, err := tpm2.Unmarshal[tpm2.TPM2BDigest](marshaled.CreationHash)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CreationHash: %w", err)
	}
	creationTicket, err := tpm2.Unmarshal[tpm2.TPMTTKCreation](marshaled.CreationTicket)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal CreationTicket: %w", err)
	}
	name, err := tpm2.Unmarshal[tpm2.TPM2BName](marshaled.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal Name: %w", err)
	}

	return &CreatePrimaryResult{
		OutPublic:      *outPublic,
		CreationHash:   *creationHash,
		CreationTicket: *creationTicket,
		Name:           *name,
	}, nil
}
