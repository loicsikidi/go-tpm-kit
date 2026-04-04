// This code is mostly inspired by this PR: https://github.com/google/go-tpm/pull/428
//
// It will be removed once the PR is merged.
package tpmutil

import (
	"bytes"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// Policy and NV Index constants from EK Credential Profile.
var (
	policyA = map[tpm2.TPMIAlgHash][]byte{
		tpm2.TPMAlgSHA256: policyASHA256,
		tpm2.TPMAlgSHA384: policyASHA384,
		tpm2.TPMAlgSHA512: policyASHA512,
		tpm2.TPMAlgSM3256: policyASM3256,
	}
	// policyB = map[tpm2.TPMIAlgHash][]byte{
	// 	tpm2.TPMAlgSHA256: policyBSHA256,
	// 	tpm2.TPMAlgSHA384: policyBSHA384,
	// 	tpm2.TPMAlgSHA512: policyBSHA512,
	// 	tpm2.TPMAlgSM3256: policyBSM3256,
	// }
	policyC = map[tpm2.TPMIAlgHash][]byte{
		tpm2.TPMAlgSHA256: policyCSHA256,
		tpm2.TPMAlgSHA384: policyCSHA384,
		tpm2.TPMAlgSHA512: policyCSHA512,
		tpm2.TPMAlgSM3256: policyCSM3256,
	}
)

// authPolicyA is a policy satisfied by proving knowledge of the Endorsement
// Hierarchy password.
//
// This is done by executing [PolicySecret] with [TPMRHEndorsement]. See the
// "Satisfying PolicyA" section of the EK Credential Profile for more info.
//
// This is the [TPMTPublic.AuthPolicy] for all Low Range templates.
func authPolicyA(hashAlg tpm2.TPMIAlgHash) (tpm2.TPM2BDigest, error) {
	if policy, ok := policyA[hashAlg]; ok {
		return tpm2.TPM2BDigest{Buffer: bytes.Clone(policy)}, nil
	}
	return tpm2.TPM2BDigest{}, fmt.Errorf("no PolicyA for hash alg 0x%x", hashAlg)
}

// authPolicyB is a policy satisfied by satisfying [authPolicyA] or
// [authPolicyC].
//
// This is done by:
//   - First, satifying either of the two policies.
//   - Then, executing [PolicyOr] with a digest list of {PolicyA, PolicyC}.
//
// See the "Satisfying PolicyB" section of the EK Credential Profile for more info.
//
// This is the [TPMTPublic.AuthPolicy] for all High Range templates.
// func authPolicyB(hashAlg tpm2.TPMIAlgHash) (tpm2.TPM2BDigest, error) {
// 	if policy, ok := policyB[hashAlg]; ok {
// 		return tpm2.TPM2BDigest{Buffer: bytes.Clone(policy)}, nil
// 	}
// 	return tpm2.TPM2BDigest{}, fmt.Errorf("no PolicyB for hash alg 0x%x", hashAlg)
// }

// authPolicyC is a policy satisfied by satisfying the policy stored at
// [AuthPolicyNVPublic].
//
// This is done by executing [PolicyAuthorizeNV] with the [TPMSNVPublic.NVIndex]
// of [AuthPolicyNVPublic].
func authPolicyC(hashAlg tpm2.TPMIAlgHash) (tpm2.TPM2BDigest, error) {
	if policy, ok := policyC[hashAlg]; ok {
		return tpm2.TPM2BDigest{Buffer: bytes.Clone(policy)}, nil
	}
	return tpm2.TPM2BDigest{}, fmt.Errorf("no PolicyC for hash alg 0x%x", hashAlg)
}
