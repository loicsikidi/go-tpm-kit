// Copyright (c) 2025, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tpmutil

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// EkPolicyACallback is a callback used to satisfy EK's PolicyA.
// It is used to create a policy session for the endorsement hierarchy.
//
// Example:
//
//	activateRsp, err := tpm2.ActivateCredential{
//		KeyHandle: tpmutil.ToAuthHandle(ekHandle, tpm2.Policy(ekTemplate.NameAlg, 16, tpmutil.EkPolicyCallback)),
//		truncated...
//	}.Execute(tpm)
func EkPolicyACallback(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	// Satisfy PolicyA by calling [tpm2.PolicySecret] on [tpm2.TPMRHEndorsement].
	cmd := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	return err
}

// EkPolicyBViaACallback is a callback used to satisfy EK's PolicyB via PolicyA.
// It is used to create a policy session for the endorsement hierarchy.
//
// Example:
//
//	activateRsp, err := tpm2.ActivateCredential{
//		KeyHandle: tpmutil.ToAuthHandle(ekHandle, tpm2.Policy(ekTemplate.NameAlg, 16, tpmutil.EkPolicyBViaACallback(ekTemplate.NameAlg))),
//		truncated...
//	}.Execute(tpm)
func EkPolicyBViaACallback(alg tpm2.TPMIAlgHash) tpm2.PolicyCallback {
	return func(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
		if err := EkPolicyACallback(t, handle, nonceTPM); err != nil {
			return err
		}
		return ekPolicyB(t, handle, alg)
	}
}

// Satisfy PolicyB by calling [tpm2.PolicyOr] with PolicyA and PolicyC.
func ekPolicyB(t transport.TPM, handle tpm2.TPMISHPolicy, alg tpm2.TPMIAlgHash) error {
	policyA, _ := authPolicyA(alg)
	policyC, _ := authPolicyC(alg)
	digests := []tpm2.TPM2BDigest{policyA, policyC}

	policyOrCmd := tpm2.PolicyOr{
		PolicySession: handle,
		PHashList:     tpm2.TPMLDigest{Digests: digests},
	}
	_, err := policyOrCmd.Execute(t)
	return err
}
