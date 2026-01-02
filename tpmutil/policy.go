package tpmutil

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// EkPolicyCallback is a callback used to satisfy EK's authPolicy.
// It is used to create a policy session for the endorsement hierarchy.
//
// Example:
//
//	activateRsp, err := tpm2.ActivateCredential{
//		KeyHandle: tpmutil.ToAuthHandle(ekHandle, tpm2.Policy(tpm2.TPMAlgSHA256, 16, tpmutil.EkPolicyCallback)),
//		truncated...
//	}.Execute(tpm)
func EkPolicyCallback(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	cmd := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}
	_, err := cmd.Execute(t)
	return err
}
