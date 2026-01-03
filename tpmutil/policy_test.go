package tpmutil_test

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/internal/utils/testutil"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestEkPolicyCallback(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	// Start a policy session
	sess, closer, err := tpm2.PolicySession(thetpm, tpm2.TPMAlgSHA256, 16, tpm2.Trial())
	if err != nil {
		t.Fatalf("PolicySession() failed: %v", err)
	}
	defer func() {
		if err := closer(); err != nil {
			t.Errorf("closer() failed: %v", err)
		}
	}()

	// Use EkPolicy to satisfy the policy
	err = tpmutil.EkPolicyCallback(thetpm, sess.Handle(), tpm2.TPM2BNonce{})
	if err != nil {
		t.Fatalf("EkPolicy() failed: %v", err)
	}
}
