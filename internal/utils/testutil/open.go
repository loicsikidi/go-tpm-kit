package testutil

import (
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

func OpenSimulator(t *testing.T) transport.TPM {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("could not close TPM simulator: %v", err)
		}
	})
	return thetpm
}
