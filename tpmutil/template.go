package tpmutil

import "github.com/google/go-tpm/tpm2"

var (
	// RSASRKTemplate contains the TCG reference RSA-2048 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	defaultRSASRKTemplate = tpm2.RSASRKTemplate
	// ECCSRKTemplate contains the TCG reference ECC-P256 SRK template.
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	defaultECCSRKTemplate = tpm2.ECCSRKTemplate
)
