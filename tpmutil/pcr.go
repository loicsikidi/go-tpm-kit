package tpmutil

import "github.com/google/go-tpm/tpm2"

const (
	// MaxPCRIndex is the maximum PCR index supported by PC Client TPMs.
	//
	// PC Client specification mandates at least 24 PCRs (0-23).
	MaxPCRIndex = 23
)

// ToTPMLPCRSelection converts a slice of PCR numbers and a hash algorithm to a [tpm2.TPMLPCRSelection] structure.
//
// Returns an empty TPMLPCRSelection if no valid PCRs are provided.
//
// Example:
//
//	// Create a PCR selection for PCRs 0, 1, 7 using SHA256
//	selection := tpmutil.ToTPMLPCRSelection([]uint{0, 1, 7}, tpm2.TPMAlgSHA256)
//	// Use the selection in TPM operations like PolicyPCR or Quote
func ToTPMLPCRSelection(pcrs []uint, bank tpm2.TPMIAlgHash) tpm2.TPMLPCRSelection {
	// Filter valid PCRs (within range)
	validPCRs := make([]uint, 0, len(pcrs))
	for _, pcr := range pcrs {
		if pcr <= MaxPCRIndex {
			validPCRs = append(validPCRs, pcr)
		}
	}

	if len(validPCRs) == 0 {
		return tpm2.TPMLPCRSelection{}
	}

	if bank == 0 {
		bank = tpm2.TPMAlgSHA256
	}

	return tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      bank,
				PCRSelect: tpm2.PCClientCompatible.PCRs(validPCRs...),
			},
		},
	}
}

// PCRSelectToPCRs converts a byte slice representing a PCR selection into a slice of PCR numbers.
//
// Example:
//
//	// Convert a PCR selection bitmap to PCR numbers
//	// The byte slice [0x83, 0x00, 0x00] represents PCRs 0, 1, and 7
//	pcrs := tpmutil.PCRSelectToPCRs([]byte{0x83, 0x00, 0x00})
//	// pcrs will be []uint{0, 1, 7}
func PCRSelectToPCRs(selection []byte) []uint {
	var pcrs []uint
	for byteIdx, byteVal := range selection {
		for bitIdx := range uint(8) {
			if (byteVal & (1 << bitIdx)) != 0 {
				pcrNum := uint(byteIdx)*8 + bitIdx
				pcrs = append(pcrs, pcrNum)
			}
		}
	}
	return pcrs
}
