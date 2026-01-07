package tpmcrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name: "valid TPM2BPublic pointer",
			input: tpm2.New2B(tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					SignEncrypt: true,
				},
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 2048,
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPublicKeyRSA{
						Buffer: make([]byte, 256),
					},
				),
			}),
			wantErr: false,
		},
		{
			name: "valid TPMTPublic pointer",
			input: &tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				ObjectAttributes: tpm2.TPMAObject{
					SignEncrypt: true,
				},
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 2048,
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgRSA,
					&tpm2.TPM2BPublicKeyRSA{
						Buffer: make([]byte, 256),
					},
				),
			},
			wantErr: false,
		},
		{
			name:    "unsupported type",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PublicKey(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPublicKeyRSA(t *testing.T) {
	t.Run("valid RSA key", func(t *testing.T) {
		rsaPub := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					KeyBits: 2048,
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{
					Buffer: make([]byte, 256),
				},
			),
		}

		pub, err := PublicKeyRSA(rsaPub)
		if err != nil {
			t.Fatalf("PublicKeyRSA() failed: %v", err)
		}

		if pub == nil {
			t.Error("PublicKeyRSA() returned nil public key")
		}
	})

	t.Run("wrong type - ECC key", func(t *testing.T) {
		eccPub := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
					Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
				},
			),
		}

		_, err := PublicKeyRSA(eccPub)
		if err == nil {
			t.Error("PublicKeyRSA() expected error when given ECC key")
		}
	})
}

func TestPublicKeyECDSA(t *testing.T) {
	t.Run("valid ECC key", func(t *testing.T) {
		eccPub := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: tpm2.TPMECCNistP256,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
					Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
				},
			),
		}

		pub, err := PublicKeyECDSA(eccPub)
		if err != nil {
			t.Fatalf("PublicKeyECDSA() failed: %v", err)
		}

		if pub == nil {
			t.Error("PublicKeyECDSA() returned nil public key")
		}
	})

	t.Run("wrong type - RSA key", func(t *testing.T) {
		rsaPub := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					KeyBits: 2048,
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{
					Buffer: make([]byte, 256),
				},
			),
		}

		_, err := PublicKeyECDSA(rsaPub)
		if err == nil {
			t.Error("PublicKeyECDSA() expected error when given RSA key")
		}
	})
}

func TestValidatePublicKey(t *testing.T) {
	tests := []struct {
		name    string
		pub     tpm2.TPMTPublic
		wantErr bool
	}{
		{
			name: "valid RSA 2048 key",
			pub: tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 2048,
					},
				),
			},
			wantErr: false,
		},
		{
			name: "invalid RSA key - too small",
			pub: tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgRSA,
				NameAlg: tpm2.TPMAlgSHA256,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 1024,
					},
				),
			},
			wantErr: true,
		},
		{
			name: "valid ECC P256 key",
			pub: tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgECC,
				NameAlg: tpm2.TPMAlgSHA256,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCPoint{
						X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
						Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
					},
				),
			},
			wantErr: false,
		},
		{
			name: "invalid ECC key - insecure curve",
			pub: tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgECC,
				NameAlg: tpm2.TPMAlgSHA256,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCCurve(999),
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCPoint{
						X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
						Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
					},
				),
			},
			wantErr: true,
		},
		{
			name: "invalid ECC key - small X point",
			pub: tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgECC,
				NameAlg: tpm2.TPMAlgSHA256,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCPoint{
						X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 16)},
						Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
					},
				),
			},
			wantErr: true,
		},
		{
			name: "invalid ECC key - small Y point",
			pub: tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgECC,
				NameAlg: tpm2.TPMAlgSHA256,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
					},
				),
				Unique: tpm2.NewTPMUPublicID(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCPoint{
						X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
						Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 16)},
					},
				),
			},
			wantErr: true,
		},
		{
			name: "unsupported algorithm",
			pub: tpm2.TPMTPublic{
				Type:    tpm2.TPMAlgID(0x9999),
				NameAlg: tpm2.TPMAlgSHA256,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePublicKey(tt.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetDigest(t *testing.T) {
	data := []byte("test data")

	tests := []struct {
		name    string
		hash    crypto.Hash
		wantErr bool
	}{
		{
			name:    "SHA256",
			hash:    crypto.SHA256,
			wantErr: false,
		},
		{
			name:    "SHA384",
			hash:    crypto.SHA384,
			wantErr: false,
		},
		{
			name:    "SHA512",
			hash:    crypto.SHA512,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, err := GetDigest(data, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDigest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(digest) == 0 {
				t.Error("GetDigest() returned empty digest")
			}
		})
	}
}

func TestGetSigScheme(t *testing.T) {
	scheme := GetSigScheme(tpm2.TPMAlgRSASSA, tpm2.TPMAlgSHA256)

	if scheme.Scheme != tpm2.TPMAlgRSASSA {
		t.Errorf("GetSigScheme() scheme = %v, want %v", scheme.Scheme, tpm2.TPMAlgRSASSA)
	}
}

func TestGetSigSchemeFromPublic(t *testing.T) {
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				KeyBits: 2048,
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
	}

	scheme, err := GetSigSchemeFromPublic(pub)
	if err != nil {
		t.Fatalf("GetSigSchemeFromPublic() error = %v", err)
	}

	if scheme.Scheme != tpm2.TPMAlgRSASSA {
		t.Errorf("GetSigSchemeFromPublic() scheme = %v, want %v", scheme.Scheme, tpm2.TPMAlgRSASSA)
	}
}

func TestGetSigSchemeFromPublicKey(t *testing.T) {
	t.Run("RSA key with SHA256", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		scheme, err := GetSigSchemeFromPublicKey(&rsaKey.PublicKey, crypto.SHA256)
		if err != nil {
			t.Fatalf("GetSigSchemeFromPublicKey() error = %v", err)
		}

		if scheme.Scheme != tpm2.TPMAlgRSASSA {
			t.Errorf("GetSigSchemeFromPublicKey() scheme = %v, want %v", scheme.Scheme, tpm2.TPMAlgRSASSA)
		}
	})

	t.Run("ECDSA key with SHA256", func(t *testing.T) {
		eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		scheme, err := GetSigSchemeFromPublicKey(&eccKey.PublicKey, crypto.SHA256)
		if err != nil {
			t.Fatalf("GetSigSchemeFromPublicKey() error = %v", err)
		}

		if scheme.Scheme != tpm2.TPMAlgECDSA {
			t.Errorf("GetSigSchemeFromPublicKey() scheme = %v, want %v", scheme.Scheme, tpm2.TPMAlgECDSA)
		}
	})

	t.Run("RSA key with PSS", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		}

		scheme, err := GetSigSchemeFromPublicKey(&rsaKey.PublicKey, pssOpts)
		if err != nil {
			t.Fatalf("GetSigSchemeFromPublicKey() error = %v", err)
		}

		if scheme.Scheme != tpm2.TPMAlgRSAPSS {
			t.Errorf("GetSigSchemeFromPublicKey() scheme = %v, want %v", scheme.Scheme, tpm2.TPMAlgRSAPSS)
		}

		pssScheme, err := scheme.Details.RSAPSS()
		if err != nil {
			t.Fatalf("failed to get RSAPSS scheme: %v", err)
		}

		if pssScheme.HashAlg != tpm2.TPMAlgSHA256 {
			t.Errorf("RSAPSS hash = %v, want %v", pssScheme.HashAlg, tpm2.TPMAlgSHA256)
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		type unsupportedKey struct{}

		_, err := GetSigSchemeFromPublicKey(&unsupportedKey{}, crypto.SHA256)
		if err == nil {
			t.Error("GetSigSchemeFromPublicKey() expected error for unsupported key type")
		}
	})
}

func TestGetSigHashFromPublic(t *testing.T) {
	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				KeyBits: 2048,
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
			},
		),
	}

	hash, err := GetSigHashFromPublic(pub)
	if err != nil {
		t.Fatalf("GetSigHashFromPublic() error = %v", err)
	}

	if hash != crypto.SHA256 {
		t.Errorf("GetSigHashFromPublic() hash = %v, want %v", hash, crypto.SHA256)
	}
}

func TestGetSigSchemeAndHashFromPublic(t *testing.T) {
	tests := []struct {
		name       string
		pub        tpm2.TPMTPublic
		wantScheme tpm2.TPMAlgID
		wantHash   tpm2.TPMAlgID
		wantErr    bool
	}{
		{
			name: "RSA RSASSA",
			pub: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 2048,
						Scheme: tpm2.TPMTRSAScheme{
							Scheme: tpm2.TPMAlgRSASSA,
							Details: tpm2.NewTPMUAsymScheme(
								tpm2.TPMAlgRSASSA,
								&tpm2.TPMSSigSchemeRSASSA{
									HashAlg: tpm2.TPMAlgSHA256,
								},
							),
						},
					},
				),
			},
			wantScheme: tpm2.TPMAlgRSASSA,
			wantHash:   tpm2.TPMAlgSHA256,
			wantErr:    false,
		},
		{
			name: "RSA RSAPSS",
			pub: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 2048,
						Scheme: tpm2.TPMTRSAScheme{
							Scheme: tpm2.TPMAlgRSAPSS,
							Details: tpm2.NewTPMUAsymScheme(
								tpm2.TPMAlgRSAPSS,
								&tpm2.TPMSSigSchemeRSAPSS{
									HashAlg: tpm2.TPMAlgSHA384,
								},
							),
						},
					},
				),
			},
			wantScheme: tpm2.TPMAlgRSAPSS,
			wantHash:   tpm2.TPMAlgSHA384,
			wantErr:    false,
		},
		{
			name: "ECC ECDSA",
			pub: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
						Scheme: tpm2.TPMTECCScheme{
							Scheme: tpm2.TPMAlgECDSA,
							Details: tpm2.NewTPMUAsymScheme(
								tpm2.TPMAlgECDSA,
								&tpm2.TPMSSigSchemeECDSA{
									HashAlg: tpm2.TPMAlgSHA256,
								},
							),
						},
					},
				),
			},
			wantScheme: tpm2.TPMAlgECDSA,
			wantHash:   tpm2.TPMAlgSHA256,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme, hash, err := GetSigSchemeAndHashFromPublic(tt.pub)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSigSchemeAndHashFromPublic() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if scheme != tt.wantScheme {
				t.Errorf("GetSigSchemeAndHashFromPublic() scheme = %v, want %v", scheme, tt.wantScheme)
			}
			if hash != tt.wantHash {
				t.Errorf("GetSigSchemeAndHashFromPublic() hash = %v, want %v", hash, tt.wantHash)
			}
		})
	}
}

func TestNewRSASigKeyParameters(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		scheme  tpm2.TPMAlgID
		wantErr bool
	}{
		{
			name:    "RSA 2048 RSASSA",
			size:    2048,
			scheme:  tpm2.TPMAlgRSASSA,
			wantErr: false,
		},
		{
			name:    "RSA 3072 RSAPSS",
			size:    3072,
			scheme:  tpm2.TPMAlgRSAPSS,
			wantErr: false,
		},
		{
			name:    "RSA 4096 NULL",
			size:    4096,
			scheme:  tpm2.TPMAlgNull,
			wantErr: false,
		},
		{
			name:    "unsupported size",
			size:    1024,
			scheme:  tpm2.TPMAlgRSASSA,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := NewRSASigKeyParameters(tt.size, tt.scheme)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRSASigKeyParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && params == nil {
				t.Error("NewRSASigKeyParameters() returned nil params")
			}
		})
	}
}

func TestNewECCSigKeyParameters(t *testing.T) {
	tests := []struct {
		name    string
		curve   tpm2.TPMECCCurve
		wantErr bool
	}{
		{
			name:    "P256",
			curve:   tpm2.TPMECCNistP256,
			wantErr: false,
		},
		{
			name:    "P384",
			curve:   tpm2.TPMECCNistP384,
			wantErr: false,
		},
		{
			name:    "P521",
			curve:   tpm2.TPMECCNistP521,
			wantErr: false,
		},
		{
			name:    "unsupported curve",
			curve:   tpm2.TPMECCCurve(999),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := NewECCSigKeyParameters(tt.curve)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewECCSigKeyParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && params == nil {
				t.Error("NewECCSigKeyParameters() returned nil params")
			}
		})
	}
}

func TestNewECCKeyUnique(t *testing.T) {
	tests := []struct {
		name     string
		curveID  tpm2.TPMECCCurve
		wantSize int
		wantErr  bool
	}{
		{
			name:     "P256",
			curveID:  tpm2.TPMECCNistP256,
			wantSize: 32,
			wantErr:  false,
		},
		{
			name:     "P384",
			curveID:  tpm2.TPMECCNistP384,
			wantSize: 48,
			wantErr:  false,
		},
		{
			name:     "P521",
			curveID:  tpm2.TPMECCNistP521,
			wantSize: 65,
			wantErr:  false,
		},
		{
			name:     "unsupported curve",
			curveID:  tpm2.TPMECCCurve(999),
			wantSize: 0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unique, err := NewECCKeyUnique(tt.curveID)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewECCKeyUnique() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			eccPoint, err := unique.ECC()
			if err != nil {
				t.Fatalf("failed to extract ECC point: %v", err)
			}

			if len(eccPoint.X.Buffer) != tt.wantSize {
				t.Errorf("NewECCKeyUnique() X buffer size = %d, want %d", len(eccPoint.X.Buffer), tt.wantSize)
			}
			if len(eccPoint.Y.Buffer) != tt.wantSize {
				t.Errorf("NewECCKeyUnique() Y buffer size = %d, want %d", len(eccPoint.Y.Buffer), tt.wantSize)
			}
		})
	}
}

func TestNewHMACParameters(t *testing.T) {
	tests := []struct {
		name     string
		hashAlg  tpm2.TPMAlgID
		wantErr  bool
		wantHash tpm2.TPMAlgID
	}{
		{
			name:     "SHA256",
			hashAlg:  tpm2.TPMAlgSHA256,
			wantErr:  false,
			wantHash: tpm2.TPMAlgSHA256,
		},
		{
			name:     "SHA384",
			hashAlg:  tpm2.TPMAlgSHA384,
			wantErr:  false,
			wantHash: tpm2.TPMAlgSHA384,
		},
		{
			name:     "SHA512",
			hashAlg:  tpm2.TPMAlgSHA512,
			wantErr:  false,
			wantHash: tpm2.TPMAlgSHA512,
		},
		{
			name:    "unsupported hash algorithm",
			hashAlg: tpm2.TPMAlgSHA1,
			wantErr: true,
		},
		{
			name:    "null algorithm",
			hashAlg: tpm2.TPMAlgNull,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := NewHMACParameters(tt.hashAlg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHMACParameters() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if params == nil {
				t.Error("NewHMACParameters() returned nil params")
				return
			}

			keyedHashParams, err := params.KeyedHashDetail()
			if err != nil {
				t.Fatalf("failed to get keyed hash details: %v", err)
			}

			if keyedHashParams.Scheme.Scheme != tpm2.TPMAlgHMAC {
				t.Errorf("scheme = %v, want %v", keyedHashParams.Scheme.Scheme, tpm2.TPMAlgHMAC)
			}

			hmacScheme, err := keyedHashParams.Scheme.Details.HMAC()
			if err != nil {
				t.Fatalf("failed to get HMAC scheme: %v", err)
			}

			if hmacScheme.HashAlg != tt.wantHash {
				t.Errorf("hash algorithm = %v, want %v", hmacScheme.HashAlg, tt.wantHash)
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	t.Run("RSA signature", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		data := []byte("test data")
		hash := crypto.SHA256
		digest, err := GetDigest(data, hash)
		if err != nil {
			t.Fatalf("failed to compute digest: %v", err)
		}

		signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, digest)
		if err != nil {
			t.Fatalf("failed to sign data: %v", err)
		}

		sig := tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: signature},
				},
			),
		}

		err = VerifySignature(&rsaKey.PublicKey, sig, hash, data)
		if err != nil {
			t.Errorf("VerifySignature() failed: %v", err)
		}
	})

	t.Run("ECDSA signature", func(t *testing.T) {
		eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		data := []byte("test data")
		hash := crypto.SHA256
		digest, err := GetDigest(data, hash)
		if err != nil {
			t.Fatalf("failed to compute digest: %v", err)
		}

		r, s, err := ecdsa.Sign(rand.Reader, eccKey, digest)
		if err != nil {
			t.Fatalf("failed to sign data: %v", err)
		}

		sig := tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSignatureECC{
					Hash:       tpm2.TPMAlgSHA256,
					SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
					SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
				},
			),
		}

		err = VerifySignature(&eccKey.PublicKey, sig, hash, data)
		if err != nil {
			t.Errorf("VerifySignature() failed: %v", err)
		}
	})

	t.Run("invalid RSA signature", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		data := []byte("test data")
		hash := crypto.SHA256

		sig := tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: []byte("invalid signature")},
				},
			),
		}

		err = VerifySignature(&rsaKey.PublicKey, sig, hash, data)
		if err != ErrInvalidSignature {
			t.Errorf("VerifySignature() expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("invalid ECDSA signature", func(t *testing.T) {
		eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		data := []byte("test data")
		hash := crypto.SHA256

		sig := tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgECDSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSignatureECC{
					Hash:       tpm2.TPMAlgSHA256,
					SignatureR: tpm2.TPM2BECCParameter{Buffer: []byte("invalid")},
					SignatureS: tpm2.TPM2BECCParameter{Buffer: []byte("invalid")},
				},
			),
		}

		err = VerifySignature(&eccKey.PublicKey, sig, hash, data)
		if err != ErrInvalidSignature {
			t.Errorf("VerifySignature() expected ErrInvalidSignature, got %v", err)
		}
	})
}

func TestGetDigestFromHashAlg(t *testing.T) {
	data := []byte("test data")

	tests := []struct {
		name       string
		hashAlg    tpm2.TPMIAlgHash
		wantDigest []byte
		wantErr    bool
	}{
		{
			name:    "SHA1",
			hashAlg: tpm2.TPMAlgSHA1,
			wantDigest: func() []byte {
				h := crypto.SHA1.New()
				h.Write(data)
				return h.Sum(nil)
			}(),
			wantErr: false,
		},
		{
			name:    "SHA256",
			hashAlg: tpm2.TPMAlgSHA256,
			wantDigest: func() []byte {
				h := crypto.SHA256.New()
				h.Write(data)
				return h.Sum(nil)
			}(),
			wantErr: false,
		},
		{
			name:    "SHA384",
			hashAlg: tpm2.TPMAlgSHA384,
			wantDigest: func() []byte {
				h := crypto.SHA384.New()
				h.Write(data)
				return h.Sum(nil)
			}(),
			wantErr: false,
		},
		{
			name:    "SHA512",
			hashAlg: tpm2.TPMAlgSHA512,
			wantDigest: func() []byte {
				h := crypto.SHA512.New()
				h.Write(data)
				return h.Sum(nil)
			}(),
			wantErr: false,
		},
		{
			name:       "unsupported hash algorithm",
			hashAlg:    tpm2.TPMIAlgHash(0x9999),
			wantDigest: nil,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest, err := GetDigestFromHashAlg(data, tt.hashAlg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDigestFromHashAlg() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(digest) == 0 {
					t.Error("GetDigestFromHashAlg() returned empty digest")
				}
				if !bytes.Equal(digest, tt.wantDigest) {
					t.Errorf("GetDigestFromHashAlg() = %x, want %x", digest, tt.wantDigest)
				}
			}
		})
	}
}

func TestHashToAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		hash    crypto.Hash
		wantAlg tpm2.TPMAlgID
		wantErr bool
	}{
		{
			name:    "SHA1",
			hash:    crypto.SHA1,
			wantAlg: tpm2.TPMAlgSHA1,
			wantErr: false,
		},
		{
			name:    "SHA256",
			hash:    crypto.SHA256,
			wantAlg: tpm2.TPMAlgSHA256,
			wantErr: false,
		},
		{
			name:    "SHA384",
			hash:    crypto.SHA384,
			wantAlg: tpm2.TPMAlgSHA384,
			wantErr: false,
		},
		{
			name:    "SHA512",
			hash:    crypto.SHA512,
			wantAlg: tpm2.TPMAlgSHA512,
			wantErr: false,
		},
		{
			name:    "unsupported hash",
			hash:    crypto.Hash(99),
			wantAlg: tpm2.TPMAlgID(0),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg, err := HashToAlgorithm(tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashToAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && alg != tt.wantAlg {
				t.Errorf("HashToAlgorithm() = %v, want %v", alg, tt.wantAlg)
			}
		})
	}
}

func TestVerifySignatureFromPublic(t *testing.T) {
	t.Run("valid RSA signature", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		data := []byte("test data")
		hash := crypto.SHA256
		digest, err := GetDigest(data, hash)
		if err != nil {
			t.Fatalf("failed to compute digest: %v", err)
		}

		signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, hash, digest)
		if err != nil {
			t.Fatalf("failed to sign data: %v", err)
		}

		pub := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					KeyBits: 2048,
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgRSASSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgRSASSA,
							&tpm2.TPMSSigSchemeRSASSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{
					Buffer: rsaKey.N.Bytes(),
				},
			),
		}

		sig := tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: signature},
				},
			),
		}

		err = VerifySignatureFromPublic(pub, sig, data)
		if err != nil {
			t.Errorf("VerifySignatureFromPublic() failed: %v", err)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		pub := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					KeyBits: 2048,
					Scheme: tpm2.TPMTRSAScheme{
						Scheme: tpm2.TPMAlgRSASSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgRSASSA,
							&tpm2.TPMSSigSchemeRSASSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{
					Buffer: rsaKey.N.Bytes(),
				},
			),
		}

		sig := tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: []byte("invalid")},
				},
			),
		}

		err = VerifySignatureFromPublic(pub, sig, []byte("data"))
		if err != ErrInvalidSignature {
			t.Errorf("VerifySignatureFromPublic() expected ErrInvalidSignature, got %v", err)
		}
	})

	t.Run("invalid key size", func(t *testing.T) {
		pub := tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					KeyBits: 1024,
				},
			),
		}

		sig := tpm2.TPMTSignature{
			SigAlg: tpm2.TPMAlgRSASSA,
			Signature: tpm2.NewTPMUSignature(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSignatureRSA{
					Hash: tpm2.TPMAlgSHA256,
					Sig:  tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 128)},
				},
			),
		}

		err := VerifySignatureFromPublic(pub, sig, []byte("data"))
		if err == nil {
			t.Error("VerifySignatureFromPublic() expected error for small key size")
		}
	})
}
