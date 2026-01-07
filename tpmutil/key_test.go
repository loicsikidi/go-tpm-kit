package tpmutil_test

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/loicsikidi/go-tpm-kit/internal/utils/testutil"
	"github.com/loicsikidi/go-tpm-kit/tpmutil"
)

func TestAlgIDToKeyFamily(t *testing.T) {
	tests := []struct {
		name string
		alg  tpm2.TPMAlgID
		want tpmutil.KeyFamily
	}{
		{
			name: "RSA algorithm",
			alg:  tpm2.TPMAlgRSA,
			want: tpmutil.RSA,
		},
		{
			name: "ECC algorithm",
			alg:  tpm2.TPMAlgECC,
			want: tpmutil.ECC,
		},
		{
			name: "SHA256 algorithm (not a key type)",
			alg:  tpm2.TPMAlgSHA256,
			want: tpmutil.UnspecifiedKey,
		},
		{
			name: "NULL algorithm",
			alg:  tpm2.TPMAlgNull,
			want: tpmutil.UnspecifiedKey,
		},
		{
			name: "AES algorithm (not a key type)",
			alg:  tpm2.TPMAlgAES,
			want: tpmutil.UnspecifiedKey,
		},
		{
			name: "unknown algorithm ID",
			alg:  tpm2.TPMAlgID(0xFFFF),
			want: tpmutil.UnspecifiedKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tpmutil.AlgIDToKeyFamily(tt.alg)
			if got != tt.want {
				t.Errorf("AlgIDToKeyFamily() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicToKeyType(t *testing.T) {
	tests := []struct {
		name    string
		public  tpm2.TPMTPublic
		want    tpmutil.KeyType
		wantErr bool
	}{
		{
			name: "RSA 2048-bit key",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 2048,
					},
				),
			},
			want:    tpmutil.RSA2048,
			wantErr: false,
		},
		{
			name: "RSA 3072-bit key",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 3072,
					},
				),
			},
			want:    tpmutil.RSA3072,
			wantErr: false,
		},
		{
			name: "RSA 4096-bit key",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 4096,
					},
				),
			},
			want:    tpmutil.RSA4096,
			wantErr: false,
		},
		{
			name: "RSA unsupported key size (1024-bit)",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 1024,
					},
				),
			},
			want:    tpmutil.UnspecifiedAlgo,
			wantErr: true,
		},
		{
			name: "RSA unsupported key size (8192-bit)",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 8192,
					},
				),
			},
			want:    tpmutil.UnspecifiedAlgo,
			wantErr: true,
		},
		{
			name: "ECC NIST P-256",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
					},
				),
			},
			want:    tpmutil.ECCNISTP256,
			wantErr: false,
		},
		{
			name: "ECC NIST P-384",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP384,
					},
				),
			},
			want:    tpmutil.ECCNISTP384,
			wantErr: false,
		},
		{
			name: "ECC NIST P-521",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP521,
					},
				),
			},
			want:    tpmutil.ECCNISTP521,
			wantErr: false,
		},
		{
			name: "ECC SM2 P-256",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCSM2P256,
					},
				),
			},
			want:    tpmutil.ECCSM2P256,
			wantErr: false,
		},
		{
			name: "ECC unsupported curve (BN P-256)",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCBNP256,
					},
				),
			},
			want:    tpmutil.UnspecifiedAlgo,
			wantErr: true,
		},
		{
			name: "unsupported algorithm type (HMAC)",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgKeyedHash,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgKeyedHash,
					&tpm2.TPMSKeyedHashParms{},
				),
			},
			want:    tpmutil.UnspecifiedAlgo,
			wantErr: true,
		},
		{
			name: "unsupported algorithm type (SymCipher)",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgSymCipher,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgSymCipher,
					&tpm2.TPMSSymCipherParms{},
				),
			},
			want:    tpmutil.UnspecifiedAlgo,
			wantErr: true,
		},
		{
			name: "RSA with invalid parameters (non-RSA params)",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
					},
				),
			},
			want:    tpmutil.UnspecifiedAlgo,
			wantErr: true,
		},
		{
			name: "ECC with invalid parameters (non-ECC params)",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 2048,
					},
				),
			},
			want:    tpmutil.UnspecifiedAlgo,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tpmutil.PublicToKeyType(tt.public)
			if tt.wantErr {
				if err == nil {
					t.Errorf("PublicToKeyType() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("PublicToKeyType() unexpected error: %v", err)
				}
			}
			if got != tt.want {
				t.Errorf("PublicToKeyType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMustPublicToKeyType(t *testing.T) {
	t.Run("panics on unsupported key type", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("MustPublicToKeyType() did not panic")
			}
		}()

		public := tpm2.TPMTPublic{
			Type: tpm2.TPMAlgRSA,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					KeyBits: 1024,
				},
			),
		}
		tpmutil.MustPublicToKeyType(public)
	})

	t.Run("returns key type on success", func(t *testing.T) {
		public := tpm2.TPMTPublic{
			Type: tpm2.TPMAlgRSA,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					KeyBits: 2048,
				},
			),
		}
		got := tpmutil.MustPublicToKeyType(public)
		if got != tpmutil.RSA2048 {
			t.Errorf("MustPublicToKeyType() = %v, want %v", got, tpmutil.RSA2048)
		}
	})
}

func TestKeyFamilyString(t *testing.T) {
	tests := []struct {
		name string
		kf   tpmutil.KeyFamily
		want string
	}{
		{
			name: "RSA key family",
			kf:   tpmutil.RSA,
			want: "RSA",
		},
		{
			name: "ECC key family",
			kf:   tpmutil.ECC,
			want: "ECC",
		},
		{
			name: "Unspecified key",
			kf:   tpmutil.UnspecifiedKey,
			want: "unknown(0)",
		},
		{
			name: "invalid key family value",
			kf:   tpmutil.KeyFamily(999),
			want: "unknown(999)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.kf.String()
			if got != tt.want {
				t.Errorf("KeyFamily.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyTypeString(t *testing.T) {
	tests := []struct {
		name string
		kt   tpmutil.KeyType
		want string
	}{
		{
			name: "RSA 2048",
			kt:   tpmutil.RSA2048,
			want: "RSA_2048",
		},
		{
			name: "RSA 3072",
			kt:   tpmutil.RSA3072,
			want: "RSA_3072",
		},
		{
			name: "RSA 4096",
			kt:   tpmutil.RSA4096,
			want: "RSA_4096",
		},
		{
			name: "ECC NIST P-256",
			kt:   tpmutil.ECCNISTP256,
			want: "ECC_NIST_P256",
		},
		{
			name: "ECC NIST P-384",
			kt:   tpmutil.ECCNISTP384,
			want: "ECC_NIST_P384",
		},
		{
			name: "ECC NIST P-521",
			kt:   tpmutil.ECCNISTP521,
			want: "ECC_NIST_P521",
		},
		{
			name: "ECC SM2 P-256",
			kt:   tpmutil.ECCSM2P256,
			want: "ECC_SM2_P256",
		},
		{
			name: "Unspecified algorithm",
			kt:   tpmutil.UnspecifiedAlgo,
			want: "unknown(0)",
		},
		{
			name: "invalid key type value",
			kt:   tpmutil.KeyType(999),
			want: "unknown(999)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.kt.String()
			if got != tt.want {
				t.Errorf("KeyType.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicToKeyTypeErrorMessages(t *testing.T) {
	tests := []struct {
		name          string
		public        tpm2.TPMTPublic
		wantErrSubstr string
	}{
		{
			name: "RSA unsupported size error message",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 1024,
					},
				),
			},
			wantErrSubstr: "unsupported RSA key size: 1024 bits",
		},
		{
			name: "ECC unsupported curve error message",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCBNP256,
					},
				),
			},
			wantErrSubstr: "unsupported ECC curve",
		},
		{
			name: "unsupported algorithm error message",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgKeyedHash,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgKeyedHash,
					&tpm2.TPMSKeyedHashParms{},
				),
			},
			wantErrSubstr: "unsupported key algorithm",
		},
		{
			name: "RSA parameter extraction error",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgRSA,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgECC,
					&tpm2.TPMSECCParms{
						CurveID: tpm2.TPMECCNistP256,
					},
				),
			},
			wantErrSubstr: "failed to get RSA details",
		},
		{
			name: "ECC parameter extraction error",
			public: tpm2.TPMTPublic{
				Type: tpm2.TPMAlgECC,
				Parameters: tpm2.NewTPMUPublicParms(
					tpm2.TPMAlgRSA,
					&tpm2.TPMSRSAParms{
						KeyBits: 2048,
					},
				),
			},
			wantErrSubstr: "failed to get ECC details",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tpmutil.PublicToKeyType(tt.public)
			if err == nil {
				t.Fatalf("PublicToKeyType() expected error containing %q, got nil", tt.wantErrSubstr)
			}
			if !errors.Is(err, err) {
				t.Errorf("error type mismatch")
			}
			errMsg := err.Error()
			if len(tt.wantErrSubstr) > 0 && !containsSubstring(errMsg, tt.wantErrSubstr) {
				t.Errorf("PublicToKeyType() error = %q, want substring %q", errMsg, tt.wantErrSubstr)
			}
		})
	}
}

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || indexSubstring(s, substr) >= 0)
}

func indexSubstring(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// TestNewApplicationKeyTemplate verifies that [tpmutil.NewApplicationKeyTemplate]
// generates valid TPM key templates and that these templates can be used to
// successfully create keys in the TPM.
//
// Note: RSA 3072/4096 and ECC SM2 P-256 are not tested as they are not fully
// supported by the TPM simulator (either size limitations or unsupported
// signature schemes).
func TestNewApplicationKeyTemplate(t *testing.T) {
	thetpm := testutil.OpenSimulator(t)

	// Create SRK first
	srkHandle, err := tpmutil.GetSKRHandle(thetpm, tpmutil.ParentConfig{})
	if err != nil {
		t.Fatalf("failed to get SRK handle: %v", err)
	}

	tests := []struct {
		name          string
		config        tpmutil.KeyConfig
		wantErr       bool
		wantErrSubstr string
		validate      func(t *testing.T, tmpl tpm2.TPMTPublic)
	}{
		{
			name:    "default config (ECC NIST P-256)",
			config:  tpmutil.KeyConfig{},
			wantErr: false,
			validate: func(t *testing.T, tmpl tpm2.TPMTPublic) {
				if tmpl.Type != tpm2.TPMAlgECC {
					t.Errorf("expected Type = TPMAlgECC, got %v", tmpl.Type)
				}
				if tmpl.NameAlg != tpm2.TPMAlgSHA256 {
					t.Errorf("expected NameAlg = TPMAlgSHA256, got %v", tmpl.NameAlg)
				}
				eccParams, err := tmpl.Parameters.ECCDetail()
				if err != nil {
					t.Fatalf("failed to get ECC details: %v", err)
				}
				if eccParams.CurveID != tpm2.TPMECCNistP256 {
					t.Errorf("expected CurveID = TPMECCNistP256, got %v", eccParams.CurveID)
				}
				if !tmpl.ObjectAttributes.SignEncrypt {
					t.Error("expected SignEncrypt to be true")
				}
				if tmpl.ObjectAttributes.Decrypt {
					t.Error("expected Decrypt to be false")
				}
			},
		},
		{
			name: "RSA 2048",
			config: tpmutil.KeyConfig{
				KeyType: tpmutil.RSA2048,
			},
			wantErr: false,
			validate: func(t *testing.T, tmpl tpm2.TPMTPublic) {
				if tmpl.Type != tpm2.TPMAlgRSA {
					t.Errorf("expected Type = TPMAlgRSA, got %v", tmpl.Type)
				}
				if tmpl.NameAlg != tpm2.TPMAlgSHA256 {
					t.Errorf("expected NameAlg = TPMAlgSHA256, got %v", tmpl.NameAlg)
				}
				rsaParams, err := tmpl.Parameters.RSADetail()
				if err != nil {
					t.Fatalf("failed to get RSA details: %v", err)
				}
				if rsaParams.KeyBits != 2048 {
					t.Errorf("expected KeyBits = 2048, got %v", rsaParams.KeyBits)
				}
				if !tmpl.ObjectAttributes.SignEncrypt {
					t.Error("expected SignEncrypt to be true")
				}
				if !tmpl.ObjectAttributes.Decrypt {
					t.Error("expected Decrypt to be true")
				}
			},
		},
		{
			name: "ECC NIST P-256",
			config: tpmutil.KeyConfig{
				KeyType: tpmutil.ECCNISTP256,
			},
			wantErr: false,
			validate: func(t *testing.T, tmpl tpm2.TPMTPublic) {
				if tmpl.Type != tpm2.TPMAlgECC {
					t.Errorf("expected Type = TPMAlgECC, got %v", tmpl.Type)
				}
				if tmpl.NameAlg != tpm2.TPMAlgSHA256 {
					t.Errorf("expected NameAlg = TPMAlgSHA256, got %v", tmpl.NameAlg)
				}
				eccParams, err := tmpl.Parameters.ECCDetail()
				if err != nil {
					t.Fatalf("failed to get ECC details: %v", err)
				}
				if eccParams.CurveID != tpm2.TPMECCNistP256 {
					t.Errorf("expected CurveID = TPMECCNistP256, got %v", eccParams.CurveID)
				}
			},
		},
		{
			name: "ECC NIST P-384",
			config: tpmutil.KeyConfig{
				KeyType: tpmutil.ECCNISTP384,
			},
			wantErr: false,
			validate: func(t *testing.T, tmpl tpm2.TPMTPublic) {
				if tmpl.Type != tpm2.TPMAlgECC {
					t.Errorf("expected Type = TPMAlgECC, got %v", tmpl.Type)
				}
				if tmpl.NameAlg != tpm2.TPMAlgSHA384 {
					t.Errorf("expected NameAlg = TPMAlgSHA384, got %v", tmpl.NameAlg)
				}
				eccParams, err := tmpl.Parameters.ECCDetail()
				if err != nil {
					t.Fatalf("failed to get ECC details: %v", err)
				}
				if eccParams.CurveID != tpm2.TPMECCNistP384 {
					t.Errorf("expected CurveID = TPMECCNistP384, got %v", eccParams.CurveID)
				}
			},
		},
		{
			name: "ECC NIST P-521",
			config: tpmutil.KeyConfig{
				KeyType: tpmutil.ECCNISTP521,
			},
			wantErr: false,
			validate: func(t *testing.T, tmpl tpm2.TPMTPublic) {
				if tmpl.Type != tpm2.TPMAlgECC {
					t.Errorf("expected Type = TPMAlgECC, got %v", tmpl.Type)
				}
				if tmpl.NameAlg != tpm2.TPMAlgSHA512 {
					t.Errorf("expected NameAlg = TPMAlgSHA512, got %v", tmpl.NameAlg)
				}
				eccParams, err := tmpl.Parameters.ECCDetail()
				if err != nil {
					t.Fatalf("failed to get ECC details: %v", err)
				}
				if eccParams.CurveID != tpm2.TPMECCNistP521 {
					t.Errorf("expected CurveID = TPMECCNistP521, got %v", eccParams.CurveID)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl, err := tpmutil.NewApplicationKeyTemplate(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NewApplicationKeyTemplate() expected error, got nil")
				}
				if tt.wantErrSubstr != "" && !containsSubstring(err.Error(), tt.wantErrSubstr) {
					t.Errorf("NewApplicationKeyTemplate() error = %q, want substring %q", err.Error(), tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewApplicationKeyTemplate() unexpected error: %v", err)
			}

			if tt.validate != nil {
				tt.validate(t, tmpl)
			}

			// Test that the template can actually be used to create a key
			keyHandle, err := tpmutil.Create(thetpm, tpmutil.CreateConfig{
				ParentHandle: srkHandle,
				InPublic:     tmpl,
			})
			if err != nil {
				t.Fatalf("failed to create key with template: %v", err)
			}
			defer keyHandle.Close()

			// Verify the created key matches expected type
			gotKeyType, err := tpmutil.PublicToKeyType(*keyHandle.Public())
			if err != nil {
				t.Fatalf("failed to get key type from created key: %v", err)
			}
			expectedKeyType := tt.config.KeyType
			if expectedKeyType == tpmutil.UnspecifiedAlgo {
				expectedKeyType = tpmutil.ECCNISTP256
			}
			if gotKeyType != expectedKeyType {
				t.Errorf("created key type = %v, want %v", gotKeyType, expectedKeyType)
			}
		})
	}
}
