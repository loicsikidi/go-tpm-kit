// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509ext

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"reflect"
	"testing"

	"github.com/loicsikidi/go-tpm-kit/internal/utils"
	"github.com/loicsikidi/go-tpm-kit/tpmcert/oid"
	testutil "github.com/loicsikidi/go-tpm-kit/tpmtest/testutil/ek"
)

func TestParseEKCert(t *testing.T) {
	type want struct {
		san  *SubjectAltName
		spec *TPMSpecification
	}
	tests := []struct {
		name     string
		pemBytes []byte
		want     want
	}{
		{
			name:     "ok",
			pemBytes: testutil.IntelEKCert,
			want: want{
				san: &SubjectAltName{
					TPMManufacturer: "INTC",
					TPMModel:        "SPT",
					TPMVersion:      "id:00020000",
				},
				spec: &TPMSpecification{
					Family:   "2.0",
					Revision: 103,
					Level:    0,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO(lsi): migrate to commons/crypto/pemutil
			cert, err := utils.ParseCertificate(tt.pemBytes)
			if err != nil {
				t.Fatalf("ParseCertificate() error = %v", err)
			}

			san, err := GetSubjectAltNameFromCertificate(cert)
			if err != nil {
				t.Fatalf("GetSubjectAltNameFromCertificate() error = %v", err)
			}
			if !reflect.DeepEqual(tt.want.san, san) {
				t.Errorf("GetSubjectAltNameFromCertificate() = %v, want %v", san, tt.want.san)
			}

			spec, err := GetTpmSpecficationFromCertificate(cert)
			if err != nil {
				t.Fatalf("GetTpmSpecficationFromCertificate() error = %v", err)
			}
			if !reflect.DeepEqual(tt.want.spec, spec) {
				t.Errorf("GetTpmSpecficationFromCertificate() = %v, want %v", spec, tt.want.spec)
			}

			if got := len(cert.UnknownExtKeyUsage); got != 1 {
				t.Errorf("len(cert.UnknownExtKeyUsage) = %d, want 1", got)
			}
			if got := cert.UnknownExtKeyUsage[0]; !reflect.DeepEqual(asn1.ObjectIdentifier(oid.EKCertificate), got) {
				t.Errorf("cert.UnknownExtKeyUsage[0] = %v, want %v", got, asn1.ObjectIdentifier(oid.EKCertificate))
			}
		})
	}
}

func TestMarshalTpmSpecification(t *testing.T) {
	tests := []struct {
		name string
		spec *TPMSpecification
	}{
		{
			name: "marshal valid TPMSpecification",
			spec: &TPMSpecification{
				Family:   "2.0",
				Revision: 99,
				Level:    0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := MarshalTpmSpecification(tt.spec, false)
			if err != nil {
				t.Fatalf("MarshalTpmSpecification() error = %v", err)
			}

			cert := &x509.Certificate{
				Extensions: []pkix.Extension{ext},
			}

			spec, err := GetTpmSpecficationFromCertificate(cert)
			if err != nil {
				t.Fatalf("GetTpmSpecficationFromCertificate() error = %v", err)
			}
			if !reflect.DeepEqual(tt.spec, spec) {
				t.Errorf("GetTpmSpecficationFromCertificate() = %v, want %v", spec, tt.spec)
			}
		})
	}
}
