// Copyright (c) 2026, Loïc Sikidi
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ek

import _ "embed"

//go:embed testdata/ekcert.pem
var ExpiredEKCert []byte

//go:embed testdata/intel-ekcert.pem
var IntelEKCert []byte
