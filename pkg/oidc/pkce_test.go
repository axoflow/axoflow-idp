// Copyright © 2026 Axoflow
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oidc

import (
	"strings"
	"testing"
)

// The verifier/challenge pair is RFC 7636 Appendix B.
const (
	rfcVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	rfcChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func TestVerifyPKCE(t *testing.T) {
	tests := []struct {
		name      string
		challenge string
		method    string
		verifier  string
		wantErr   error
	}{
		{"s256 match (RFC 7636 appendix B)", rfcChallenge, "S256", rfcVerifier, nil},
		{"s256 mismatch", rfcChallenge, "S256", strings.Repeat("a", 43), ErrInvalidGrant},
		{"challenge present, verifier missing", rfcChallenge, "S256", "", ErrInvalidGrant},
		{"verifier too short (42)", rfcChallenge, "S256", strings.Repeat("a", 42), ErrInvalidGrant},
		{"verifier too long (129)", rfcChallenge, "S256", strings.Repeat("a", 129), ErrInvalidGrant},
		{"unsupported stored method (plain)", rfcVerifier, "plain", rfcVerifier, ErrInvalidGrant},
		{"legacy: no challenge, no verifier", "", "", "", nil},
		{"anti-downgrade: no challenge, verifier present", "", "", rfcVerifier, ErrInvalidGrant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyPKCE(tt.challenge, tt.method, tt.verifier); err != tt.wantErr {
				t.Errorf("VerifyPKCE(%q,%q,%q) = %v, want %v", tt.challenge, tt.method, tt.verifier, err, tt.wantErr)
			}
		})
	}
}
