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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

const (
	// pkceMethodS256 is the only code_challenge_method this server supports;
	// "plain" is deliberately rejected (RFC 9700 §2.1.1).
	pkceMethodS256 = "S256"

	pkceVerifierMinLen = 43
	pkceVerifierMaxLen = 128
)

// VerifyPKCE checks a token-endpoint code_verifier against the code_challenge
// and method that were bound to the authorization code at authorize time (per
// RFC 7636 §4.6). The method is the one *stored* at authorize, never one
// asserted by the token request, which is what defeats an S256->plain rewrite.
//
// A challenge with no verifier, or a verifier with no stored challenge (a
// stripped challenge, RFC 9700 §2.1.1), is rejected. Only S256 is supported.
func VerifyPKCE(challenge, method, verifier string) error {
	if challenge == "" {
		if verifier != "" {
			return ErrInvalidGrant
		}
		return nil
	}
	if verifier == "" {
		return ErrInvalidGrant
	}
	if len(verifier) < pkceVerifierMinLen || len(verifier) > pkceVerifierMaxLen {
		return ErrInvalidGrant
	}
	if method != pkceMethodS256 {
		return ErrInvalidGrant
	}

	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return ErrInvalidGrant
	}
	return nil
}
