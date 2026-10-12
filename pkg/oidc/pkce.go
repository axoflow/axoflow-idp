// Copyright © 2025 Axoflow
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
	"regexp"
)

// RFC 7636 §4.1 verifier syntax; an S256 challenge is always 43 base64url characters.
var (
	codeVerifierPattern  = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	codeChallengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

func validCodeChallenge(challenge string) bool {
	return codeChallengePattern.MatchString(challenge)
}

// VerifyPKCE reports whether BASE64URL(SHA256(verifier)) == challenge (RFC 7636 §4.6), in constant time.
func VerifyPKCE(challenge, verifier string) bool {
	if !codeVerifierPattern.MatchString(verifier) || !validCodeChallenge(challenge) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}
