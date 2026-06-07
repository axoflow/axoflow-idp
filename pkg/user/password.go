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

package user

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const (
	argon2Time    = 2
	argon2Memory  = 15 * 1024
	argon2Threads = 1
	argon2KeyLen  = 32

	// minPasswordLength is the minimum length enforced on every password-setting
	// path (Register, ChangePassword, SetPassword, AdminResetPassword).
	minPasswordLength = 8
)

// validatePassword enforces the minimum password policy applied on every write
// path, so a direct POST cannot bypass the client-side minlength hint. It
// requires at least minPasswordLength non-whitespace characters: trimming
// before the length check rejects whitespace-only or whitespace-padded values,
// which are almost always an accidental, trivially weak entry. It wraps
// ErrWeakPassword so callers can surface a friendly, retryable message at the
// route layer.
func validatePassword(p string) error {
	if len(strings.TrimSpace(p)) < minPasswordLength {
		return fmt.Errorf("%w: must be at least %d characters and not whitespace-only", ErrWeakPassword, minPasswordLength)
	}
	return nil
}

// hash returns an argon2id PHC string: $argon2id$v=<v>$m=<m>,t=<t>,p=<p>$<salt>$<hash>
func hash(salt []byte, password string) string {
	h := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(h))
}

// verifyPassword verifies a plaintext password against a stored hash string.
// Supports argon2id PHC strings ($argon2id$...) and bcrypt MCF strings ($2a$/$2b$/$2y$...).
func verifyPassword(user UserInfo, password string) bool {
	switch {
	case strings.HasPrefix(user.Password, "$argon2id$"):
		return verifyArgon2id(user.Password, password)
	case strings.HasPrefix(user.Password, "$2"):
		return bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil
	default:
		// Backward compat: Password was []byte, serialized by encoding/json as standard base64.
		// Salt was user.ID.String() with the current argon2id parameters.
		//
		// Renaming the ID of a user with a legacy hash breaks verification — the hash
		// was derived with the original ID as salt, so a new ID produces a different
		// expected value. Upgrade such users to PHC argon2id or bcrypt (both embed
		// their own salt) before changing their ID.
		raw, err := base64.StdEncoding.DecodeString(user.Password)
		if err != nil {
			return false
		}
		expected := argon2.IDKey([]byte(password), []byte(user.ID), argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
		return subtle.ConstantTimeCompare(raw, expected) == 1
	}
}

func verifyArgon2id(encoded, password string) bool {
	// $argon2id$v=<v>$m=<m>,t=<t>,p=<p>$<salt>$<hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil {
		return false
	}

	var m uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	actual := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
