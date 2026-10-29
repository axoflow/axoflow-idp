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

// HashNewPassword checks password against the policy and returns the hash
// that would be stored for userID, so a caller can run the ~100ms argon2id
// before a transaction such as SetPasswordByReset rather than inside it. It
// returns ErrBusy when the derivation gate refuses.
func HashNewPassword(userID, password string) (string, error) {
	if err := validatePassword(password); err != nil {
		return "", err
	}
	return gatedHash([]byte(userID), password)
}

// hash returns an argon2id PHC string: $argon2id$v=<v>$m=<m>,t=<t>,p=<p>$<salt>$<hash>
func hash(salt []byte, password string) string {
	h := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(h))
}

// bcryptMaxPassword is the longest password bcrypt reads: it ignores every
// byte after it.
const bcryptMaxPassword = 72

// verifyPassword verifies a plaintext password against a stored hash string,
// with the derivation run through kdf; the error is ErrBusy when the gate
// refused. Supports argon2id PHC strings ($argon2id$...) and bcrypt MCF
// strings ($2a$/$2b$/$2y$...). A stored value that can never match, such as
// LockedPasswordHash or a malformed hash, is refused after the dummy
// derivation, so it takes as long as a wrong password.
func verifyPassword(user UserInfo, password string) (bool, error) {
	var ok bool
	switch {
	case strings.HasPrefix(user.Password, "$argon2id$"):
		params, valid := parseArgon2id(user.Password)
		if !valid {
			return refuse(password)
		}
		err := kdf.run(func() {
			actual := argon2.IDKey([]byte(password), params.salt, params.time, params.memory, params.threads, uint32(len(params.key)))
			ok = subtle.ConstantTimeCompare(actual, params.key) == 1
		})
		return ok, err
	case strings.HasPrefix(user.Password, "$2"):
		if _, err := bcrypt.Cost([]byte(user.Password)); err != nil {
			return refuse(password)
		}
		// bcrypt would compare the first 72 bytes only, so any suffix would
		// pass; such a user sets a shorter password through a reset.
		if len(password) > bcryptMaxPassword {
			return refuse(password)
		}
		err := kdf.run(func() {
			ok = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil
		})
		return ok, err
	default:
		// Backward compat: Password was []byte, serialized by encoding/json as standard base64.
		// Salt was user.ID.String() with the current argon2id parameters.
		//
		// Renaming the ID of a user with a legacy hash breaks verification — the hash
		// was derived with the original ID as salt, so a new ID produces a different
		// expected value. Upgrade such users to PHC argon2id or bcrypt (both embed
		// their own salt) before changing their ID.
		raw, err := base64.StdEncoding.DecodeString(user.Password)
		if err != nil || len(raw) != argon2KeyLen {
			return refuse(password)
		}
		err = kdf.run(func() {
			expected := argon2.IDKey([]byte(password), []byte(user.ID), argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
			ok = subtle.ConstantTimeCompare(raw, expected) == 1
		})
		return ok, err
	}
}

// Bounds on the parameters of a stored argon2id string. users.json is read
// as it is, and argon2 allocates memory KiB, runs time passes and would
// panic on a time or threads of zero; a salt or digest length outside
// these is no hash this server writes either.
const (
	maxArgon2Memory  = 32 * 1024 // KiB
	maxArgon2Time    = 10
	maxArgon2Threads = 4
	maxSaltLen       = 1024 // salted with the user ID, which has no length limit
	minKeyLen        = 16
	maxKeyLen        = 64
)

// refuse runs the derivation of a wrong password against dummyPasswordHash,
// through the gate, and reports false.
func refuse(password string) (bool, error) {
	if testOnDummy != nil {
		testOnDummy()
	}
	_, err := verifyPassword(UserInfo{Password: dummyPasswordHash}, password)
	return false, err
}

// argon2idParams is a parsed argon2id PHC string.
type argon2idParams struct {
	memory, time uint32
	threads      uint8
	salt, key    []byte
}

// parseArgon2id parses encoded, reporting false for a malformed string or one
// whose parameters are outside the bounds above.
func parseArgon2id(encoded string) (argon2idParams, bool) {
	var params argon2idParams
	// $argon2id$v=<v>$m=<m>,t=<t>,p=<p>$<salt>$<hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return params, false
	}

	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return params, false
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.time, &params.threads); err != nil {
		return params, false
	}
	if params.memory > maxArgon2Memory ||
		params.time < 1 || params.time > maxArgon2Time ||
		params.threads < 1 || params.threads > maxArgon2Threads {
		return params, false
	}

	var err error
	if params.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil || len(params.salt) < 1 || len(params.salt) > maxSaltLen {
		return params, false
	}
	if params.key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(params.key) < minKeyLen || len(params.key) > maxKeyLen {
		return params, false
	}
	return params, true
}
