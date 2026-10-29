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
	"strconv"
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
		if !validBcrypt(user.Password) {
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
		if len(user.Password) > maxLegacyLen {
			return refuse(password)
		}
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

// Bounds on a stored hash. users.json is read as it is, and argon2
// allocates memory KiB, runs time passes and would panic on a time or
// threads of zero; bcrypt runs 2^cost rounds, up to 2^31, in one of the
// derivation gate's slots. A salt or digest length outside these is no hash
// this server writes either. The encoded lengths are checked before a value
// is split or decoded, so its size does not decide what that allocates.
const (
	maxArgon2Memory  = 32 * 1024 // KiB
	maxArgon2Time    = 10
	maxArgon2Threads = 4
	maxSaltLen       = 256 // the user ID, which the writers refuse beyond this
	minKeyLen        = 16
	maxKeyLen        = 64
	maxPHCLen        = 512
	maxBcryptCost    = 15 // about two seconds of a slot
	maxLegacyLen     = 64 // base64 of a 32-byte key is 44
)

// bcryptAlphabet is the base64 alphabet of a bcrypt salt and digest.
const bcryptAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// validBcrypt reports whether encoded is a bcrypt string whose comparison
// runs its full cost: 60 bytes, $2a$, $2b$ or $2y$, a cost from
// bcrypt.MinCost to maxBcryptCost, and a salt and digest in bcrypt's
// alphabet. bcrypt.Cost accepts a salt that fails to decode, and the
// comparison then returns before any work.
func validBcrypt(encoded string) bool {
	if len(encoded) != 60 || encoded[0] != '$' || encoded[1] != '2' || !strings.ContainsRune("aby", rune(encoded[2])) ||
		encoded[3] != '$' || encoded[6] != '$' {
		return false
	}
	tens, ones := encoded[4], encoded[5]
	if tens < '0' || tens > '9' || ones < '0' || ones > '9' {
		return false
	}
	cost := int(tens-'0')*10 + int(ones-'0')
	return cost >= bcrypt.MinCost && cost <= maxBcryptCost && strings.Trim(encoded[7:], bcryptAlphabet) == ""
}

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
	if len(encoded) > maxPHCLen {
		return params, false
	}
	// $argon2id$v=<v>$m=<m>,t=<t>,p=<p>$<salt>$<hash>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return params, false
	}

	if v, ok := phcParam(parts[2], "v", 32); !ok || v != argon2.Version {
		return params, false
	}

	m, rest, _ := strings.Cut(parts[3], ",")
	tm, p, _ := strings.Cut(rest, ",")
	memory, okM := phcParam(m, "m", 32)
	passes, okT := phcParam(tm, "t", 32)
	threads, okP := phcParam(p, "p", 8)
	if !okM || !okT || !okP {
		return params, false
	}
	params.memory, params.time, params.threads = uint32(memory), uint32(passes), uint8(threads)
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

// phcParam parses field as name=<decimal of at most bits bits>, with nothing
// before or after it.
func phcParam(field, name string, bits int) (uint64, bool) {
	value, ok := strings.CutPrefix(field, name+"=")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(value, 10, bits)
	return n, err == nil
}
