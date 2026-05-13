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

package user

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/oklog/ulid/v2"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

func TestHashAndVerify(t *testing.T) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	h := hash(salt, "correcthorsebatterystaple")
	u := UserInfo{Password: h}

	if !verifyPassword(u, "correcthorsebatterystaple") {
		t.Error("correct password should verify")
	}
	if verifyPassword(u, "wrong") {
		t.Error("wrong password should not verify")
	}
}

func TestVerifyArgon2idDifferentParams(t *testing.T) {
	// Verify that verifyArgon2id re-derives with the params from the encoded string,
	// so changing time/memory in the current defaults doesn't break old hashes.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	// Hash with non-default params (t=1, m=64KB, p=2).
	h := argon2.IDKey([]byte("mypassword"), salt, 1, 64*1024, 2, 32)
	encoded := "$argon2id$v=19$m=65536,t=1,p=2$" +
		base64.RawStdEncoding.EncodeToString(salt) + "$" +
		base64.RawStdEncoding.EncodeToString(h)

	u := UserInfo{Password: encoded}
	if !verifyPassword(u, "mypassword") {
		t.Error("should verify with params from encoded string")
	}
	if verifyPassword(u, "notmypassword") {
		t.Error("wrong password should not verify")
	}
}

func TestVerifyBcrypt(t *testing.T) {
	hashed, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := UserInfo{Password: string(hashed)}

	if !verifyPassword(u, "secret") {
		t.Error("correct password should verify against bcrypt hash")
	}
	if verifyPassword(u, "wrong") {
		t.Error("wrong password should not verify against bcrypt hash")
	}
}

func TestVerifyLegacyBase64(t *testing.T) {
	id := ulid.Make().String()
	h := argon2.IDKey([]byte("legacypass"), []byte(id), argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	u := UserInfo{
		ID:       id,
		Password: base64.StdEncoding.EncodeToString(h),
	}

	if !verifyPassword(u, "legacypass") {
		t.Error("correct password should verify against legacy base64 hash")
	}
	if verifyPassword(u, "wrong") {
		t.Error("wrong password should not verify against legacy base64 hash")
	}
}

func TestVerifyInvalidHash(t *testing.T) {
	u := UserInfo{Password: "notahash"}
	if verifyPassword(u, "anything") {
		t.Error("garbage hash should not verify")
	}
}
