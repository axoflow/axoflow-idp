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
	"strings"
	"testing"
)

func newTestUser(t *testing.T, passwordChangeable bool) *User {
	t.Helper()
	path := writeUsersFile(t, `[{"ID":"alice","Username":"alice"}]`)
	u, err := New(Config{FilePath: path, PasswordChangeable: passwordChangeable})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u.users[0].Password = hash([]byte("alice"), "original")
	return u
}

func TestSetPassword(t *testing.T) {
	u := newTestUser(t, true)

	if err := u.SetPassword("alice", "brand-new"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	if _, ok := u.Authenticate("alice", "brand-new"); !ok {
		t.Error("new password should authenticate")
	}
	if _, ok := u.Authenticate("alice", "original"); ok {
		t.Error("old password should no longer authenticate")
	}
}

func TestSetPasswordDisabled(t *testing.T) {
	u := newTestUser(t, false)

	err := u.SetPassword("alice", "brand-new")
	if err == nil {
		t.Fatal("SetPassword should fail when passwordChangeable is false")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSetPasswordUnknownUser(t *testing.T) {
	u := newTestUser(t, true)
	if err := u.SetPassword("nobody", "x"); err == nil {
		t.Error("SetPassword should fail for unknown user")
	}
}

func TestChangePassword(t *testing.T) {
	u := newTestUser(t, true)

	if err := u.ChangePassword("alice", "wrong", "new"); err == nil {
		t.Error("ChangePassword with wrong old password should fail")
	}
	if err := u.ChangePassword("alice", "original", "new"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if _, ok := u.Authenticate("alice", "new"); !ok {
		t.Error("changed password should authenticate")
	}
}
