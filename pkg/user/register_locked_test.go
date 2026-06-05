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

import "testing"

func TestLockedPasswordHashNeverVerifies(t *testing.T) {
	u := UserInfo{ID: "x", Password: LockedPasswordHash}
	for _, attempt := range []string{"", LockedPasswordHash, "password", "!"} {
		if verifyPassword(u, attempt) {
			t.Errorf("locked password should never verify, but %q did", attempt)
		}
	}
}

func TestRegisterLocked(t *testing.T) {
	path := writeUsersFile(t, `[]`)
	u, err := New(Config{FilePath: path, PasswordChangeable: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	id, err := u.RegisterLocked("carol", []string{"user"}, "carol@example.com")
	if err != nil {
		t.Fatalf("RegisterLocked: %v", err)
	}
	if id == "" {
		t.Fatal("RegisterLocked returned empty id")
	}

	// The account exists but cannot be logged into until a password is set.
	if _, ok := u.Authenticate("carol", ""); ok {
		t.Error("locked account should not authenticate with empty password")
	}
	if _, ok := u.Authenticate("carol", "anything"); ok {
		t.Error("locked account should not authenticate")
	}

	if err := u.SetPassword(id, "chosen"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if _, ok := u.Authenticate("carol", "chosen"); !ok {
		t.Error("account should authenticate after a password is set")
	}
}

func TestRegisterLockedDuplicateUsername(t *testing.T) {
	path := writeUsersFile(t, `[{"ID":"alice","Username":"alice"}]`)
	u, err := New(Config{FilePath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := u.RegisterLocked("alice", nil, ""); err == nil {
		t.Error("expected duplicate username error")
	}
}

func TestAdminRegisterLocked(t *testing.T) {
	path := writeUsersFile(t, `[{"ID":"admin1","Username":"admin","Groups":["admins"]}]`)
	u, err := New(Config{FilePath: path, UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := u.AdminRegisterLocked("admin1", "dave", []string{"user"}, "dave@example.com"); err != nil {
		t.Fatalf("AdminRegisterLocked: %v", err)
	}

	// A non-admin cannot use it.
	if _, err := u.AdminRegisterLocked("dave-not-admin", "eve", nil, ""); err == nil {
		t.Error("non-admin should be rejected")
	}
}
