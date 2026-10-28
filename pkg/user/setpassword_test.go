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
	"errors"
	"testing"
)

func newTestUser(t *testing.T, static bool) *User {
	t.Helper()
	path := writeUsersFile(t, `[{"ID":"alice","Username":"alice"}]`)
	u, err := New(Config{FilePath: path, Static: static})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Seed directly (bypasses the read-only guard) so static stores can be set up.
	u.users[0].Password = hash([]byte("alice"), "original")
	return u
}

func TestSetPassword(t *testing.T) {
	u := newTestUser(t, false)

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

func TestSetPasswordStatic(t *testing.T) {
	u := newTestUser(t, true)

	if err := u.SetPassword("alice", "brand-new"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("SetPassword in static mode = %v, want ErrReadOnly", err)
	}
}

func TestSetPasswordUnknownUser(t *testing.T) {
	u := newTestUser(t, false)
	err := u.SetPassword("nobody", "validpassword1")
	if err == nil {
		t.Fatal("SetPassword should fail for unknown user")
	}
	if errors.Is(err, ErrWeakPassword) {
		t.Fatalf("expected user-not-found error, got weak-password error: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	u := newTestUser(t, false)

	if _, err := u.ChangePassword("alice", "wrong", "newpass12"); err == nil {
		t.Error("ChangePassword with wrong old password should fail")
	}
	newHash, err := u.ChangePassword("alice", "original", "newpass12")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if alice, _ := u.Get("alice"); alice.Password != newHash {
		t.Error("ChangePassword returned a hash other than the one stored")
	}
	if _, ok := u.Authenticate("alice", "newpass12"); !ok {
		t.Error("changed password should authenticate")
	}
}

// A change verified against the old hash must not overwrite a password that
// another path set while it ran.
func TestChangePasswordLosesToConcurrentChange(t *testing.T) {
	tests := []struct {
		name    string
		compete func(u *User) error
	}{
		{"admin reset", func(u *User) error { return u.AdminResetPassword("admin1", "alice", "adminset1") }},
		{"reset link", func(u *User) error {
			alice, _ := u.Get("alice")
			h, _ := HashNewPassword("alice", "adminset1")
			return u.SetPasswordByReset("alice", "admin1", alice.Password, h)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeUsersFile(t, `[{"ID":"admin1","Username":"admin","Groups":["admins"]},{"ID":"alice","Username":"alice"}]`)
			u, err := New(Config{FilePath: path, UserAdminGroup: "admins"})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := u.SetPassword("alice", "original"); err != nil {
				t.Fatalf("SetPassword: %v", err)
			}
			u.afterVerify = func() {
				if err := tt.compete(u); err != nil {
					t.Errorf("competing change: %v", err)
				}
			}

			_, err = u.ChangePassword("alice", "original", "requester1")
			if err == nil || err.Error() != "invalid old password" {
				t.Errorf("ChangePassword = %v, want invalid old password", err)
			}
			if _, ok := u.Authenticate("alice", "adminset1"); !ok {
				t.Error("the competing password no longer verifies")
			}
			if _, ok := u.Authenticate("alice", "requester1"); ok {
				t.Error("the stale change was written")
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"empty", "", true},
		{"too short", "short", true},
		{"whitespace only", "        ", true},
		{"padded but too few real chars", "  abc   ", true},
		{"exactly minimum", "12345678", false},
		{"comfortably long", "a-good-long-password", false},
		{"internal spaces allowed", "pass word ok", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePassword(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrWeakPassword) {
				t.Errorf("validatePassword(%q) error should wrap ErrWeakPassword, got %v", tt.password, err)
			}
		})
	}
}

func TestSetPasswordByReset(t *testing.T) {
	const users = `[
		{"ID":"admin1","Username":"admin","Groups":["admins"]},
		{"ID":"user1","Username":"user","Groups":["user"]},
		{"ID":"bob","Username":"bob","Password":"bob-hash"}
	]`
	newHash, err := HashNewPassword("bob", "linkpass1")
	if err != nil {
		t.Fatalf("HashNewPassword: %v", err)
	}
	tests := []struct {
		name         string
		target       string
		issuer       string
		expectedHash string
		static       bool
		wantErr      error
	}{
		{"current admin, unchanged hash", "bob", "admin1", "bob-hash", false, nil},
		{"issuer not an admin", "bob", "user1", "bob-hash", false, ErrResetRefused},
		{"issuer gone", "bob", "nobody", "bob-hash", false, ErrResetRefused},
		{"target's hash changed", "bob", "admin1", "older-hash", false, ErrResetRefused},
		{"target gone", "carol", "admin1", "bob-hash", false, ErrResetRefused},
		{"static database", "bob", "admin1", "bob-hash", true, ErrReadOnly},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := New(Config{FilePath: writeUsersFile(t, users), UserAdminGroup: "admins", Static: tt.static})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			err = u.SetPasswordByReset(tt.target, tt.issuer, tt.expectedHash, newHash)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("SetPasswordByReset = %v, want %v", err, tt.wantErr)
			}
			_, set := u.Authenticate("bob", "linkpass1")
			if set != (tt.wantErr == nil) {
				t.Errorf("link password authenticates = %v, want %v", set, tt.wantErr == nil)
			}
		})
	}
}

func TestHashNewPasswordRefusesWeak(t *testing.T) {
	if _, err := HashNewPassword("bob", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("HashNewPassword(short) = %v, want ErrWeakPassword", err)
	}
}
