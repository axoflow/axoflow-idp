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
	if err := u.SetPassword("nobody", "x"); err == nil {
		t.Error("SetPassword should fail for unknown user")
	}
}

func TestChangePassword(t *testing.T) {
	u := newTestUser(t, false)

	if err := u.ChangePassword("alice", "wrong", "newpass12"); err == nil {
		t.Error("ChangePassword with wrong old password should fail")
	}
	if err := u.ChangePassword("alice", "original", "newpass12"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if _, ok := u.Authenticate("alice", "newpass12"); !ok {
		t.Error("changed password should authenticate")
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
