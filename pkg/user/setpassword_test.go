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
	"fmt"
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
		name     string
		password string // the competing change's password
		compete  func(u *User) error
	}{
		{"admin reset", "adminset1", func(u *User) error { return u.AdminResetPassword("admin1", "alice", "adminset1") }},
		{"reset link", "adminset1", func(u *User) error {
			generation, _ := u.CredentialGeneration("alice")
			h, _ := HashNewPassword("alice", "adminset1")
			return u.SetPasswordByReset("alice", "admin1", generation, h)
		}},
		// The hash is deterministic per user, so a reset to the password the
		// change verified leaves the stored hash as it was.
		{"admin reset to the same password", "original", func(u *User) error { return u.AdminResetPassword("admin1", "alice", "original") }},
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
			if _, ok := u.Authenticate("alice", tt.password); !ok {
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
		name   string
		target string
		issuer string
		// stale has a password write for bob commit after the link captured
		// generation 0.
		stale   bool
		static  bool
		wantErr error
	}{
		{"current admin, current generation", "bob", "admin1", false, false, nil},
		{"issuer not an admin", "bob", "user1", false, false, ErrResetRefused},
		{"issuer gone", "bob", "nobody", false, false, ErrResetRefused},
		{"generation moved", "bob", "admin1", true, false, ErrResetRefused},
		{"target gone", "carol", "admin1", false, false, ErrResetRefused},
		{"static database", "bob", "admin1", false, true, ErrReadOnly},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := New(Config{FilePath: writeUsersFile(t, users), UserAdminGroup: "admins", Static: tt.static})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if tt.stale {
				if err := u.SetPassword("bob", "bobs-own1"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
			}
			before, _ := u.CredentialGeneration("bob")

			err = u.SetPasswordByReset(tt.target, tt.issuer, 0, newHash)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("SetPasswordByReset = %v, want %v", err, tt.wantErr)
			}
			_, set := u.Authenticate("bob", "linkpass1")
			if set != (tt.wantErr == nil) {
				t.Errorf("link password authenticates = %v, want %v", set, tt.wantErr == nil)
			}
			after, _ := u.CredentialGeneration("bob")
			if set && after != before+1 || !set && after != before {
				t.Errorf("bob's generation went from %d to %d (password set: %v)", before, after, set)
			}
		})
	}
}

// The credential generation counts every committed password write and the
// deletion, whatever the hash, and nothing else.
func TestCredentialGeneration(t *testing.T) {
	users := fmt.Sprintf(`[
		{"ID":"admin1","Username":"admin","Groups":["admins"]},
		{"ID":"alice","Username":"alice","Password":%q},
		{"ID":"carol","Username":"carol"}
	]`, hash([]byte("alice"), "original"))
	alice := func(write func(u *User) error) func(u *User) (string, error) {
		return func(u *User) (string, error) { return "alice", write(u) }
	}
	tests := []struct {
		name   string
		write  func(u *User) (string, error)
		want   uint64
		exists bool
	}{
		{"untouched", alice(func(*User) error { return nil }), 0, true},
		{"SetPassword", alice(func(u *User) error { return u.SetPassword("alice", "brand-new1") }), 1, true},
		{"ChangePassword", alice(func(u *User) error {
			_, err := u.ChangePassword("alice", "original", "changed12")
			return err
		}), 1, true},
		{"refused ChangePassword", alice(func(u *User) error {
			if _, err := u.ChangePassword("alice", "wrong", "changed12"); err == nil {
				return errors.New("wrong old password accepted")
			}
			return nil
		}), 0, true},
		{"AdminResetPassword", alice(func(u *User) error { return u.AdminResetPassword("admin1", "alice", "adminset1") }), 1, true},
		{"AdminResetPassword to the same password", alice(func(u *User) error {
			return u.AdminResetPassword("admin1", "alice", "original")
		}), 1, true},
		{"two writes", alice(func(u *User) error {
			if err := u.AdminResetPassword("admin1", "alice", "adminset1"); err != nil {
				return err
			}
			return u.SetPassword("alice", "brand-new1")
		}), 2, true},
		{"SetPasswordByReset", alice(func(u *User) error {
			h, _ := HashNewPassword("alice", "linkpass1")
			return u.SetPasswordByReset("alice", "admin1", 0, h)
		}), 1, true},
		{"group update", alice(func(u *User) error { return u.AdminUpdateUserGroups("admin1", "alice", []string{"ops"}) }), 0, true},
		{"deletion", alice(func(u *User) error { return u.AdminDelete("admin1", "alice") }), 1, false},
		{"Register", func(u *User) (string, error) {
			if err := u.Register("dave", "davepass1", nil, ""); err != nil {
				return "", err
			}
			dave, _ := u.Authenticate("dave", "davepass1")
			return dave.ID, nil
		}, 1, true},
		{"SelfRegister", func(u *User) (string, error) {
			id, _, err := u.SelfRegister("dave", "davepass1", nil, "")
			return id, err
		}, 1, true},
		{"AdminRegister", func(u *User) (string, error) {
			if err := u.AdminRegister("admin1", "dave", "davepass1", nil, ""); err != nil {
				return "", err
			}
			dave, _ := u.Authenticate("dave", "davepass1")
			return dave.ID, nil
		}, 1, true},
		{"RegisterLocked", func(u *User) (string, error) { return u.RegisterLocked("dave", nil, "") }, 1, true},
		{"AdminRegisterLocked", func(u *User) (string, error) {
			return u.AdminRegisterLocked("admin1", "dave", nil, "")
		}, 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := New(Config{FilePath: writeUsersFile(t, users), UserAdminGroup: "admins", SelfRegistration: true})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			for _, id := range []string{"admin1", "alice", "carol"} {
				if g, ok := u.CredentialGeneration(id); g != 0 || !ok {
					t.Fatalf("%s's generation at load = (%d, %v), want (0, true)", id, g, ok)
				}
			}

			id, err := tt.write(u)
			if err != nil {
				t.Fatalf("write: %v", err)
			}
			if g, ok := u.CredentialGeneration(id); g != tt.want || ok != tt.exists {
				t.Errorf("%s's generation = (%d, %v), want (%d, %v)", id, g, ok, tt.want, tt.exists)
			}
			if g, _ := u.CredentialGeneration("carol"); g != 0 {
				t.Errorf("carol's generation = %d, want 0", g)
			}
		})
	}
}

// Applying the seed passwords at start is a password write too.
func TestCredentialGeneration_SeedPassword(t *testing.T) {
	path := writeUsersFile(t, `[{"ID":"alice","Username":"alice","Password":"old-hash"},{"ID":"carol","Username":"carol","Password":"carol-hash"}]`)
	u, err := New(Config{
		FilePath: path, CreateIfMissing: true, UpdateSeedPasswords: true,
		Defaults: []UserInfo{{ID: "alice", Username: "alice", Password: "new-hash"}, {ID: "carol", Username: "carol", Password: "carol-hash"}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// carol's hash already matched, so nothing was written for her.
	for id, want := range map[string]uint64{"alice": 1, "carol": 0} {
		if g, _ := u.CredentialGeneration(id); g != want {
			t.Errorf("%s's generation = %d, want %d", id, g, want)
		}
	}
}

func TestHashNewPasswordRefusesWeak(t *testing.T) {
	if _, err := HashNewPassword("bob", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("HashNewPassword(short) = %v, want ErrWeakPassword", err)
	}
}
