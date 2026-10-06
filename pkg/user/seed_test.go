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
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func bcryptHash(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	return string(h)
}

func TestSeedIsNotReappliedOnUpgrade(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	v1 := []UserInfo{{Username: "admin", Password: bcryptHash(t, "adminpass"), Groups: []string{"admin"}}}
	u, err := New(Config{FilePath: path, CreateIfMissing: true, UserAdminGroup: "admin", Defaults: v1})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	admin, _ := u.Authenticate("admin", "adminpass")

	if err := u.Register("alice", "alicepass", []string{"contentViewer"}, "alice@example.com"); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := u.AdminUpdateUserGroups(admin.ID, admin.ID, []string{"admin", "logSearcher"}); err != nil {
		t.Fatalf("update groups: %v", err)
	}
	if err := u.SaveUsers(); err != nil {
		t.Fatalf("save: %v", err)
	}

	v2 := []UserInfo{
		{Username: "admin", Password: bcryptHash(t, "changedpass"), Groups: []string{"admin"}},
		{Username: "viewer", Password: bcryptHash(t, "viewerpass")},
	}
	upgraded, err := New(Config{FilePath: path, CreateIfMissing: true, UserAdminGroup: "admin", Defaults: v2})
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}

	if _, ok := upgraded.Authenticate("admin", "adminpass"); !ok {
		t.Error("admin password reverted to seed without updateSeedPasswords")
	}
	if _, ok := upgraded.Authenticate("alice", "alicepass"); !ok {
		t.Error("operator-added user lost on upgrade")
	}
	if got, _ := upgraded.Get(admin.ID); !slices.Contains(got.Groups, "logSearcher") {
		t.Errorf("admin groups reverted to seed: %v", got.Groups)
	}
	if _, ok := upgraded.Authenticate("viewer", "viewerpass"); ok {
		t.Error("new seed user appeared in existing database")
	}
}

func TestSeedPasswordFollowsTheConfiguredHash(t *testing.T) {
	first, second := bcryptHash(t, "first-password"), bcryptHash(t, "second-password")
	seeded := func(t *testing.T, path string) { startSeeded(t, path, first) }
	changedSince := func(t *testing.T, path string) {
		changePassword(t, startSeeded(t, path, first), "first-password", "changed-password")
	}

	tests := map[string]struct {
		before  func(t *testing.T, path string)
		restart string
		want    string
		notWant string
	}{
		"a changed configured hash replaces the password":                    {before: seeded, restart: second, want: "second-password", notWant: "first-password"},
		"a password changed in the IdP reverts to the configured hash":       {before: changedSince, restart: first, want: "first-password", notWant: "changed-password"},
		"an empty configured hash would lock the account and is not applied": {before: seeded, restart: "", want: "first-password"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			tc.before(t, path)

			startSeeded(t, path, tc.restart)
			u := startSeeded(t, path, tc.restart) // the second start reads what the first one saved

			if _, ok := u.Authenticate("admin", tc.want); !ok {
				t.Errorf("admin does not log in with %q", tc.want)
			}
			if _, ok := u.Authenticate("admin", tc.notWant); tc.notWant != "" && ok {
				t.Errorf("admin still logs in with %q", tc.notWant)
			}
		})
	}
}

func TestSeedPasswordsRefuseDuplicateSeedsInAnExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	startSeeded(t, path, bcryptHash(t, "first-password"))

	_, err := New(Config{FilePath: path, CreateIfMissing: true, UpdateSeedPasswords: true, Defaults: []UserInfo{
		{Username: "admin", Password: bcryptHash(t, "first-password")},
		{Username: "admin", Password: bcryptHash(t, "second-password")},
	}})
	if err == nil {
		t.Error("New should reject duplicate seed users")
	}
}

func startSeeded(t *testing.T, path, adminHash string) *User {
	t.Helper()
	u, err := New(Config{FilePath: path, CreateIfMissing: true, UpdateSeedPasswords: true, UserAdminGroup: "admin", Defaults: []UserInfo{
		{Username: "admin", Password: adminHash, Groups: []string{"admin"}},
	}})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return u
}

func changePassword(t *testing.T, u *User, from, to string) {
	t.Helper()
	admin, _ := u.Authenticate("admin", from)
	if err := u.SetPassword(admin.ID, to); err != nil {
		t.Fatalf("set password: %v", err)
	}
	if err := u.SaveUsers(); err != nil {
		t.Fatalf("save: %v", err)
	}
}

func TestSeedRejectsInvalidDefaultsWithoutWritingThem(t *testing.T) {
	tests := map[string][]UserInfo{
		"duplicate username": {{Username: "admin"}, {Username: "admin"}},
		"duplicate id":       {{ID: "same", Username: "a"}, {ID: "same", Username: "b"}},
	}

	for name, defaults := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			if _, err := New(Config{FilePath: path, CreateIfMissing: true, Defaults: defaults}); err == nil {
				t.Fatal("New should reject an invalid seed")
			}
			if _, err := os.Stat(path); err == nil {
				t.Error("invalid seed must not be persisted")
			}
		})
	}
}
