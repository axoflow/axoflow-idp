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
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		{ID: "admin-id", Username: "admin", Password: bcryptHash(t, "first-password")},
		{ID: "admin-id-2", Username: "admin", Password: bcryptHash(t, "second-password")},
	}})
	if err == nil {
		t.Error("New should reject duplicate seed users")
	}
}

func startSeeded(t *testing.T, path, adminHash string) *User {
	t.Helper()
	u, err := New(Config{FilePath: path, CreateIfMissing: true, UpdateSeedPasswords: true, UserAdminGroup: "admin", Defaults: []UserInfo{
		{ID: "admin-id", Username: "admin", Password: adminHash, Groups: []string{"admin"}},
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

// A seed entry's password follows the account it created: once that account
// is deleted, the same username registered again belongs to someone else,
// and the next start leaves its password alone.
func TestSeedPasswordFollowsTheAccountNotTheName(t *testing.T) {
	tests := []struct {
		name     string
		recreate func(u *User, adminID string) error
	}{
		{"re-created through self-registration", func(u *User, _ string) error {
			_, _, err := u.SelfRegister("ops", "newowner1", []string{RoleUser}, "new@example.com")
			return err
		}},
		{"re-created by an admin", func(u *User, adminID string) error {
			return u.AdminRegister(adminID, "ops", "newowner1", []string{RoleUser}, "new@example.com")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			cfg := Config{FilePath: path, CreateIfMissing: true, UpdateSeedPasswords: true, SelfRegistration: true, UserAdminGroup: "admin", Defaults: []UserInfo{
				{ID: "seed-admin", Username: "admin", Password: bcryptHash(t, "adminpass"), Groups: []string{"admin"}},
				{ID: "seed-ops", Username: "ops", Password: bcryptHash(t, "seedpass1")},
			}}
			u, err := New(cfg)
			if err != nil {
				t.Fatalf("seed: %v", err)
			}
			if err := u.AdminDelete("seed-admin", "seed-ops"); err != nil {
				t.Fatalf("delete: %v", err)
			}
			if err := tc.recreate(u, "seed-admin"); err != nil {
				t.Fatalf("re-create: %v", err)
			}
			warnings := captureSeedWarnings(t)

			restarted, err := New(cfg)
			if err != nil {
				t.Fatalf("restart: %v", err)
			}

			if _, ok := restarted.Authenticate("ops", "seedpass1"); ok {
				t.Error("the seed password was put on the account that reuses the username")
			}
			if _, ok := restarted.Authenticate("ops", "newowner1"); !ok {
				t.Error("the new owner's password no longer works")
			}
			got := warnings()
			if len(got) != 1 || !strings.Contains(got[0], `"msg":"seed entry does not match its account"`) ||
				!strings.Contains(got[0], `"username":"ops"`) || !strings.Contains(got[0], `"seed_id":"seed-ops"`) || strings.Contains(got[0], "$2") {
				t.Errorf("warnings = %q, want one naming ops and seed-ops, without a hash", got)
			}
		})
	}
}

// With updateSeedPasswords every seed entry names its account by ID; without
// the option an ID-less entry still seeds a new database with a generated one.
func TestSeedPasswordsRequireAnID(t *testing.T) {
	for _, update := range []bool{true, false} {
		t.Run(fmt.Sprintf("updateSeedPasswords=%v", update), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			_, err := New(Config{FilePath: path, CreateIfMissing: true, UpdateSeedPasswords: update, Defaults: []UserInfo{
				{Username: "admin", Password: bcryptHash(t, "adminpass")},
			}})
			if update && err == nil {
				t.Error("New accepted a seed entry without an ID")
			}
			if !update && err != nil {
				t.Errorf("New refused a seed entry without an ID: %v", err)
			}
		})
	}
}

func captureSeedWarnings(t *testing.T) func() []string {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return func() []string {
		return strings.FieldsFunc(buf.String(), func(r rune) bool { return r == '\n' })
	}
}
