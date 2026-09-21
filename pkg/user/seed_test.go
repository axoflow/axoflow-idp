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

	v2 := append(slices.Clone(v1), UserInfo{Username: "viewer", Password: bcryptHash(t, "viewerpass")})
	upgraded, err := New(Config{FilePath: path, CreateIfMissing: true, UserAdminGroup: "admin", Defaults: v2})
	if err != nil {
		t.Fatalf("upgrade: %v", err)
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
