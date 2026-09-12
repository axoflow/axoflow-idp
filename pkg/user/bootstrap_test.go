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
	"slices"
	"sync"
	"testing"
)

// find returns the stored record of the user with the given username.
func find(t *testing.T, u *User, username string) UserInfo {
	t.Helper()
	u.mu.RLock()
	defer u.mu.RUnlock()
	for _, info := range u.users {
		if info.Username == username {
			return info
		}
	}
	t.Fatalf("user %q not found", username)
	return UserInfo{}
}

func TestRegister_FirstUserBecomesAdmin(t *testing.T) {
	tests := []struct {
		name       string
		usersFile  string
		adminGroup string
		groups     []string
		wantAdmin  bool
	}{
		{
			name:       "first user in an empty database",
			usersFile:  `[]`,
			adminGroup: "admins",
			groups:     []string{RoleUser},
			wantAdmin:  true,
		},
		{
			name:       "database already has a user",
			usersFile:  `[{"ID":"alice","Username":"alice","Groups":["user"]}]`,
			adminGroup: "admins",
			groups:     []string{RoleUser},
			wantAdmin:  false,
		},
		{
			name:       "no admin group configured",
			usersFile:  `[]`,
			adminGroup: "",
			groups:     []string{RoleUser},
			wantAdmin:  false,
		},
		{
			name:       "admin group already requested is not duplicated",
			usersFile:  `[]`,
			adminGroup: "admins",
			groups:     []string{RoleUser, "admins"},
			wantAdmin:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := New(Config{FilePath: writeUsersFile(t, tt.usersFile), UserAdminGroup: tt.adminGroup})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			if err := u.Register("carol", "carolpass1", tt.groups, "carol@example.com"); err != nil {
				t.Fatalf("Register: %v", err)
			}

			carol := find(t, u, "carol")
			if got := u.IsAdmin(&carol); got != tt.wantAdmin {
				t.Errorf("IsAdmin = %v, want %v (groups %v)", got, tt.wantAdmin, carol.Groups)
			}
			if tt.adminGroup != "" {
				n := 0
				for _, g := range carol.Groups {
					if g == tt.adminGroup {
						n++
					}
				}
				if n > 1 {
					t.Errorf("admin group appears %d times in %v, want at most once", n, carol.Groups)
				}
			}
		})
	}
}

// A memory-only database (no FilePath) starts empty on every boot, so the
// bootstrap admin grant must not arm there: it would repeat on each restart.
func TestRegister_MemoryOnlyDatabaseDoesNotBootstrapAdmin(t *testing.T) {
	u, err := New(Config{UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := u.Register("carol", "carolpass1", []string{RoleUser}, ""); err != nil {
		t.Fatalf("Register: %v", err)
	}

	carol := find(t, u, "carol")
	if u.IsAdmin(&carol) {
		t.Errorf("memory-only database must not grant admin, got groups %v", carol.Groups)
	}
}

func TestRegister_DoesNotMutateCallersGroups(t *testing.T) {
	u, err := New(Config{FilePath: writeUsersFile(t, `[]`), UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	groups := []string{RoleUser}
	if err := u.Register("carol", "carolpass1", groups, ""); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !slices.Equal(groups, []string{RoleUser}) {
		t.Errorf("caller's slice = %v, want it unchanged", groups)
	}
}

func TestRegister_SecondUserIsNotAdmin(t *testing.T) {
	u, err := New(Config{FilePath: writeUsersFile(t, `[]`), UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := u.Register("first", "firstpass1", []string{RoleUser}, "first@example.com"); err != nil {
		t.Fatalf("Register first: %v", err)
	}
	if err := u.Register("second", "secondpass1", []string{RoleUser}, "second@example.com"); err != nil {
		t.Fatalf("Register second: %v", err)
	}

	if g := find(t, u, "first").Groups; !slices.Contains(g, "admins") {
		t.Errorf("first user groups = %v, want it to contain admins", g)
	}
	if g := find(t, u, "second").Groups; slices.Contains(g, "admins") {
		t.Errorf("second user groups = %v, want no admins", g)
	}
}

// Concurrent registrations against an empty database must produce exactly one
// admin: the bootstrap check runs under the same lock as the append.
func TestRegister_ConcurrentBootstrapCreatesOneAdmin(t *testing.T) {
	u, err := New(Config{FilePath: writeUsersFile(t, `[]`), UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			username := string(rune('a'+i)) + "user"
			if err := u.Register(username, "password1", []string{RoleUser}, username+"@example.com"); err != nil {
				t.Errorf("Register %s: %v", username, err)
			}
		}(i)
	}
	wg.Wait()

	u.mu.RLock()
	defer u.mu.RUnlock()
	admins := 0
	for _, info := range u.users {
		if slices.Contains(info.Groups, "admins") {
			admins++
		}
	}
	if admins != 1 {
		t.Errorf("admins = %d, want exactly 1", admins)
	}
}

func TestCount(t *testing.T) {
	u, err := New(Config{FilePath: writeUsersFile(t, `[]`)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := u.Count(); got != 0 {
		t.Errorf("Count = %d, want 0", got)
	}
	if err := u.Register("carol", "carolpass1", []string{RoleUser}, ""); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if got := u.Count(); got != 1 {
		t.Errorf("Count = %d, want 1", got)
	}
}
