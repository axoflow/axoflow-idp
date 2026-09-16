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
	"slices"
	"sync"
	"sync/atomic"
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

func TestSelfRegister_Policy(t *testing.T) {
	tests := []struct {
		name             string
		usersFile        string
		selfRegistration bool
		allowBootstrap   bool
		wantErr          error
		wantAdmin        bool
	}{
		{
			name:      "closed by default",
			usersFile: `[]`,
			wantErr:   ErrRegistrationClosed,
		},
		{
			name:           "allowBootstrap opens an empty database",
			usersFile:      `[]`,
			allowBootstrap: true,
			wantAdmin:      true,
		},
		{
			name:           "allowBootstrap does not open a non-empty database",
			usersFile:      `[{"ID":"alice","Username":"alice","Groups":["user"]}]`,
			allowBootstrap: true,
			wantErr:        ErrRegistrationClosed,
		},
		{
			name:             "selfRegistration keeps a non-empty database open",
			usersFile:        `[{"ID":"alice","Username":"alice","Groups":["user"]}]`,
			selfRegistration: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := New(Config{
				FilePath:         writeUsersFile(t, tt.usersFile),
				UserAdminGroup:   "admins",
				SelfRegistration: tt.selfRegistration,
				AllowBootstrap:   tt.allowBootstrap,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			id, err := u.SelfRegister("carol", "carolpass1", []string{RoleUser}, "carol@example.com")
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("SelfRegister error = %v, want %v", err, tt.wantErr)
			}
			if err == nil && id == "" {
				t.Error("SelfRegister returned an empty id")
			}
			if tt.wantErr != nil {
				return
			}
			carol := find(t, u, "carol")
			if u.IsAdmin(&carol) != tt.wantAdmin {
				t.Errorf("IsAdmin = %v, want %v (groups %v)", u.IsAdmin(&carol), tt.wantAdmin, carol.Groups)
			}
		})
	}
}

// With AllowBootstrap alone, a concurrent burst against an empty database must
// produce exactly one user: the policy check shares the lock with the append.
func TestSelfRegister_ConcurrentBootstrapWindowAdmitsOne(t *testing.T) {
	u, err := New(Config{
		FilePath:       writeUsersFile(t, `[]`),
		UserAdminGroup: "admins",
		AllowBootstrap: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	var succeeded, closed atomic.Int32
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			username := string(rune('a'+i)) + "user"
			switch _, err := u.SelfRegister(username, "password1", []string{RoleUser}, ""); {
			case err == nil:
				succeeded.Add(1)
			case errors.Is(err, ErrRegistrationClosed):
				closed.Add(1)
			default:
				t.Errorf("SelfRegister %s: %v", username, err)
			}
		}(i)
	}
	wg.Wait()

	if succeeded.Load() != 1 || closed.Load() != n-1 {
		t.Errorf("succeeded = %d, closed = %d; want 1 and %d", succeeded.Load(), closed.Load(), n-1)
	}
	if got := u.Count(); got != 1 {
		t.Errorf("Count = %d, want 1", got)
	}
}

// Admin-driven registration is not subject to the self-registration policy.
func TestRegister_AdminPathsBypassPolicy(t *testing.T) {
	u, err := New(Config{
		FilePath:       writeUsersFile(t, `[{"ID":"admin1","Username":"admin","Groups":["admins"]}]`),
		UserAdminGroup: "admins",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := u.AdminRegister("admin1", "dave", "davepass1", []string{RoleUser}, ""); err != nil {
		t.Errorf("AdminRegister: %v", err)
	}
	if _, err := u.AdminRegisterLocked("admin1", "erin", []string{RoleUser}, ""); err != nil {
		t.Errorf("AdminRegisterLocked: %v", err)
	}
}
