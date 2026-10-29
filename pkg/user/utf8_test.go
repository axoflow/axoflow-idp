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

// encoding/json replaces each invalid UTF-8 byte with U+FFFD, so two names
// that differ only there are stored as one; the next start would then refuse
// the database as holding a duplicate username.
func TestRegister_InvalidUTF8RoundTrips(t *testing.T) {
	long := strings.Repeat("a", 1<<20)
	tests := []struct {
		name          string
		first, second string
	}{
		{name: "0xFF vs 0xFE", first: "p\xff", second: "p\xfe"},
		{name: "0xFF vs literal U+FFFD", first: "p�", second: "p\xff"},
		{name: "encoded surrogate vs 0xFF", first: "p\xed\xa0\x80", second: "p\xff"},
		{name: "overlong vs two invalid bytes", first: "p\xc0\xaf", second: "p\xff\xfe"},
		{name: "1 MiB name, differing invalid tail byte", first: long + "\xff", second: long + "\xfe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeUsersFile(t, `[]`)
			u, err := New(Config{FilePath: path, SelfRegistration: true})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			_, _, err1 := u.SelfRegister(tt.first, "password123", []string{RoleUser}, "one@example.com")
			_, _, err2 := u.SelfRegister(tt.second, "password123", []string{RoleUser}, "two@example.com")
			if err1 == nil && err2 == nil {
				t.Error("both registrations accepted, want the invalid UTF-8 one refused")
			}
			for _, err := range []error{err1, err2} {
				if err != nil && !strings.Contains(err.Error(), "must be valid UTF-8") {
					t.Errorf("unexpected error: %v", err)
				}
			}

			if err := u.SaveUsers(); err != nil {
				t.Fatalf("SaveUsers: %v", err)
			}
			if _, err := New(Config{FilePath: path}); err != nil {
				t.Fatalf("reload: %v", err)
			}
		})
	}
}

func TestRegister_UTF8(t *testing.T) {
	tests := []struct {
		name     string
		username string
		email    string
		groups   []string
		wantErr  bool
	}{
		{name: "literal U+FFFD in a valid name", username: "p�", email: "p@example.com"},
		{name: "invalid email", username: "carol", email: "c\xff@example.com", wantErr: true},
		{name: "invalid group", username: "carol", email: "c@example.com", groups: []string{"ops\xff"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := New(Config{FilePath: writeUsersFile(t, `[]`)})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			_, err = u.RegisterLocked(tt.username, tt.groups, tt.email)
			if (err != nil) != tt.wantErr {
				t.Fatalf("RegisterLocked error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && u.Count() != 0 {
				t.Errorf("Count = %d after a refused registration, want 0", u.Count())
			}
		})
	}
}

func TestAdminUpdateUserGroups_InvalidUTF8(t *testing.T) {
	path := writeUsersFile(t, `[
		{"ID":"admin1","Username":"alice","Groups":["admins"]},
		{"ID":"bob","Username":"bob","Groups":["user"]}
	]`)
	u, err := New(Config{FilePath: path, UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := u.AdminUpdateUserGroups("admin1", "bob", []string{"ops\xff"}); err == nil {
		t.Fatal("invalid UTF-8 group accepted")
	}
	if bob, _ := u.Get("bob"); len(bob.Groups) != 1 || bob.Groups[0] != "user" {
		t.Errorf("groups changed despite error: %v", bob.Groups)
	}
}
