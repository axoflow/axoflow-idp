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
	"encoding/json"
	"testing"
)

func TestRegister_NewAccountIdentity(t *testing.T) {
	const existing = `[
		{"ID":"alice","Username":"alice","Email":"alice@example.com"},
		{"ID":"carol","Username":" carol ","Email":" carol@example.com "},
		{"ID":"dave","Username":"dave"}
	]`

	tests := []struct {
		name               string
		username, email    string
		wantErr            string
		wantUser, wantMail string
	}{
		{name: "case variant of a username", username: "Alice", email: "a2@example.com", wantErr: "username already exists"},
		{name: "whitespace variant of a username", username: " alice\t", email: "a2@example.com", wantErr: "username already exists"},
		{name: "case variant of an email", username: "bob", email: "ALICE@Example.com", wantErr: "email already registered"},
		{name: "trimmed variant of a legacy username", username: "Carol", email: "c2@example.com", wantErr: "username already exists"},
		{name: "trimmed variant of a legacy email", username: "bob", email: "carol@example.com", wantErr: "email already registered"},
		{name: "empty username", username: "", email: "bob@example.com", wantErr: "username is required"},
		{name: "blank username", username: "  ", email: "bob@example.com", wantErr: "username is required"},
		{name: "blank email", username: "bob", email: "  ", wantErr: "email must not be blank"},
		{name: "control character in username", username: "bo\x00b", email: "bob@example.com", wantErr: "username and email must not contain control characters"},
		{name: "control character in email", username: "bob", email: "bob\n@example.com", wantErr: "username and email must not contain control characters"},
		{name: "surrounding whitespace is dropped", username: " bob ", email: " bob@example.com\n", wantUser: "bob", wantMail: "bob@example.com"},
		{name: "empty email never collides", username: "bob", email: "", wantUser: "bob"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := New(Config{FilePath: writeUsersFile(t, existing)})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			id, err := u.RegisterLocked(tt.username, nil, tt.email)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("RegisterLocked error = %v, want %q", err, tt.wantErr)
				}
				if u.Count() != 3 {
					t.Errorf("Count = %d after a refused registration, want 3", u.Count())
				}
				return
			}
			if err != nil {
				t.Fatalf("RegisterLocked: %v", err)
			}
			got, _ := u.Get(id)
			if got.Username != tt.wantUser || got.Email != tt.wantMail {
				t.Errorf("stored %q / %q, want %q / %q", got.Username, got.Email, tt.wantUser, tt.wantMail)
			}
		})
	}
}

// The policy covers new accounts only: a database written before it may hold
// names that differ only in case, and each must still load and log in.
func TestLegacyCaseVariantsLoadAndLogIn(t *testing.T) {
	users, err := json.Marshal([]UserInfo{
		{ID: "lower", Username: "alice", Password: hash([]byte("lower"), "lowerpass1")},
		{ID: "upper", Username: "Alice", Password: hash([]byte("upper"), "upperpass1")},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	u, err := New(Config{FilePath: writeUsersFile(t, string(users))})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tests := []struct {
		username, password string
		wantID             string
	}{
		{username: "alice", password: "lowerpass1", wantID: "lower"},
		{username: "Alice", password: "upperpass1", wantID: "upper"},
		{username: "ALICE", password: "lowerpass1"},
		{username: "alice", password: "upperpass1"},
	}
	for _, tt := range tests {
		got, ok := u.Authenticate(tt.username, tt.password)
		if ok != (tt.wantID != "") || (ok && got.ID != tt.wantID) {
			t.Errorf("Authenticate(%q, %q) = %q, %v; want %q", tt.username, tt.password, got.ID, ok, tt.wantID)
		}
	}
}
