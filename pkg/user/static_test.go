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
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// newStaticStore seeds a users file with a writable store, then reopens it as
// static (read-only).
func newStaticStore(t *testing.T) *User {
	t.Helper()
	path := writeUsersFile(t, `[
		{"ID":"admin1","Username":"admin","Groups":["admins"]},
		{"ID":"bob","Username":"bob","Groups":["user"]}
	]`)
	seed, err := New(Config{FilePath: path, UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := seed.SetPassword("bob", "bobpass1"); err != nil {
		t.Fatalf("seed password: %v", err)
	}
	if err := seed.SaveUsers(); err != nil {
		t.Fatalf("save: %v", err)
	}

	u, err := New(Config{FilePath: path, Static: true, UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("static New: %v", err)
	}
	return u
}

func TestStaticRejectsAllMutations(t *testing.T) {
	u := newStaticStore(t)

	checks := map[string]error{
		"Register":              u.Register("carol", "pw", nil, "carol@x"),
		"ChangePassword":        u.ChangePassword("bob", "bobpass", "new"),
		"SetPassword":           u.SetPassword("bob", "new"),
		"AdminResetPassword":    u.AdminResetPassword("admin1", "bob", "new"),
		"AdminUpdateUserGroups": u.AdminUpdateUserGroups("admin1", "bob", []string{"x"}),
		"AdminDelete":           u.AdminDelete("admin1", "bob"),
		"SaveUsers":             u.SaveUsers(),
	}
	for _, name := range []string{"RegisterLocked", "AdminRegisterLocked"} {
		var err error
		switch name {
		case "RegisterLocked":
			_, err = u.RegisterLocked("dave", nil, "")
		case "AdminRegisterLocked":
			_, err = u.AdminRegisterLocked("admin1", "dave", nil, "")
		}
		checks[name] = err
	}

	for name, err := range checks {
		if !errors.Is(err, ErrReadOnly) {
			t.Errorf("%s in static mode = %v, want ErrReadOnly", name, err)
		}
	}

	// And the data is genuinely unchanged.
	if _, ok := u.Authenticate("bob", "bobpass1"); !ok {
		t.Error("bob's password must be intact in static mode")
	}
}

func TestStaticReadsWork(t *testing.T) {
	u := newStaticStore(t)

	if _, ok := u.Get("bob"); !ok {
		t.Error("Get should work in static mode")
	}
	if _, ok := u.Authenticate("bob", "bobpass1"); !ok {
		t.Error("Authenticate should work in static mode")
	}
	if _, err := u.AdminList("admin1"); err != nil {
		t.Errorf("AdminList should work in static mode: %v", err)
	}
}

func TestStaticDoesNotCreateMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	_, err := New(Config{FilePath: path, Static: true, CreateIfMissing: true})
	if err == nil {
		t.Fatal("static New should fail when the file is missing")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("static mode must not create the users file")
	}
}

func TestConfigIgnoresLegacyPasswordChangeable(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"static":true,"passwordChangeable":true,"userAdminGroup":"admin"}`), &c); err != nil {
		t.Fatalf("legacy config should still parse: %v", err)
	}
	if !c.Static {
		t.Error("static should be parsed")
	}
	if c.UserAdminGroup != "admin" {
		t.Error("userAdminGroup should be parsed")
	}
}
