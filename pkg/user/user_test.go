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
	"strings"
	"testing"
)

func writeUsersFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write users file: %v", err)
	}
	return path
}

func TestLoadUsersFromFile_Valid(t *testing.T) {
	path := writeUsersFile(t, `[
		{"ID":"alice","Username":"alice"},
		{"ID":"bob","Username":"bob"}
	]`)

	_, err := New(Config{FilePath: path})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestLoadUsersFromFile_MissingID(t *testing.T) {
	path := writeUsersFile(t, `[
		{"ID":"alice","Username":"alice"},
		{"ID":"","Username":"bob"}
	]`)

	_, err := New(Config{FilePath: path})
	if err == nil {
		t.Fatal("expected error for missing id, got nil")
	}
	if !strings.Contains(err.Error(), `user "bob" has no id`) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadUsersFromFile_DuplicateID(t *testing.T) {
	path := writeUsersFile(t, `[
		{"ID":"alice","Username":"alice"},
		{"ID":"alice","Username":"alice2"}
	]`)

	_, err := New(Config{FilePath: path})
	if err == nil {
		t.Fatal("expected error for duplicate id, got nil")
	}
	if !strings.Contains(err.Error(), `duplicate user id "alice"`) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadUsersFromFile_DuplicateUsername(t *testing.T) {
	path := writeUsersFile(t, `[
		{"ID":"id1","Username":"alice"},
		{"ID":"id2","Username":"alice"}
	]`)

	_, err := New(Config{FilePath: path})
	if err == nil {
		t.Fatal("expected error for duplicate username, got nil")
	}
	if !strings.Contains(err.Error(), `duplicate username "alice"`) {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestLoadUsersFromFile_MultipleErrorsJoined(t *testing.T) {
	path := writeUsersFile(t, `[
		{"ID":"alice","Username":"alice"},
		{"ID":"","Username":"bob"},
		{"ID":"alice","Username":"carol"},
		{"ID":"id4","Username":"alice"},
		{"ID":"","Username":"dave"}
	]`)

	_, err := New(Config{FilePath: path})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	msg := err.Error()
	for _, want := range []string{
		`user "bob" has no id`,
		`user "dave" has no id`,
		`duplicate user id "alice"`,
		`duplicate username "alice"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("expected error to contain %q, got: %v", want, msg)
		}
	}
}
