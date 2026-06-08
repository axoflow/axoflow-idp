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
	"os"
	"sync"
	"testing"
)

// TestConcurrentAccess exercises readers and writers together so go test -race
// catches unsynchronized access to the users slice.
func TestConcurrentAccess(t *testing.T) {
	path := writeUsersFile(t, `[{"ID":"alice","Username":"alice"}]`)
	u, err := New(Config{FilePath: path, UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Give alice a known password and admin rights.
	u.users[0].Password = hash([]byte("alice"), "start")
	u.users[0].Groups = []string{"admins"}

	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers * 5)

	for i := 0; i < workers; i++ {
		go func() { defer wg.Done(); _, _ = u.Get("alice") }()
		go func() { defer wg.Done(); _, _ = u.Authenticate("alice", "start") }()
		go func() { defer wg.Done(); _ = u.AdminUpdateUserGroups("alice", "alice", []string{"admins", "user"}) }()
		go func() { defer wg.Done(); _ = u.AdminResetPassword("alice", "alice", "nextpass1") }()
		go func() { defer wg.Done(); _ = u.SetPassword("alice", "concurrentpw") }()
	}
	wg.Wait()
}

// TestConcurrentSaveUsers ensures that many concurrent SaveUsers calls never
// corrupt the file: the temp file must not be shared between racing writers.
// Without serialization, concurrent writers interleave bytes in the shared
// temp file and one rename can move a partially written file into place.
func TestConcurrentSaveUsers(t *testing.T) {
	path := writeUsersFile(t, `[{"ID":"alice","Username":"alice"},{"ID":"bob","Username":"bob"}]`)
	u, err := New(Config{FilePath: path})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const workers = 30
	var wg sync.WaitGroup
	wg.Add(workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = u.SaveUsers()
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("SaveUsers #%d returned error: %v", i, err)
		}
	}

	// The persisted file must be valid, complete JSON every time.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read users file: %v", err)
	}
	var got []UserInfo
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("users file is corrupt after concurrent saves: %v\ncontent: %s", err, data)
	}
	if len(got) != 2 {
		t.Errorf("got %d users, want 2", len(got))
	}
}
