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
	"sync"
	"testing"
)

// TestConcurrentAccess exercises readers and writers together so go test -race
// catches unsynchronized access to the users slice.
func TestConcurrentAccess(t *testing.T) {
	path := writeUsersFile(t, `[{"ID":"alice","Username":"alice"}]`)
	u, err := New(Config{FilePath: path, PasswordChangeable: true, UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Give alice a known password and admin rights.
	u.users[0].Password = hash([]byte("alice"), "start")
	u.users[0].Groups = []string{"admins"}

	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers * 4)

	for i := 0; i < workers; i++ {
		go func() { defer wg.Done(); _, _ = u.Get("alice") }()
		go func() { defer wg.Done(); _, _ = u.Authenticate("alice", "start") }()
		go func() { defer wg.Done(); _ = u.AdminUpdateUserGroups("alice", "alice", []string{"admins", "user"}) }()
		go func() { defer wg.Done(); _ = u.AdminResetPassword("alice", "alice", "next") }()
	}
	wg.Wait()
}
