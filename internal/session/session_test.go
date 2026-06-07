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

package session

import (
	"sync"
	"testing"
)

func TestCreateGetDelete(t *testing.T) {
	s := New()

	id := s.Create("user-1")
	if id == "" {
		t.Fatal("Create returned empty session id")
	}

	userID, err := s.Get(id)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if userID != "user-1" {
		t.Errorf("Get = %q, want %q", userID, "user-1")
	}

	s.Delete(id)
	if _, err := s.Get(id); err == nil {
		t.Error("Get after Delete should return error")
	}
}

func TestDeleteUserSessions(t *testing.T) {
	s := New()

	a1 := s.Create("alice")
	a2 := s.Create("alice")
	b1 := s.Create("bob")

	s.DeleteUserSessions("alice")

	if _, err := s.Get(a1); err == nil {
		t.Error("alice session a1 should be gone")
	}
	if _, err := s.Get(a2); err == nil {
		t.Error("alice session a2 should be gone")
	}
	if _, err := s.Get(b1); err != nil {
		t.Error("bob session should be unaffected")
	}
}

// TestConcurrentAccess hammers the store from many goroutines so the race
// detector (go test -race) catches unsynchronized map access, which in Go
// panics with "concurrent map read and map write" at runtime.
func TestConcurrentAccess(_ *testing.T) {
	s := New()

	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				id := s.Create("user")
				_, _ = s.Get(id)
				s.DeleteUserSessions("user")
				s.Delete(id)
			}
		}()
	}
	wg.Wait()
}
