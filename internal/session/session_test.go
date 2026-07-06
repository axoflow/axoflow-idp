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
	"time"
)

func TestCreateGetDelete(t *testing.T) {
	s := New(Config{})

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
	s := New(Config{})

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

func TestAbsoluteExpiry(t *testing.T) {
	now := time.Unix(0, 0)
	s := New(Config{AbsoluteTTL: time.Hour})
	s.now = func() time.Time { return now }

	id := s.Create("user-1")

	now = now.Add(59 * time.Minute)
	if _, err := s.Get(id); err != nil {
		t.Fatalf("session should still be valid before absolute TTL: %v", err)
	}

	now = now.Add(2 * time.Minute)
	if _, err := s.Get(id); err == nil {
		t.Error("session should be expired past the absolute TTL")
	}
}

func TestIdleExpirySlides(t *testing.T) {
	now := time.Unix(0, 0)
	s := New(Config{IdleTTL: time.Hour})
	s.now = func() time.Time { return now }

	id := s.Create("user-1")

	for i := 0; i < 5; i++ {
		now = now.Add(59 * time.Minute)
		if _, err := s.Get(id); err != nil {
			t.Fatalf("active session should stay valid: %v", err)
		}
	}

	now = now.Add(61 * time.Minute)
	if _, err := s.Get(id); err == nil {
		t.Error("idle session should expire after the idle TTL")
	}
}

func TestAbsoluteCapsIdleSliding(t *testing.T) {
	now := time.Unix(0, 0)
	s := New(Config{IdleTTL: time.Hour, AbsoluteTTL: 2 * time.Hour})
	s.now = func() time.Time { return now }

	id := s.Create("user-1")

	now = now.Add(59 * time.Minute)
	if _, err := s.Get(id); err != nil {
		t.Fatalf("should be valid: %v", err)
	}
	now = now.Add(59 * time.Minute)
	if _, err := s.Get(id); err != nil {
		t.Fatalf("should be valid under absolute cap: %v", err)
	}
	now = now.Add(10 * time.Minute)
	if _, err := s.Get(id); err == nil {
		t.Error("session should expire at the absolute cap despite activity")
	}
}

func TestCleanUpPrunesExpired(t *testing.T) {
	now := time.Unix(0, 0)
	s := New(Config{AbsoluteTTL: time.Hour})
	s.now = func() time.Time { return now }

	expired := s.Create("dead")

	now = now.Add(90 * time.Minute)
	live := s.Create("live")

	s.CleanUp()

	s.mu.RLock()
	n := len(s.sessions)
	s.mu.RUnlock()
	if n != 1 {
		t.Errorf("after cleanup want 1 live session, got %d", n)
	}
	if _, err := s.Get(live); err != nil {
		t.Error("freshly created session must survive cleanup")
	}
	if _, err := s.Get(expired); err == nil {
		t.Error("expired session should have been pruned")
	}
}

func TestZeroConfigNeverExpires(t *testing.T) {
	now := time.Unix(0, 0)
	s := New(Config{})
	s.now = func() time.Time { return now }

	id := s.Create("user-1")
	now = now.Add(10000 * time.Hour)
	s.CleanUp()
	if _, err := s.Get(id); err != nil {
		t.Error("zero-config session must not expire")
	}
}

func TestSessionIDIsOpaqueRandom(t *testing.T) {
	s := New(Config{})
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := s.Create("u")
		if len(id) != 43 { // base64url (no pad) of 32 bytes
			t.Fatalf("session id length = %d, want 43", len(id))
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate session id generated: %q", id)
		}
		seen[id] = struct{}{}
	}
}

// TestConcurrentAccess hammers the store from many goroutines so the race
// detector (go test -race) catches unsynchronized map access, which in Go
// panics with "concurrent map read and map write" at runtime.
func TestConcurrentAccess(_ *testing.T) {
	s := New(Config{})

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
