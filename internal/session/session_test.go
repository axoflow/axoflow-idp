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
	if other := s.Create("user-1"); other == id {
		t.Errorf("two sessions have the same id: %q", id)
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

// clock is a settable time source for the store.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newClockedStore(cfg Config) (*Session, *clock) {
	c := &clock{t: time.Unix(1_700_000_000, 0)}
	s := New(cfg)
	s.now = c.now
	return s, c
}

func TestLifetime(t *testing.T) {
	tests := []struct {
		name  string
		cfg   Config
		steps []time.Duration // advance the clock, then Get, for each step
		want  bool            // whether the last Get resolves
	}{
		{"no limits", Config{}, []time.Duration{10_000 * time.Hour}, true},
		{"within absolute", Config{AbsoluteTTL: time.Hour}, []time.Duration{59 * time.Minute}, true},
		{"past absolute", Config{AbsoluteTTL: time.Hour}, []time.Duration{61 * time.Minute}, false},
		{"use does not extend absolute", Config{AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute}, []time.Duration{20 * time.Minute, 20 * time.Minute, 20 * time.Minute, 5 * time.Minute}, false},
		{"within idle", Config{IdleTTL: 30 * time.Minute}, []time.Duration{29 * time.Minute}, true},
		{"past idle", Config{IdleTTL: 30 * time.Minute}, []time.Duration{31 * time.Minute}, false},
		{"use refreshes idle", Config{IdleTTL: 30 * time.Minute}, []time.Duration{20 * time.Minute, 20 * time.Minute, 20 * time.Minute, 20 * time.Minute}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, c := newClockedStore(tt.cfg)
			id := s.Create("alice")
			var err error
			for _, step := range tt.steps {
				c.t = c.t.Add(step)
				_, err = s.Get(id)
			}
			if got := err == nil; got != tt.want {
				t.Errorf("session resolves = %v (%v), want %v", got, err, tt.want)
			}
		})
	}
}

func TestCleanUp(t *testing.T) {
	for _, tt := range []struct {
		name      string
		cfg       Config
		wantStale bool // whether the stale session survives CleanUp
	}{
		{"absolute", Config{AbsoluteTTL: time.Hour}, false},
		{"idle", Config{IdleTTL: time.Hour}, false},
		{"no limits", Config{}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, c := newClockedStore(tt.cfg)
			stale := s.Create("alice")
			c.t = c.t.Add(90 * time.Minute)
			fresh := s.Create("alice")

			s.CleanUp()

			if _, ok := s.sessions[stale]; ok != tt.wantStale {
				t.Errorf("stale session held after CleanUp = %v, want %v", ok, tt.wantStale)
			}
			if _, ok := s.sessions[fresh]; !ok {
				t.Error("fresh session dropped by CleanUp")
			}
			if n := len(s.byUser["alice"]); n != len(s.sessions) {
				t.Errorf("user index holds %d ids, store %d sessions", n, len(s.sessions))
			}
		})
	}
}

func TestCreateEvictsOldestBeyondCap(t *testing.T) {
	s, c := newClockedStore(Config{})
	bob := s.Create("bob")
	ids := make([]string, MaxPerUser+1)
	for i := range ids {
		c.t = c.t.Add(time.Second)
		ids[i] = s.Create("alice")
	}

	if _, err := s.Get(ids[0]); err == nil {
		t.Error("the oldest session survived going over the cap")
	}
	for _, id := range ids[1:] {
		if _, err := s.Get(id); err != nil {
			t.Fatalf("a session within the cap is gone: %v", err)
		}
	}
	if _, err := s.Get(bob); err != nil {
		t.Error("another user's session was evicted")
	}
	if n := len(s.byUser["alice"]); n != MaxPerUser {
		t.Errorf("alice holds %d sessions, want %d", n, MaxPerUser)
	}
}

// Expired sessions do not count toward the cap: an old session kept alive by
// use outlives 49 younger ones that went idle.
func TestCreateDropsExpiredBeforeTheCap(t *testing.T) {
	s, c := newClockedStore(Config{IdleTTL: 30 * time.Minute})
	old := s.Create("alice")
	bob := s.Create("bob")
	idle := make([]string, MaxPerUser-1)
	for i := range idle {
		c.t = c.t.Add(time.Second)
		idle[i] = s.Create("alice")
	}
	c.t = c.t.Add(20 * time.Minute)
	if _, err := s.Get(old); err != nil {
		t.Fatalf("refresh the old session: %v", err)
	}
	c.t = c.t.Add(20 * time.Minute) // the idle ones and bob's are now expired

	fresh := s.Create("alice")

	if _, err := s.Get(old); err != nil {
		t.Errorf("the live old session was evicted: %v", err)
	}
	for _, id := range idle {
		if _, ok := s.sessions[id]; ok {
			t.Fatal("an expired session is still held after Create")
		}
	}
	if _, ok := s.sessions[bob]; !ok {
		t.Error("another user's session was touched")
	}
	if got := s.byUser["alice"]; len(got) != 2 {
		t.Errorf("alice's index holds %d ids, want 2 (old and fresh)", len(got))
	}
	if _, err := s.Get(fresh); err != nil {
		t.Errorf("the new session does not resolve: %v", err)
	}
}

// When every session of the user has expired, the new one still lands in the
// user's index, so DeleteUserSessions reaches it.
func TestCreateAfterAllExpiredIsIndexed(t *testing.T) {
	s, c := newClockedStore(Config{IdleTTL: 30 * time.Minute})
	s.Create("alice")
	c.t = c.t.Add(time.Hour)

	fresh := s.Create("alice")
	s.DeleteUserSessions("alice")

	if _, err := s.Get(fresh); err == nil {
		t.Error("the new session survived DeleteUserSessions")
	}
}
