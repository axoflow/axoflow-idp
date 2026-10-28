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

package resettoken

import (
	"sync"
	"testing"
	"time"
)

func TestCreateAndConsume(t *testing.T) {
	s := New(time.Hour)

	tok, err := s.Create("alice", "admin")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tok == "" {
		t.Fatal("Create returned empty token")
	}

	userID, issuedBy, ok := s.Consume(tok)
	if !ok {
		t.Fatal("Consume of valid token should succeed")
	}
	if userID != "alice" || issuedBy != "admin" {
		t.Errorf("Consume = (%q, %q), want (alice, admin)", userID, issuedBy)
	}
}

func TestConsumeIsSingleUse(t *testing.T) {
	s := New(time.Hour)
	tok, _ := s.Create("alice", "admin")

	if _, _, ok := s.Consume(tok); !ok {
		t.Fatal("first Consume should succeed")
	}
	if _, _, ok := s.Consume(tok); ok {
		t.Error("second Consume of the same token should fail")
	}
}

func TestPeekDoesNotConsume(t *testing.T) {
	s := New(time.Hour)
	tok, _ := s.Create("alice", "admin")

	for i := 0; i < 3; i++ {
		userID, issuedBy, ok := s.Peek(tok)
		if !ok || userID != "alice" || issuedBy != "admin" {
			t.Fatalf("Peek #%d = (%q,%q,%v), want (alice,admin,true)", i, userID, issuedBy, ok)
		}
	}
	// Still consumable afterwards.
	if _, _, ok := s.Consume(tok); !ok {
		t.Error("token should still be consumable after Peek")
	}
}

func TestPeekExpired(t *testing.T) {
	s := New(time.Hour)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	tok, _ := s.Create("alice", "admin")

	now = now.Add(time.Hour + time.Second)
	if _, _, ok := s.Peek(tok); ok {
		t.Error("Peek of expired token should fail")
	}
}

func TestConsumeUnknownToken(t *testing.T) {
	s := New(time.Hour)
	if _, _, ok := s.Consume("does-not-exist"); ok {
		t.Error("Consume of unknown token should fail")
	}
}

func TestConsumeExpiredToken(t *testing.T) {
	s := New(time.Hour)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }

	tok, _ := s.Create("alice", "admin")

	now = now.Add(time.Hour + time.Second) // advance past TTL
	if _, _, ok := s.Consume(tok); ok {
		t.Error("Consume of expired token should fail")
	}
}

func TestNewTokenInvalidatesPrior(t *testing.T) {
	s := New(time.Hour)

	first, _ := s.Create("alice", "admin")
	second, _ := s.Create("alice", "admin")

	if first == second {
		t.Fatal("expected distinct tokens")
	}
	if _, _, ok := s.Consume(first); ok {
		t.Error("prior token should be invalidated by a newer one")
	}
	if _, _, ok := s.Consume(second); !ok {
		t.Error("newest token should still be valid")
	}
}

func TestRevokeUser(t *testing.T) {
	s := New(time.Hour)
	alice, _ := s.Create("alice", "admin")
	bob, _ := s.Create("bob", "admin")

	s.RevokeUser("alice")
	s.RevokeUser("carol") // no token: a no-op

	if _, _, ok := s.Consume(alice); ok {
		t.Error("revoked token should be invalid")
	}
	if _, _, ok := s.Consume(bob); !ok {
		t.Error("another user's token should survive the revocation")
	}
}

func TestCleanUpDropsExpired(t *testing.T) {
	s := New(time.Hour)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	old, _ := s.Create("alice", "admin")
	now = now.Add(30 * time.Minute)
	fresh, _ := s.Create("bob", "admin")

	now = now.Add(31 * time.Minute) // past old's TTL, within fresh's
	s.CleanUp()

	if _, ok := s.byToken[old]; ok {
		t.Error("expired token still held after CleanUp")
	}
	if _, ok := s.byUser["alice"]; ok {
		t.Error("expired token's user index still held after CleanUp")
	}
	if _, _, ok := s.Consume(fresh); !ok {
		t.Error("unexpired token dropped by CleanUp")
	}
}

func TestTokensAreUnique(t *testing.T) {
	s := New(time.Hour)
	seen := map[string]struct{}{}
	for i := 0; i < 1000; i++ {
		tok, err := s.Create("user", "admin")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token generated: %q", tok)
		}
		seen[tok] = struct{}{}
	}
}

func TestConcurrentAccess(_ *testing.T) {
	s := New(time.Hour)
	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tok, _ := s.Create("user", "admin")
				_, _, _ = s.Consume(tok)
			}
		}()
	}
	wg.Wait()
}
