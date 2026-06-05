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

	tok, err := s.Create("alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if tok == "" {
		t.Fatal("Create returned empty token")
	}

	userID, ok := s.Consume(tok)
	if !ok {
		t.Fatal("Consume of valid token should succeed")
	}
	if userID != "alice" {
		t.Errorf("Consume userID = %q, want %q", userID, "alice")
	}
}

func TestConsumeIsSingleUse(t *testing.T) {
	s := New(time.Hour)
	tok, _ := s.Create("alice")

	if _, ok := s.Consume(tok); !ok {
		t.Fatal("first Consume should succeed")
	}
	if _, ok := s.Consume(tok); ok {
		t.Error("second Consume of the same token should fail")
	}
}

func TestPeekDoesNotConsume(t *testing.T) {
	s := New(time.Hour)
	tok, _ := s.Create("alice")

	for i := 0; i < 3; i++ {
		userID, ok := s.Peek(tok)
		if !ok || userID != "alice" {
			t.Fatalf("Peek #%d = (%q,%v), want (alice,true)", i, userID, ok)
		}
	}
	// Still consumable afterwards.
	if _, ok := s.Consume(tok); !ok {
		t.Error("token should still be consumable after Peek")
	}
}

func TestPeekExpired(t *testing.T) {
	s := New(time.Hour)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	tok, _ := s.Create("alice")

	now = now.Add(time.Hour + time.Second)
	if _, ok := s.Peek(tok); ok {
		t.Error("Peek of expired token should fail")
	}
}

func TestConsumeUnknownToken(t *testing.T) {
	s := New(time.Hour)
	if _, ok := s.Consume("does-not-exist"); ok {
		t.Error("Consume of unknown token should fail")
	}
}

func TestConsumeExpiredToken(t *testing.T) {
	s := New(time.Hour)
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }

	tok, _ := s.Create("alice")

	now = now.Add(time.Hour + time.Second) // advance past TTL
	if _, ok := s.Consume(tok); ok {
		t.Error("Consume of expired token should fail")
	}
}

func TestNewTokenInvalidatesPrior(t *testing.T) {
	s := New(time.Hour)

	first, _ := s.Create("alice")
	second, _ := s.Create("alice")

	if first == second {
		t.Fatal("expected distinct tokens")
	}
	if _, ok := s.Consume(first); ok {
		t.Error("prior token should be invalidated by a newer one")
	}
	if _, ok := s.Consume(second); !ok {
		t.Error("newest token should still be valid")
	}
}

func TestTokensAreUnique(t *testing.T) {
	s := New(time.Hour)
	seen := map[string]struct{}{}
	for i := 0; i < 1000; i++ {
		tok, err := s.Create("user")
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token generated: %q", tok)
		}
		seen[tok] = struct{}{}
	}
}

func TestConcurrentAccess(t *testing.T) {
	s := New(time.Hour)
	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tok, _ := s.Create("user")
				_, _ = s.Consume(tok)
			}
		}()
	}
	wg.Wait()
}
