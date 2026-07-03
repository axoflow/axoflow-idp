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

package refreshstore

import (
	"sync"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestStore() (*Store, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s := New(Config{IdleTTL: time.Hour, AbsoluteTTL: 24 * time.Hour, ReuseLeeway: 10 * time.Second})
	s.now = clk.now
	return s, clk
}

func testGrant() Grant {
	return Grant{UserID: "u1", ClientID: "app", Scopes: []string{"openid", "offline_access"}}
}

func TestRotateClientMismatchNoRevoke(t *testing.T) {
	s, _ := newTestStore()
	tok, _ := s.Issue(testGrant())

	if _, _, err := s.Rotate(tok, "other-client"); err != ErrInvalidGrant {
		t.Errorf("client mismatch = %v, want ErrInvalidGrant", err)
	}
	// Not treated as theft: the correct client can still use the token.
	if _, _, err := s.Rotate(tok, "app"); err != nil {
		t.Errorf("Rotate after client mismatch = %v, want success (no family revoke)", err)
	}
}

func TestRotateReuseAfterLeewayRevokesFamily(t *testing.T) {
	s, clk := newTestStore()
	tok, _ := s.Issue(testGrant())

	_, next, err := s.Rotate(tok, "app")
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}

	clk.advance(11 * time.Second) // past ReuseLeeway (10s)

	if _, _, err := s.Rotate(tok, "app"); err != ErrInvalidGrant {
		t.Errorf("replay of consumed token = %v, want ErrInvalidGrant", err)
	}
	// Theft response: the whole family is dead, including the live successor.
	if _, _, err := s.Rotate(next, "app"); err != ErrInvalidGrant {
		t.Errorf("successor after detected reuse = %v, want ErrInvalidGrant (family revoked)", err)
	}
}

func TestRotateConsumedCheckBeforeExpiry(t *testing.T) {
	s, clk := newTestStore()
	tok, _ := s.Issue(testGrant())

	_, next, err := s.Rotate(tok, "app")
	if err != nil {
		t.Fatalf("first rotate: %v", err)
	}

	// Advance past BOTH the reuse leeway and the original token's idle expiry.
	clk.advance(2 * time.Hour)

	// A stolen-then-idle-expired token must still trip theft detection, not be
	// silently dismissed as merely expired.
	if _, _, err := s.Rotate(tok, "app"); err != ErrInvalidGrant {
		t.Errorf("replay of expired consumed token = %v, want ErrInvalidGrant", err)
	}
	if _, _, err := s.Rotate(next, "app"); err != ErrInvalidGrant {
		t.Errorf("successor = %v, want ErrInvalidGrant (family revoked as theft)", err)
	}
}

func TestRotateIdleExpiry(t *testing.T) {
	s, clk := newTestStore()
	tok, _ := s.Issue(testGrant())

	clk.advance(time.Hour + time.Second) // past IdleTTL, never rotated

	if _, _, err := s.Rotate(tok, "app"); err != ErrInvalidGrant {
		t.Errorf("idle-expired token = %v, want ErrInvalidGrant", err)
	}
}

func TestRotateAbsoluteExpiry(t *testing.T) {
	s, clk := newTestStore()
	tok, _ := s.Issue(testGrant())

	// Keep within idle by rotating every 30 min, but cross the 24h absolute cap.
	for i := 0; i < 47; i++ {
		clk.advance(30 * time.Minute)
		grant, next, err := s.Rotate(tok, "app")
		if err != nil {
			t.Fatalf("rotate %d before absolute cap: %v", i, err)
		}
		_ = grant
		tok = next
	}
	clk.advance(time.Hour) // now past 24h absolute cap

	if _, _, err := s.Rotate(tok, "app"); err != ErrInvalidGrant {
		t.Errorf("token past absolute cap = %v, want ErrInvalidGrant", err)
	}
}

func TestRevokeFamilyOwnerChecked(t *testing.T) {
	s, _ := newTestStore()
	tok, _ := s.Issue(testGrant())
	_, next, _ := s.Rotate(tok, "app")

	if ok := s.Revoke(next, "wrong-client"); ok {
		t.Error("Revoke by non-owning client returned true, want false")
	}
	if _, _, err := s.Rotate(next, "app"); err != nil {
		t.Errorf("token after non-owner revoke = %v, want still usable", err)
	}

	if ok := s.Revoke(next, "app"); !ok {
		t.Error("Revoke by owning client returned false, want true")
	}
	if _, _, err := s.Rotate(next, "app"); err != ErrInvalidGrant {
		t.Errorf("token after owner revoke = %v, want ErrInvalidGrant", err)
	}
}

func TestRevokeUser(t *testing.T) {
	s, _ := newTestStore()
	a1, _ := s.Issue(Grant{UserID: "u1", ClientID: "app"})
	a2, _ := s.Issue(Grant{UserID: "u1", ClientID: "other"})
	b1, _ := s.Issue(Grant{UserID: "u2", ClientID: "app"})

	s.RevokeUser("u1")
	if _, _, err := s.Rotate(a1, "app"); err != ErrInvalidGrant {
		t.Error("u1 family a1 should be revoked")
	}
	if _, _, err := s.Rotate(a2, "other"); err != ErrInvalidGrant {
		t.Error("u1 family a2 should be revoked")
	}
	if _, _, err := s.Rotate(b1, "app"); err != nil {
		t.Errorf("u2 family should be unaffected, got %v", err)
	}
}

func TestCleanUpPrunesExpiredFamilies(t *testing.T) {
	s, clk := newTestStore()
	tok, _ := s.Issue(testGrant())

	clk.advance(25 * time.Hour) // past absolute cap
	if _, err := s.Issue(testGrant()); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if got := len(s.byToken); got != 1 {
		t.Errorf("expired family survived the prune: byToken size = %d, want 1 (the new token only)", got)
	}
	if _, _, err := s.Rotate(tok, "app"); err != ErrInvalidGrant {
		t.Errorf("pruned token = %v, want ErrInvalidGrant", err)
	}
}

func TestConcurrentAccess(_ *testing.T) {
	s, _ := newTestStore()

	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				tok, _ := s.Issue(Grant{UserID: "u", ClientID: "app"})
				_, next, err := s.Rotate(tok, "app")
				if err == nil {
					s.Revoke(next, "app")
				}
				s.RevokeUser("u")
			}
		}()
	}
	wg.Wait()
}

// TestConcurrentSameToken verifies that many goroutines rotating the SAME token
// serialize into exactly one successor (via the reuse-leeway window) rather than
// revoking the family as a false-positive reuse.
func TestConcurrentSameToken(t *testing.T) {
	s, _ := newTestStore()
	tok, _ := s.Issue(testGrant())

	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[string]int)
	errs := 0

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			_, next, err := s.Rotate(tok, "app")
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs++
				return
			}
			results[next]++
		}()
	}
	wg.Wait()

	if errs != 0 {
		t.Errorf("got %d errors racing the same token, want 0 (leeway should make it idempotent)", errs)
	}
	if len(results) != 1 {
		t.Errorf("got %d distinct successors, want exactly 1", len(results))
	}
}
