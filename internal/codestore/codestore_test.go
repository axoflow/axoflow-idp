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

package codestore

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/axoflow/axoflow-idp/pkg/user"
)

const cb = "https://app.example.com/cb"

func TestCreateReturnsDistinctCodes(t *testing.T) {
	s := New()
	if a, b := s.Create(Grant{}, "app", cb), s.Create(Grant{}, "app", cb); a == b {
		t.Errorf("two codes are the same: %q", a)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	s := New()

	code := s.Create(Grant{User: user.UserInfo{ID: "u1"}}, "app", cb)
	if _, err := s.Pop(code, "app", cb); err != nil {
		t.Fatalf("Pop returned error: %v", err)
	}
	if _, err := s.Pop(code, "app", cb); err == nil {
		t.Error("an authorization code must not be redeemable twice (RFC 6749 §10.5)")
	}
}

func TestPop_WrongClientIsRejectedAndSpendsTheCode(t *testing.T) {
	s := New()
	code := s.Create(Grant{User: user.UserInfo{ID: "u1"}}, "app", cb)

	got, err := s.Pop(code, "other", cb)
	if !errors.Is(err, ErrClientMismatch) {
		t.Fatalf("Pop err = %v, want %v", err, ErrClientMismatch)
	}
	if got.User.ID != "" {
		t.Errorf("Pop returned a grant %+v on failure", got)
	}
	if _, err := s.Pop(code, "app", cb); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Pop after failure err = %v, want %v", err, ErrNotFound)
	}
}

// The entry goes straight into the map, so no Create runs cleanUp before Pop.
func TestPop_ExpiredCodeIsRejectedAndSpent(t *testing.T) {
	s := New()
	const id = "stale-code"
	s.codes[id] = code{createdAt: time.Now().Add(-2 * time.Minute), grant: Grant{User: user.UserInfo{ID: "u1"}}, clientID: "app", redirectURI: cb}

	got, err := s.Pop(id, "app", cb)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Pop err = %v, want %v", err, ErrExpired)
	}
	if got.User.ID != "" {
		t.Errorf("Pop returned a grant %+v for an expired code", got)
	}
	if _, err := s.Pop(id, "app", cb); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Pop after expiry err = %v, want %v", err, ErrNotFound)
	}
}

// The entries go straight into the map with their creation time set, so no
// Create runs cleanUp first and no test waits out the minute.
func TestCleanUpDropsExpiredCodes(t *testing.T) {
	s := New()
	now := time.Now()
	for id, age := range map[string]time.Duration{"expired-1": 2 * time.Minute, "expired-2": time.Hour, "fresh-1": 0, "fresh-2": 30 * time.Second} {
		s.codes[id] = code{createdAt: now.Add(-age), clientID: "app", redirectURI: cb}
	}

	s.CleanUp()

	for _, id := range []string{"expired-1", "expired-2"} {
		if _, ok := s.codes[id]; ok {
			t.Errorf("%s is still held after CleanUp", id)
		}
	}
	for _, id := range []string{"fresh-1", "fresh-2"} {
		if _, ok := s.codes[id]; !ok {
			t.Errorf("%s was dropped by CleanUp", id)
		}
	}
}

// No assertions: this fails only under -race, as a regression for the
// unsynchronized map access.
func TestConcurrentAccess(_ *testing.T) {
	s := New()

	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				code := s.Create(Grant{User: user.UserInfo{ID: "u1"}}, "app", cb)
				s.CleanUp()
				_, _ = s.Pop(code, "app", cb)
			}
		}()
	}
	wg.Wait()
}
