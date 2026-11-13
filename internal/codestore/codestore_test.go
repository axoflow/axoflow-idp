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
)

const cb = "https://app.example.com/cb"

func TestCreateReturnsDistinctCodes(t *testing.T) {
	s := New()
	if a, b := s.Create("id-token", "app", cb), s.Create("id-token", "app", cb); a == b {
		t.Errorf("two codes are the same: %q", a)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	s := New()

	code := s.Create("id-token-1", "app", cb)
	if _, err := s.Pop(code, "app", cb); err != nil {
		t.Fatalf("Pop returned error: %v", err)
	}
	if _, err := s.Pop(code, "app", cb); err == nil {
		t.Error("an authorization code must not be redeemable twice (RFC 6749 §10.5)")
	}
}

func TestPop_BindingMismatchIsRejectedAndSpendsTheCode(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		redirect string
		want     error
	}{
		{"another client", "other", cb, ErrClientMismatch},
		{"another redirect_uri", "app", "https://app.example.com/other", ErrRedirectMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New()
			code := s.Create("id-token", "app", cb)

			got, err := s.Pop(code, tt.clientID, tt.redirect)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Pop err = %v, want %v", err, tt.want)
			}
			if got != "" {
				t.Errorf("Pop returned token %q on failure", got)
			}
			if _, err := s.Pop(code, "app", cb); !errors.Is(err, ErrNotFound) {
				t.Fatalf("Pop after failure err = %v, want %v", err, ErrNotFound)
			}
		})
	}
}

// The entry goes straight into the map, so no Create runs cleanUp before Pop.
func TestPop_ExpiredCodeIsRejectedAndSpent(t *testing.T) {
	s := New()
	id := "expired"
	s.codes[id] = code{createdAt: time.Now().Add(-2 * time.Minute), id_token: "id-token", clientID: "app", redirectURI: cb}

	got, err := s.Pop(id, "app", cb)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Pop err = %v, want %v", err, ErrExpired)
	}
	if got != "" {
		t.Errorf("Pop returned token %q for an expired code", got)
	}
	if _, err := s.Pop(id, "app", cb); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Pop after expiry err = %v, want %v", err, ErrNotFound)
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
				code := s.Create("id-token", "app", cb)
				s.CleanUp()
				_, _ = s.Pop(code, "app", cb)
			}
		}()
	}
	wg.Wait()
}
