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
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

const cb = "https://app.example.com/cb"

func TestCodeIsSingleUse(t *testing.T) {
	s := New()

	code := s.Create(Issued{IDToken: "id-token-1"}, "app", cb)
	if _, err := s.Pop(code, "app", cb); err != nil {
		t.Fatalf("Pop returned error: %v", err)
	}
	if _, err := s.Pop(code, "app", cb); err == nil {
		t.Error("an authorization code must not be redeemable twice (RFC 6749 §10.5)")
	}
}

func TestPop_WrongClientIsRejectedAndSpendsTheCode(t *testing.T) {
	s := New()
	code := s.Create(Issued{IDToken: "id-token"}, "app", cb)

	got, err := s.Pop(code, "other", cb)
	if !errors.Is(err, ErrClientMismatch) {
		t.Fatalf("Pop err = %v, want %v", err, ErrClientMismatch)
	}
	if got != (Issued{}) {
		t.Errorf("Pop returned tokens %+v on failure", got)
	}
	if _, err := s.Pop(code, "app", cb); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Pop after failure err = %v, want %v", err, ErrNotFound)
	}
}

// The entry goes straight into the map, so no Create runs cleanUp before Pop.
func TestPop_ExpiredCodeIsRejectedAndSpent(t *testing.T) {
	s := New()
	id := ulid.MustNew(ulid.Timestamp(time.Now().Add(-2*time.Minute)), rand.Reader)
	s.codes[id.String()] = code{ID: id, issued: Issued{IDToken: "id-token"}, clientID: "app", redirectURI: cb}

	got, err := s.Pop(id.String(), "app", cb)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("Pop err = %v, want %v", err, ErrExpired)
	}
	if got != (Issued{}) {
		t.Errorf("Pop returned tokens %+v for an expired code", got)
	}
	if _, err := s.Pop(id.String(), "app", cb); !errors.Is(err, ErrNotFound) {
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
				code := s.Create(Issued{IDToken: "id-token"}, "app", cb)
				s.CleanUp()
				_, _ = s.Pop(code, "app", cb)
			}
		}()
	}
	wg.Wait()
}
