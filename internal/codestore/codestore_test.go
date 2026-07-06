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
	"sync"
	"testing"
)

func TestCodeIsSingleUse(t *testing.T) {
	s := New()

	code := s.Create(Grant{IDToken: "id-token-1"})
	if _, err := s.Pop(code); err != nil {
		t.Fatalf("Pop returned error: %v", err)
	}
	if _, err := s.Pop(code); err == nil {
		t.Error("an authorization code must not be redeemable twice (RFC 6749 §10.5)")
	}
}

func TestCodeIsOpaqueRandom(t *testing.T) {
	s := New()
	const n = 1000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		c := s.Create(Grant{IDToken: "t"})
		if len(c) != 43 { // base64url (no pad) of 32 bytes
			t.Fatalf("code length = %d, want 43", len(c))
		}
		for _, r := range c {
			urlSafe := r == '-' || r == '_' ||
				(r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			if !urlSafe {
				t.Fatalf("code %q contains non-URL-safe char %q", c, r)
			}
		}
		if _, dup := seen[c]; dup {
			t.Fatalf("duplicate code generated: %q", c)
		}
		seen[c] = struct{}{}
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
				code := s.Create(Grant{IDToken: "id-token"})
				s.CleanUp()
				_, _ = s.Pop(code)
			}
		}()
	}
	wg.Wait()
}
