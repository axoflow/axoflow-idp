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

func TestCreateGetPop(t *testing.T) {
	s := New()

	code := s.Create("id-token-1")
	if code == "" {
		t.Fatal("Create returned empty code")
	}

	idToken, err := s.Get(code)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if idToken != "id-token-1" {
		t.Errorf("Get = %q, want %q", idToken, "id-token-1")
	}

	popped, err := s.Pop(code)
	if err != nil {
		t.Fatalf("Pop returned error: %v", err)
	}
	if popped != "id-token-1" {
		t.Errorf("Pop = %q, want %q", popped, "id-token-1")
	}

	if _, err := s.Get(code); err == nil {
		t.Error("Get after Pop should return error")
	}
}

func TestGetPopUnknownCode(t *testing.T) {
	s := New()

	if _, err := s.Get("nope"); err == nil {
		t.Error("Get of unknown code should return error")
	}
	if _, err := s.Pop("nope"); err == nil {
		t.Error("Pop of unknown code should return error")
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
				code := s.Create("id-token")
				_, _ = s.Get(code)
				s.CleanUp()
				_, _ = s.Pop(code)
				s.Delete(code)
			}
		}()
	}
	wg.Wait()
}
