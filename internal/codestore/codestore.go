// Copyright © 2025 Axoflow
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
	"time"
)

type code struct {
	createdAt time.Time
	id_token  string
}

type CodeStore struct {
	codes map[string]code
	mu    sync.RWMutex
	ttl   time.Duration
}

func New() *CodeStore {
	return &CodeStore{
		codes: map[string]code{},
		ttl:   time.Minute,
	}
}

func (s *CodeStore) CleanUp() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanUp()
}

// cleanUp assumes the caller holds the write lock.
func (s *CodeStore) cleanUp() {
	if s.ttl == 0 {
		return
	}
	for k, v := range s.codes {
		if v.createdAt.Before(time.Now().Add(-s.ttl)) {
			delete(s.codes, k)
		}
	}
}

func (s *CodeStore) Create(id_token string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanUp()
	// the code is a credential (RFC 6749 §10.10), so it comes from crypto/rand: a ULID's entropy is math/rand
	id := rand.Text()
	s.codes[id] = code{
		createdAt: time.Now(),
		id_token:  id_token,
	}

	return id
}

func (s *CodeStore) Pop(code string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.codes[code]
	if !ok {
		return "", errors.New("code not found")
	}

	delete(s.codes, code)
	return session.id_token, nil
}
