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
	"errors"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// Issued is what a code redeems to.
type Issued struct {
	IDToken       string
	AccessToken   string
	CodeChallenge string
}

type code struct {
	ID          ulid.ULID
	issued      Issued
	clientID    string
	redirectURI string
}

type CodeStore struct {
	codes map[string]code
	mu    sync.RWMutex
	ttl   time.Duration
}

var (
	ErrNotFound         = errors.New("code not found")
	ErrClientMismatch   = errors.New("code issued to another client")
	ErrRedirectMismatch = errors.New("code issued for another redirect_uri")
)

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
		if ulid.Time(v.ID.Time()).Before(time.Now().Add(-s.ttl)) {
			delete(s.codes, k)
		}
	}
}

// Create stores the issued tokens under a new code bound to clientID and redirectURI.
func (s *CodeStore) Create(issued Issued, clientID, redirectURI string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanUp()
	code := code{
		ID:          ulid.Make(),
		issued:      issued,
		clientID:    clientID,
		redirectURI: redirectURI,
	}
	s.codes[code.ID.String()] = code

	return code.ID.String()
}

// Pop consumes the code even when the binding fails: single use per RFC 6749 §4.1.2.
func (s *CodeStore) Pop(code, clientID, redirectURI string) (Issued, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.codes[code]
	if !ok {
		return Issued{}, ErrNotFound
	}

	delete(s.codes, code)
	if session.clientID != clientID {
		return Issued{}, ErrClientMismatch
	}
	if session.redirectURI != redirectURI {
		return Issued{}, ErrRedirectMismatch
	}
	return session.issued, nil
}
