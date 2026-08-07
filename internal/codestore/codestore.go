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

// Grant is the state captured at authorize time and consumed at the token
// endpoint, so the exchange can be checked against the request that created it.
type Grant struct {
	IDToken             string
	UserID              string
	ClientID            string
	Scopes              []string
	OfflineGranted      bool
	CodeChallenge       string
	CodeChallengeMethod string
}

type code struct {
	ID    ulid.ULID
	grant Grant
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
		if ulid.Time(v.ID.Time()).Before(time.Now().Add(-s.ttl)) {
			delete(s.codes, k)
		}
	}
}

func (s *CodeStore) Create(grant Grant) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanUp()
	code := code{
		ID:    ulid.Make(),
		grant: grant,
	}
	s.codes[code.ID.String()] = code

	return code.ID.String()
}

func (s *CodeStore) Pop(code string) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.codes[code]
	if !ok {
		return Grant{}, errors.New("code not found")
	}

	delete(s.codes, code)
	return session.grant, nil
}
