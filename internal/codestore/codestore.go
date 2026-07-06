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
	"encoding/base64"
	"errors"
	"sync"
	"time"
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
	createdAt time.Time
	grant     Grant
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
	cutoff := time.Now().Add(-s.ttl)
	for k, v := range s.codes {
		if v.createdAt.Before(cutoff) {
			delete(s.codes, k)
		}
	}
}

func (s *CodeStore) Create(grant Grant) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanUp()
	id := newCode()
	s.codes[id] = code{
		createdAt: time.Now(),
		grant:     grant,
	}

	return id
}

// newCode returns a 256-bit crypto-random, URL-safe opaque authorization code.
func newCode() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("codestore: failed to read random bytes: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
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
