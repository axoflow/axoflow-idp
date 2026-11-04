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

	"github.com/axoflow/axoflow-idp/pkg/user"
)

// Grant is what an authorization code stands for: the user who authenticated and the request the tokens
// are minted from when the code is redeemed.
type Grant struct {
	User  user.UserInfo
	Nonce string
	// Resource is the RFC 8707 resource the access token is minted for ("" for the client itself);
	// a resource named at /token must match it.
	Resource      string
	CodeChallenge string
}

type code struct {
	createdAt   time.Time
	grant       Grant
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
	ErrExpired          = errors.New("code expired")
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
		if v.createdAt.Before(time.Now().Add(-s.ttl)) {
			delete(s.codes, k)
		}
	}
}

// Create stores the grant under a new code bound to clientID and redirectURI.
func (s *CodeStore) Create(grant Grant, clientID, redirectURI string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanUp()
	// the code is a credential (RFC 6749 §10.10), so it comes from crypto/rand: a ULID's entropy is math/rand
	id := rand.Text()
	s.codes[id] = code{
		createdAt:   time.Now(),
		grant:       grant,
		clientID:    clientID,
		redirectURI: redirectURI,
	}

	return id
}

// Pop consumes the code even when the binding fails: single use per RFC 6749 §4.1.2.
// It refuses an expired code, whether or not cleanUp has run since it expired.
func (s *CodeStore) Pop(code, clientID, redirectURI string) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.codes[code]
	if !ok {
		return Grant{}, ErrNotFound
	}

	delete(s.codes, code)
	if s.ttl != 0 && session.createdAt.Before(time.Now().Add(-s.ttl)) {
		return Grant{}, ErrExpired
	}
	if session.clientID != clientID {
		return Grant{}, ErrClientMismatch
	}
	if session.redirectURI != redirectURI {
		return Grant{}, ErrRedirectMismatch
	}
	return session.grant, nil
}
