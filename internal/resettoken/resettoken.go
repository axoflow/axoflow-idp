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

// Package resettoken provides an in-memory store of single-use, expiring
// password-reset tokens. A token is unguessable (256 bits from crypto/rand),
// valid for a fixed TTL, consumed on first use, and at most one token is
// active per user (generating a new one invalidates the previous).
package resettoken

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type entry struct {
	userID    string
	expiresAt time.Time
}

// Store holds outstanding reset tokens. It is safe for concurrent use.
type Store struct {
	mu      sync.Mutex
	ttl     time.Duration
	now     func() time.Time
	byToken map[string]entry  // token -> entry
	byUser  map[string]string // userID -> active token
}

// New returns a Store whose tokens expire after ttl.
func New(ttl time.Duration) *Store {
	return &Store{
		ttl:     ttl,
		now:     time.Now,
		byToken: map[string]entry{},
		byUser:  map[string]string{},
	}
}

// Create mints a new reset token for userID, invalidating any token previously
// issued to that user. The returned token is the secret to embed in the link.
func (s *Store) Create(userID string) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if prev, ok := s.byUser[userID]; ok {
		delete(s.byToken, prev)
	}
	s.byToken[token] = entry{userID: userID, expiresAt: s.now().Add(s.ttl)}
	s.byUser[userID] = token

	return token, nil
}

// Consume validates and atomically invalidates a token. It returns the
// associated user ID and true on success. Unknown, already-used, and expired
// tokens all return ("", false); the token is removed regardless so a single
// presentation is the only chance to use it.
func (s *Store) Consume(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.byToken[token]
	if !ok {
		return "", false
	}

	delete(s.byToken, token)
	if s.byUser[e.userID] == token {
		delete(s.byUser, e.userID)
	}

	if s.now().After(e.expiresAt) {
		return "", false
	}

	return e.userID, true
}

// Peek returns the user ID for a valid (known, unexpired) token without
// consuming it, so the caller can perform fallible work (e.g. persisting the
// new password) and only Consume once it has durably succeeded. Expired tokens
// are removed and reported invalid.
func (s *Store) Peek(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.byToken[token]
	if !ok {
		return "", false
	}
	if s.now().After(e.expiresAt) {
		delete(s.byToken, token)
		if s.byUser[e.userID] == token {
			delete(s.byUser, e.userID)
		}
		return "", false
	}

	return e.userID, true
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
