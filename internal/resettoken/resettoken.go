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
	"fmt"
	"sync"
	"time"
)

type entry struct {
	userID string
	// issuedBy is the admin who minted the link: redemption carries that
	// admin's authority, so the redeemer checks it is still held.
	issuedBy  string
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

// Create mints a new reset token for userID on behalf of the admin issuedBy,
// invalidating any token previously issued to that user. The returned token is
// the secret to embed in the link.
func (s *Store) Create(userID, issuedBy string) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if prev, ok := s.byUser[userID]; ok {
		delete(s.byToken, prev)
	}
	s.byToken[token] = entry{userID: userID, issuedBy: issuedBy, expiresAt: s.now().Add(s.ttl)}
	s.byUser[userID] = token

	return token, nil
}

// Consume validates and atomically invalidates a token. It returns the
// associated user ID, the issuing admin's ID and true on success. Unknown,
// already-used, and expired tokens all return ("", "", false); the token is
// removed regardless so a single presentation is the only chance to use it.
func (s *Store) Consume(token string) (userID, issuedBy string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.byToken[token]
	if !ok {
		return "", "", false
	}

	s.remove(token, e)

	if s.now().After(e.expiresAt) {
		return "", "", false
	}

	return e.userID, e.issuedBy, true
}

// Peek is Consume without the invalidation. It decides nothing: a caller that
// acts on a token Consumes it first, so two presentations cannot both act.
// Expired tokens are removed and reported invalid.
func (s *Store) Peek(token string) (userID, issuedBy string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.byToken[token]
	if !ok {
		return "", "", false
	}
	if s.now().After(e.expiresAt) {
		s.remove(token, e)
		return "", "", false
	}

	return e.userID, e.issuedBy, true
}

// RevokeUser drops userID's outstanding token, if any. A change of the
// user's password by another path makes a link minted before it moot.
func (s *Store) RevokeUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if token, ok := s.byUser[userID]; ok {
		s.remove(token, s.byToken[token])
	}
}

// CleanUp drops every expired token. Expired tokens are otherwise removed
// only when presented or replaced, so links nobody opens would stay forever.
func (s *Store) CleanUp() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for token, e := range s.byToken {
		if now.After(e.expiresAt) {
			s.remove(token, e)
		}
	}
}

// remove deletes token, whose entry is e. The caller holds mu.
func (s *Store) remove(token string, e entry) {
	delete(s.byToken, token)
	if s.byUser[e.userID] == token {
		delete(s.byUser, e.userID)
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
