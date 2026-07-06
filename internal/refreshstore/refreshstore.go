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

// Package refreshstore holds OAuth 2.0 refresh tokens as opaque, rotating,
// server-side secrets. Tokens rotate on every use; replaying a consumed token
// after a short leeway window revokes the whole token family (reuse detection
// per the OAuth 2.0 Security BCP). State is in-memory and cleared on restart.
package refreshstore

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const (
	defaultIdleTTL     = 168 * time.Hour
	defaultAbsoluteTTL = 720 * time.Hour
	defaultReuseLeeway = 10 * time.Second
	tokenBytes         = 32
)

// ErrInvalidGrant is returned for any unusable token (unknown, expired,
// client-mismatched, or revoked). It maps to the OAuth invalid_grant error.
var ErrInvalidGrant = errors.New("invalid_grant")

type Config struct {
	IdleTTL     time.Duration `json:"idleTTL,omitempty"`
	AbsoluteTTL time.Duration `json:"absoluteTTL,omitempty"`
	ReuseLeeway time.Duration `json:"reuseLeeway,omitempty"`
}

// Grant is the identity re-minted on each refresh. Scopes is the originally
// granted scope, echoed unchanged on every rotation.
type Grant struct {
	UserID   string
	ClientID string
	Scopes   []string
}

type entry struct {
	familyID   string
	grant      Grant
	idleExpiry time.Time
	consumed   bool
	consumedAt time.Time
	successor  string
}

type family struct {
	userID         string
	absoluteExpiry time.Time
	members        map[string]struct{}
}

type Store struct {
	mu       sync.Mutex
	cfg      Config
	now      func() time.Time
	byToken  map[string]*entry
	byFamily map[string]*family
}

func New(cfg Config) *Store {
	if cfg.IdleTTL == 0 {
		cfg.IdleTTL = defaultIdleTTL
	}
	if cfg.AbsoluteTTL == 0 {
		cfg.AbsoluteTTL = defaultAbsoluteTTL
	}
	if cfg.ReuseLeeway == 0 {
		cfg.ReuseLeeway = defaultReuseLeeway
	}
	return &Store{
		cfg:      cfg,
		now:      time.Now,
		byToken:  map[string]*entry{},
		byFamily: map[string]*family{},
	}
}

// IdleTTL returns the effective sliding idle lifetime.
func (s *Store) IdleTTL() time.Duration { return s.cfg.IdleTTL }

// AbsoluteTTL returns the effective absolute family lifetime.
func (s *Store) AbsoluteTTL() time.Duration { return s.cfg.AbsoluteTTL }

func randomToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Issue starts a new token family for the grant and returns its head token.
func (s *Store) Issue(g Grant) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	familyID, err := randomToken()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanUp()

	now := s.now()
	s.byFamily[familyID] = &family{
		userID:         g.UserID,
		absoluteExpiry: now.Add(s.cfg.AbsoluteTTL),
		members:        map[string]struct{}{token: {}},
	}
	s.byToken[token] = &entry{
		familyID:   familyID,
		grant:      g,
		idleExpiry: now.Add(s.cfg.IdleTTL),
	}

	return token, nil
}

// Rotate consumes token and returns its grant plus a fresh successor token.
// Reuse detection runs before expiry, so a stolen-then-expired token still
// revokes its family. A consumed token replayed within ReuseLeeway returns the
// existing successor idempotently; replayed later it revokes the family.
func (s *Store) Rotate(token, clientID string) (Grant, string, error) {
	successor, err := randomToken()
	if err != nil {
		return Grant{}, "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.byToken[token]
	if !ok {
		return Grant{}, "", ErrInvalidGrant
	}
	fam, ok := s.byFamily[e.familyID]
	if !ok {
		return Grant{}, "", ErrInvalidGrant
	}

	// Client binding is checked before anything else so a client presenting
	// another client's token can neither obtain its successor nor force-revoke
	// its family.
	if e.grant.ClientID != clientID {
		return Grant{}, "", ErrInvalidGrant
	}

	now := s.now()

	if e.consumed {
		if now.Sub(e.consumedAt) <= s.cfg.ReuseLeeway {
			if succ, ok := s.byToken[e.successor]; ok && !succ.consumed {
				return e.grant, e.successor, nil
			}
		}
		s.revokeFamily(e.familyID)
		return Grant{}, "", ErrInvalidGrant
	}

	if now.After(fam.absoluteExpiry) || now.After(e.idleExpiry) {
		return Grant{}, "", ErrInvalidGrant
	}

	e.consumed = true
	e.consumedAt = now
	e.successor = successor

	idleExpiry := now.Add(s.cfg.IdleTTL)
	if idleExpiry.After(fam.absoluteExpiry) {
		idleExpiry = fam.absoluteExpiry
	}
	s.byToken[successor] = &entry{
		familyID:   e.familyID,
		grant:      e.grant,
		idleExpiry: idleExpiry,
	}
	fam.members[successor] = struct{}{}

	return e.grant, successor, nil
}

// Revoke kills the whole family a token belongs to, but only if clientID owns
// it. Returns whether a matching, owned token was found.
func (s *Store) Revoke(token, clientID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.byToken[token]
	if !ok || e.grant.ClientID != clientID {
		return false
	}
	s.revokeFamily(e.familyID)
	return true
}

// RevokeUser kills every family belonging to userID.
func (s *Store) RevokeUser(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for fid, fam := range s.byFamily {
		if fam.userID == userID {
			s.removeFamily(fid, fam)
		}
	}
}

func (s *Store) cleanUp() {
	now := s.now()
	for fid, fam := range s.byFamily {
		if now.After(fam.absoluteExpiry) {
			s.removeFamily(fid, fam)
		}
	}
}

func (s *Store) revokeFamily(familyID string) {
	if fam, ok := s.byFamily[familyID]; ok {
		s.removeFamily(familyID, fam)
	}
}

func (s *Store) removeFamily(familyID string, fam *family) {
	for tok := range fam.members {
		delete(s.byToken, tok)
	}
	delete(s.byFamily, familyID)
}
