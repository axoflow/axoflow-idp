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

package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

type session struct {
	userID    string
	createdAt time.Time
	lastSeen  time.Time
}

// Config bounds a session's server-side lifetime. A zero TTL disables that
// check; the zero Config keeps sessions until explicitly deleted.
type Config struct {
	IdleTTL     time.Duration `json:"idleTTL,omitempty"`
	AbsoluteTTL time.Duration `json:"absoluteTTL,omitempty"`
}

type Session struct {
	mu       sync.RWMutex
	sessions map[string]session
	cfg      Config
	now      func() time.Time
}

func New(cfg Config) *Session {
	return &Session{
		sessions: map[string]session{},
		cfg:      cfg,
		now:      time.Now,
	}
}

func (s *Session) Create(userId string) string {
	now := s.now()
	id := newToken()
	ses := session{
		userID:    userId,
		createdAt: now,
		lastSeen:  now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = ses

	return id
}

// newToken returns a 256-bit crypto-random, URL-safe opaque session ID.
func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("session: failed to read random bytes: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Session) Get(sessionId string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionId]
	if !ok {
		return "", errors.New("session not found")
	}

	now := s.now()
	if s.expired(sess, now) {
		delete(s.sessions, sessionId)
		return "", errors.New("session expired")
	}

	if s.cfg.IdleTTL > 0 {
		sess.lastSeen = now
		s.sessions[sessionId] = sess
	}

	return sess.userID, nil
}

func (s *Session) expired(sess session, now time.Time) bool {
	if s.cfg.AbsoluteTTL > 0 && now.After(sess.createdAt.Add(s.cfg.AbsoluteTTL)) {
		return true
	}
	if s.cfg.IdleTTL > 0 && now.After(sess.lastSeen.Add(s.cfg.IdleTTL)) {
		return true
	}
	return false
}

func (s *Session) CleanUp() {
	if s.cfg.IdleTTL == 0 && s.cfg.AbsoluteTTL == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, sess := range s.sessions {
		if s.expired(sess, now) {
			delete(s.sessions, id)
		}
	}
}

func (s *Session) Delete(sessionId string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionId)
}

// DeleteUserSessions removes every session belonging to userID. It is used to
// log a user out of all devices after their password changes or is reset.
func (s *Session) DeleteUserSessions(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.userID == userID {
			delete(s.sessions, id)
		}
	}
}
