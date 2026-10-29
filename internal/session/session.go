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
	"errors"
	"sync"
	"time"
)

// MaxPerUser bounds the sessions one user holds: every login adds one and
// nothing else removes them before they expire, so without it a user who
// signs in in a loop grows the store without limit.
const MaxPerUser = 50

// Config bounds a session's server-side lifetime. A zero TTL disables that
// bound; the zero Config keeps a session until it is deleted.
type Config struct {
	// IdleTTL ends a session not used for this long.
	IdleTTL time.Duration
	// AbsoluteTTL ends a session this long after it was created, used or not.
	AbsoluteTTL time.Duration
}

type session struct {
	userID    string
	createdAt time.Time
	lastSeen  time.Time
}

type Session struct {
	mu       sync.Mutex
	cfg      Config
	now      func() time.Time
	sessions map[string]session
	byUser   map[string]map[string]struct{} // userID -> its session ids
}

func New(cfg Config) *Session {
	return &Session{
		cfg:      cfg,
		now:      time.Now,
		sessions: map[string]session{},
		byUser:   map[string]map[string]struct{}{},
	}
}

func (s *Session) Create(userId string) string {
	// the id is the cookie's whole credential, so it comes from crypto/rand: a ULID's entropy is math/rand
	id := rand.Text()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Expired sessions go first, or the cap would evict a live one for them.
	// That can empty the user's index and drop it, so look it up afterwards.
	now := s.now()
	for id := range s.byUser[userId] {
		if s.expired(s.sessions[id], now) {
			s.remove(id)
		}
	}
	ids := s.byUser[userId]
	if ids == nil {
		ids = map[string]struct{}{}
		s.byUser[userId] = ids
	}
	if len(ids) >= MaxPerUser {
		s.evictOldest(ids)
	}

	s.sessions[id] = session{userID: userId, createdAt: now, lastSeen: now}
	ids[id] = struct{}{}

	return id
}

// evictOldest deletes the oldest of ids. The caller holds mu.
func (s *Session) evictOldest(ids map[string]struct{}) {
	var oldest string
	for id := range ids {
		if oldest == "" || s.sessions[id].createdAt.Before(s.sessions[oldest].createdAt) {
			oldest = id
		}
	}
	s.remove(oldest)
}

func (s *Session) Get(sessionId string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ses, ok := s.sessions[sessionId]
	if !ok {
		return "", errors.New("session not found")
	}

	now := s.now()
	if s.expired(ses, now) {
		s.remove(sessionId)
		return "", errors.New("session expired")
	}
	if s.cfg.IdleTTL > 0 {
		ses.lastSeen = now
		s.sessions[sessionId] = ses
	}

	return ses.userID, nil
}

func (s *Session) expired(ses session, now time.Time) bool {
	if s.cfg.AbsoluteTTL > 0 && now.After(ses.createdAt.Add(s.cfg.AbsoluteTTL)) {
		return true
	}
	return s.cfg.IdleTTL > 0 && now.After(ses.lastSeen.Add(s.cfg.IdleTTL))
}

// CleanUp deletes every expired session. Get deletes an expired session it is
// asked about; this catches the ones whose cookie never comes back.
func (s *Session) CleanUp() {
	if s.cfg.IdleTTL == 0 && s.cfg.AbsoluteTTL == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for id, ses := range s.sessions {
		if s.expired(ses, now) {
			s.remove(id)
		}
	}
}

func (s *Session) Delete(sessionId string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.remove(sessionId)
}

// DeleteUserSessions removes every session belonging to userID. It is used to
// log a user out of all devices after their password changes or is reset.
func (s *Session) DeleteUserSessions(userID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.byUser[userID] {
		delete(s.sessions, id)
	}
	delete(s.byUser, userID)
}

// remove deletes the session id, if any. The caller holds mu.
func (s *Session) remove(id string) {
	ses, ok := s.sessions[id]
	if !ok {
		return
	}
	delete(s.sessions, id)
	ids := s.byUser[ses.userID]
	delete(ids, id)
	if len(ids) == 0 {
		delete(s.byUser, ses.userID)
	}
}
