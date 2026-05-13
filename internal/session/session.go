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
	"errors"

	"github.com/oklog/ulid/v2"
)

type session struct {
	ID     ulid.ULID
	userID string
}

type Session struct {
	sessions map[string]session
}

func New() *Session {
	return &Session{
		sessions: map[string]session{},
	}
}

func (s *Session) Create(userId string) string {
	ses := session{
		ID:     ulid.Make(),
		userID: userId,
	}
	s.sessions[ses.ID.String()] = ses

	return ses.ID.String()
}

func (s *Session) Get(sessionId string) (string, error) {
	session, ok := s.sessions[sessionId]
	if !ok {
		return "", errors.New("session not found")
	}

	return session.userID, nil
}

func (s *Session) Delete(sessionId string) {
	delete(s.sessions, sessionId)
}
