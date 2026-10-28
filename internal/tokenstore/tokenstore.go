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

package tokenstore

import (
	"sync"
	"time"
)

type TokenStore struct {
	revokedTokens map[string]time.Time
	mu            sync.RWMutex
	ttl           time.Duration
}

// New keeps a revocation for ttl, the lifetime of the tokens it is asked about; a zero ttl keeps every one.
func New(ttl time.Duration) *TokenStore {
	return &TokenStore{
		revokedTokens: make(map[string]time.Time),
		mu:            sync.RWMutex{},
		ttl:           ttl,
	}
}

// Revoke records the token and drops the revocations older than the token lifetime: the list grows only
// here, and a token that old is refused by its own expiry.
func (s *TokenStore) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.prune(now)
	s.revokedTokens[token] = now
}

// CleanUp drops the revocations older than the token lifetime, as Revoke does, for a server that sees no
// revocation for a long time.
func (s *TokenStore) CleanUp() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.prune(time.Now())
}

// prune drops the revocations older than the token lifetime. The caller holds mu.
func (s *TokenStore) prune(now time.Time) {
	if s.ttl == 0 {
		return
	}
	for revoked, revokedAt := range s.revokedTokens {
		if now.Sub(revokedAt) > s.ttl {
			delete(s.revokedTokens, revoked)
		}
	}
}

func (s *TokenStore) IsRevoked(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.revokedTokens[token]
	return exists
}
