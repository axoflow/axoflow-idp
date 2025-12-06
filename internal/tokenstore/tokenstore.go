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

type Config struct {
	TTL time.Duration `json:"ttl,omitempty"`
}

type TokenStore struct {
	revokedTokens map[string]time.Time
	mu            sync.RWMutex
	ttl           time.Duration
}

func New(cfg Config) *TokenStore {
	return &TokenStore{
		revokedTokens: make(map[string]time.Time),
		mu:            sync.RWMutex{},
		ttl:           cfg.TTL,
	}
}

func (s *TokenStore) Revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.revokedTokens[token] = time.Now()
}

func (s *TokenStore) IsRevoked(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.revokedTokens[token]
	return exists
}

func (s *TokenStore) CleanUp() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for token, revokedAt := range s.revokedTokens {
		if now.Sub(revokedAt) > s.ttl {
			delete(s.revokedTokens, token)
		}
	}
}
