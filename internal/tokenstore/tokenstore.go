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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type TokenStore struct {
	revokedTokens map[string]time.Time
	mu            sync.RWMutex
	ttl           time.Duration

	// filePath, when set, holds the revocations as jti -> revokedAt, so a
	// restart still refuses a revoked token. Lock order: saveMu, then mu.
	filePath string
	saveMu   sync.Mutex // serializes the writes of filePath
}

// New keeps a revocation for ttl, the lifetime of the tokens it is asked about; a zero ttl keeps every one.
func New(ttl time.Duration) *TokenStore {
	return &TokenStore{
		revokedTokens: make(map[string]time.Time),
		mu:            sync.RWMutex{},
		ttl:           ttl,
	}
}

// Open is New keeping the revocations in filePath too. It loads what the file holds, a missing file
// holding none, without the revocations older than ttl; every Revoke writes the whole set back.
func Open(ttl time.Duration, filePath string) (*TokenStore, error) {
	// as users.filePath, a directory that is not there fails the start, not the first revocation
	if info, err := os.Stat(filepath.Dir(filePath)); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("revocations file %q: its directory does not exist", filePath)
	}
	s := New(ttl)
	s.filePath = filePath
	saved, err := load(filePath)
	if err != nil {
		return nil, err
	}
	maps.Copy(s.revokedTokens, saved)
	s.prune(time.Now())
	return s, nil
}

// maxRevocationsFile bounds what Open reads, so a damaged or oversized file cannot exhaust memory at
// start. A revocation takes about 64 bytes, so 16 MiB holds some 260,000 of them.
const maxRevocationsFile = 16 << 20

// load reads the revocations filePath holds, none for a missing file. A file it cannot use in full
// fails the start: loading part of it, or nothing, would accept revoked tokens again.
func load(filePath string) (map[string]time.Time, error) {
	f, err := os.Open(filePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read revocations file: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxRevocationsFile))
	if err != nil {
		return nil, fmt.Errorf("read revocations file: %w", err)
	}
	if len(data) >= maxRevocationsFile {
		return nil, fmt.Errorf("revocations file %q is %d bytes or more; remove expired revocations or the file", filePath, maxRevocationsFile)
	}
	var saved map[string]time.Time
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("revocations file %q is malformed: %w", filePath, err)
	}
	// null decodes without an error, to no map or to the zero time, and the zero time is pruned at
	// once: both would drop revocations silently
	if saved == nil {
		return nil, fmt.Errorf("revocations file %q is malformed: null, want an object", filePath)
	}
	for _, revokedAt := range saved {
		if revokedAt.IsZero() {
			return nil, fmt.Errorf("revocations file %q is malformed: an entry has no revocation time", filePath)
		}
	}
	return saved, nil
}

// Revoke records the token and drops the revocations older than the token lifetime: the list grows only
// here, and a token that old is refused by its own expiry. With a file, a revocation that cannot be
// written is still refused until a restart; the failure is logged, and the next Revoke writes it again.
func (s *TokenStore) Revoke(token string) {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.Lock()
	now := time.Now()
	s.prune(now)
	s.revokedTokens[token] = now
	var data []byte
	var err error
	if s.filePath != "" {
		data, err = json.Marshal(s.revokedTokens)
	}
	s.mu.Unlock()

	if s.filePath == "" {
		return
	}
	if err == nil {
		err = writeFile(s.filePath, data)
	}
	if err != nil {
		slog.Error("revocation not saved: a restart accepts the token again until it expires", "path", s.filePath, "error", err)
	}
}

// writeFile replaces path with data as pkg/user's writeFile replaces users.json: a fresh owner-only
// temp file in the same directory, synced, renamed over path, then the directory synced. The rename
// is the commit; before it the old file stays in place.
func writeFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	// a fresh name created with O_EXCL: a fixed one could be a planted symlink
	tmp, err := os.CreateTemp(dir, ".revocations-*.json")
	if err != nil {
		return err
	}
	if err = tmp.Chmod(0o600); err == nil {
		if _, err = tmp.Write(data); err == nil {
			err = tmp.Sync()
		}
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	d, err := os.Open(dir)
	if err == nil {
		err = d.Sync()
		_ = d.Close()
	}
	if err != nil {
		slog.Warn("revocations written but their directory could not be synced; the change may not survive a crash", "path", path, "error", err)
	}
	return nil
}

// CleanUp drops the revocations older than the token lifetime, as Revoke does, for a server that sees no
// revocation for a long time. It prunes memory only; the next Revoke rewrites the file.
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
