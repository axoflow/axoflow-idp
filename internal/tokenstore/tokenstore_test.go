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

package tokenstore

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRevokeDropsRevocationsOlderThanTheTokenLifetime(t *testing.T) {
	s := New(time.Minute)
	s.revokedTokens["stale"] = time.Now().Add(-2 * time.Minute)
	s.revokedTokens["fresh"] = time.Now()

	s.Revoke("new")

	if s.IsRevoked("stale") {
		t.Error("a revocation older than the token lifetime survived Revoke")
	}
	for _, token := range []string{"fresh", "new"} {
		if !s.IsRevoked(token) {
			t.Errorf("%q is not revoked", token)
		}
	}
}

func TestRevokeKeepsEveryRevocationWithoutALifetime(t *testing.T) {
	s := New(0)
	s.revokedTokens["old"] = time.Now().Add(-24 * time.Hour)

	s.Revoke("new")

	if !s.IsRevoked("old") {
		t.Error("a zero lifetime must keep every revocation")
	}
}

func TestCleanUpDropsRevocationsOlderThanTheTokenLifetime(t *testing.T) {
	s := New(time.Minute)
	s.revokedTokens["stale"] = time.Now().Add(-2 * time.Minute)
	s.revokedTokens["fresh"] = time.Now()

	s.CleanUp()

	if s.IsRevoked("stale") {
		t.Error("a revocation older than the token lifetime survived CleanUp")
	}
	if !s.IsRevoked("fresh") {
		t.Error("a revocation within the token lifetime was dropped")
	}
}

// A store opened on a file refuses after a restart what was revoked before
// it, and the file is owner-only.
func TestOpenKeepsRevocationsAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocations.json")
	s, err := Open(time.Hour, path)
	if err != nil {
		t.Fatalf("Open a missing file: %v", err)
	}
	s.Revoke("jti-1")

	restarted, err := Open(time.Hour, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !restarted.IsRevoked("jti-1") {
		t.Error("the revocation was lost with the restart")
	}
	if restarted.IsRevoked("jti-2") {
		t.Error("a token never revoked is revoked")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("revocations file mode = %o, want 600", mode)
	}
}

func TestOpenDropsRevocationsOlderThanTheTokenLifetime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocations.json")
	saved := map[string]time.Time{"stale": time.Now().Add(-2 * time.Hour), "fresh": time.Now().Add(-time.Minute)}
	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	s, err := Open(time.Hour, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if s.IsRevoked("stale") {
		t.Error("a revocation older than the token lifetime was loaded")
	}
	if !s.IsRevoked("fresh") {
		t.Error("a revocation within the token lifetime was not loaded")
	}
}

func TestOpenRefusesWhatItCannotUse(t *testing.T) {
	dir := t.TempDir()
	malformed := filepath.Join(dir, "malformed.json")
	if err := os.WriteFile(malformed, []byte(`{"jti":`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	for name, path := range map[string]string{
		"a malformed file":    malformed,
		"a missing directory": filepath.Join(dir, "missing", "revocations.json"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Open(time.Hour, path); err == nil {
				t.Error("Open succeeded")
			}
		})
	}
}

// A revocation that cannot be written is still refused until a restart, and
// the failure is logged.
func TestRevokeKeepsARevocationItCannotWrite(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(time.Hour, filepath.Join(dir, "revocations.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if f, err := os.CreateTemp(dir, "probe"); err == nil {
		_ = f.Close()
		t.Skip("directory permissions are not enforced (running as root?)")
	}
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(old) })

	s.Revoke("jti-1")

	if !s.IsRevoked("jti-1") {
		t.Error("the revocation was dropped with the failed write")
	}
	if n := strings.Count(logs.String(), `"level":"ERROR"`); n != 1 {
		t.Errorf("%d errors logged, want 1:\n%s", n, logs.String())
	}
}
