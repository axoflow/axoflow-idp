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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func padded(size int) string {
	return "{}" + strings.Repeat(" ", size-2)
}

func TestOpenRefusesWhatItCannotUse(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"a malformed file":      `{"jti":`,
		"a null root":           `null`,
		"a null timestamp":      `{"jti-1":"2026-10-29T12:00:00Z","jti-2":null}`,
		"a zero timestamp":      `{"jti-1":"0001-01-01T00:00:00Z"}`,
		"a file at the bound":   padded(maxRevocationsFile),
		"a file over the bound": padded(maxRevocationsFile + 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := Open(0, path); err == nil {
				t.Error("Open succeeded")
			}
		})
	}
	t.Run("a missing directory", func(t *testing.T) {
		if _, err := Open(time.Hour, filepath.Join(dir, "missing", "revocations.json")); err == nil {
			t.Error("Open succeeded")
		}
	})
}

func TestOpenAcceptsAnEmptySet(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"an empty object":             `{}`,
		"a file just under the bound": padded(maxRevocationsFile - 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name+".json")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			s, err := Open(time.Hour, path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if n := len(s.revokedTokens); n != 0 {
				t.Errorf("%d revocations loaded, want 0", n)
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

var errInjected = errors.New("injected failure")

// failingFS fails the write at step: write, sync, close, rename or syncdir.
type failingFS struct {
	osFileSystem
	step         string
	beforeRename func()
}

func (f *failingFS) CreateTemp(dir, pattern string) (tempFile, error) {
	tmp, err := f.osFileSystem.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return &failingFile{tempFile: tmp, step: f.step}, nil
}

func (f *failingFS) Rename(oldpath, newpath string) error {
	if f.beforeRename != nil {
		f.beforeRename()
	}
	if f.step == "rename" {
		return errInjected
	}
	return f.osFileSystem.Rename(oldpath, newpath)
}

func (f *failingFS) SyncDir(dir string) error {
	if f.step == "syncdir" {
		return errInjected
	}
	return f.osFileSystem.SyncDir(dir)
}

type failingFile struct {
	tempFile
	step string
}

func (f *failingFile) Write(b []byte) (int, error) {
	if f.step == "write" {
		return 0, errInjected
	}
	return f.tempFile.Write(b)
}

func (f *failingFile) Sync() error {
	if f.step == "sync" {
		return errInjected
	}
	return f.tempFile.Sync()
}

func (f *failingFile) Close() error {
	err := f.tempFile.Close()
	if f.step == "close" {
		return errInjected
	}
	return err
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &logs
}

func openRevoked(t *testing.T, path string, tokens ...string) {
	t.Helper()
	s, err := Open(time.Hour, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, token := range tokens {
		if !s.IsRevoked(token) {
			t.Errorf("%q is not revoked after a restart", token)
		}
	}
}

// A write that fails before its rename leaves the file as it was, keeps the
// revocation in memory and logs one error; the next Revoke writes it.
func TestRevokeKeepsTheOldFileWhenAWriteFails(t *testing.T) {
	for _, step := range []string{"write", "sync", "close", "rename"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "revocations.json")
			s, err := Open(time.Hour, path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			fsys := &failingFS{}
			s.fsys = fsys
			s.Revoke("jti-0")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			logs := captureLogs(t)

			fsys.step = step
			s.Revoke("jti-1")

			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
				t.Errorf("file after the failed write = %q (%v), want it unchanged %q", after, err, before)
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
				t.Errorf("directory holds %v (%v), want the revocations file only", entries, err)
			}
			if !s.IsRevoked("jti-1") {
				t.Error("the revocation was dropped with the failed write")
			}
			if n := strings.Count(logs.String(), `"level":"ERROR"`); n != 1 {
				t.Errorf("%d errors logged, want 1:\n%s", n, logs.String())
			}

			fsys.step = ""
			s.Revoke("jti-2")
			openRevoked(t, path, "jti-0", "jti-1", "jti-2")
		})
	}
}

// After the rename the write is done: a directory that cannot be synced is a
// warning, not a failed revocation.
func TestRevokeOnlyWarnsWhenTheDirectoryCannotBeSynced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocations.json")
	s, err := Open(time.Hour, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	s.fsys = &failingFS{step: "syncdir"}
	logs := captureLogs(t)

	s.Revoke("jti-1")

	if n := strings.Count(logs.String(), `"level":"ERROR"`); n != 0 {
		t.Errorf("%d errors logged, want 0:\n%s", n, logs.String())
	}
	if n := strings.Count(logs.String(), `"level":"WARN"`); n != 1 {
		t.Errorf("%d warnings logged, want 1:\n%s", n, logs.String())
	}
	openRevoked(t, path, "jti-1")
}

// The first write is held at its rename until the others are done: if the
// writes overlapped, its older snapshot would replace theirs. Serialized,
// the others wait for it and the hold ends at its timeout.
func TestOverlappingWritesKeepEveryRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revocations.json")
	s, err := Open(time.Hour, path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	inRename, othersDone, firstDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.fsys = &failingFS{beforeRename: func() {
		first := false
		once.Do(func() { first = true })
		if !first {
			return
		}
		close(inRename)
		select {
		case <-othersDone:
		case <-time.After(200 * time.Millisecond):
		}
	}}

	go func() {
		s.Revoke("first")
		close(firstDone)
	}()
	select {
	case <-inRename:
	case <-time.After(5 * time.Second):
		t.Fatal("the first write never reached its rename")
	}
	want := []string{"first"}
	var wg sync.WaitGroup
	for i := range 8 {
		token := fmt.Sprintf("jti-%d", i)
		want = append(want, token)
		wg.Add(2)
		go func() {
			defer wg.Done()
			s.Revoke(token)
		}()
		go func() {
			defer wg.Done()
			s.CleanUp()
		}()
	}
	go func() {
		wg.Wait()
		close(othersDone)
	}()
	<-firstDone
	wg.Wait()

	openRevoked(t, path, want...)
}
