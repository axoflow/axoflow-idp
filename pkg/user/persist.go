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

package user

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
)

// ErrPersist is wrapped by every mutating operation that could not write the
// user database. The change is not applied: memory and the file both keep the
// state before it. The wrapped cause can name the file path, so routes log it
// and show a generic message.
var ErrPersist = errors.New("could not save the user database")

// fileSystem is what writeFile goes through; tests swap in one that fails at a
// chosen step.
type fileSystem interface {
	CreateTemp(dir, pattern string) (tempFile, error)
	Rename(oldpath, newpath string) error
	Remove(name string) error
	SyncDir(dir string) error
}

type tempFile interface {
	Name() string
	Chmod(mode fs.FileMode) error
	Write(b []byte) (int, error)
	Sync() error
	Close() error
}

type osFileSystem struct{}

func (osFileSystem) CreateTemp(dir, pattern string) (tempFile, error) {
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (osFileSystem) Rename(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }

func (osFileSystem) Remove(name string) error { return os.Remove(name) }

func (osFileSystem) SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if closeErr := d.Close(); err == nil {
		err = closeErr
	}
	return err
}

// testBeforeUpdate, when a test sets it, runs as a writer enters update:
// after the writer's early checks, before it takes saveMu. Tests use it to
// hold a writer there while another commits. Nil in production.
var testBeforeUpdate func()

// update runs change on a copy of the users that it owns and commits what
// change returns. Holding saveMu throughout means the copy is still the
// committed state when the result is published, so a check change makes (an
// admin's authority, a free username) cannot be overtaken by another writer.
func (u *User) update(change func(users []UserInfo) ([]UserInfo, error)) error {
	if testBeforeUpdate != nil {
		testBeforeUpdate()
	}
	u.saveMu.Lock()
	defer u.saveMu.Unlock()

	users, err := change(u.snapshot())
	if err != nil {
		return err
	}
	return u.commit(users)
}

// snapshot is a deep copy of the published users, owned by the caller.
func (u *User) snapshot() []UserInfo {
	u.mu.RLock()
	defer u.mu.RUnlock()

	users := make([]UserInfo, len(u.users))
	for i, user := range u.users {
		user.Groups = slices.Clone(user.Groups)
		users[i] = user
	}
	return users
}

// commit writes users to FilePath and then publishes them. The caller holds
// saveMu and owns users. A memory-only database publishes without writing.
func (u *User) commit(users []UserInfo) error {
	if u.FilePath != "" {
		if err := u.writeFile(users); err != nil {
			return err
		}
	}

	u.mu.Lock()
	u.users = users
	u.mu.Unlock()
	return nil
}

// writeFile replaces FilePath with users. The rename is the commit boundary:
// a failure before it removes the temp file and returns ErrPersist with the
// old file in place. After it a normal restart loads the new file, so a
// failure to sync the directory is only logged and the write counts as done,
// though the change may then not survive a crash.
func (u *User) writeFile(users []UserInfo) error {
	data, err := json.Marshal(users)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPersist, err)
	}

	fsys := u.fsys
	if fsys == nil {
		fsys = osFileSystem{}
	}
	dir := filepath.Dir(u.FilePath)

	// A fresh name created with O_EXCL: a fixed one could be a planted symlink.
	tmp, err := fsys.CreateTemp(dir, ".users-*.json")
	if err != nil {
		return fmt.Errorf("%w: create temp file: %w", ErrPersist, err)
	}
	err = writeTemp(tmp, data)
	if err == nil {
		err = fsys.Rename(tmp.Name(), u.FilePath)
	}
	if err != nil {
		if removeErr := fsys.Remove(tmp.Name()); removeErr != nil {
			slog.Warn("failed to remove temp user file", "path", tmp.Name(), "error", removeErr)
		}
		return fmt.Errorf("%w: %w", ErrPersist, err)
	}

	if err := fsys.SyncDir(dir); err != nil {
		slog.Warn("user database written but its directory could not be synced; the change may not survive a crash", "path", u.FilePath, "error", err)
	}
	return nil
}

// writeTemp fills tmp with data, flushed to disk, and closes it. The file
// holds password hashes, so it is owner-only whatever the umask.
func writeTemp(tmp tempFile, data []byte) error {
	var err error
	if err = tmp.Chmod(0o600); err != nil {
		err = fmt.Errorf("chmod temp file: %w", err)
	} else if _, err = tmp.Write(data); err != nil {
		err = fmt.Errorf("write temp file: %w", err)
	} else if err = tmp.Sync(); err != nil {
		err = fmt.Errorf("sync temp file: %w", err)
	}
	if closeErr := tmp.Close(); err == nil && closeErr != nil {
		err = fmt.Errorf("close temp file: %w", closeErr)
	}
	return err
}
