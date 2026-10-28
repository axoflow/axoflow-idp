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

package user

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
)

// persistFixture is a database with an admin (alice, password alicepass1), a
// second admin (carol) and a user (bob, password bobpass123).
func persistFixture(t *testing.T) (*User, string) {
	t.Helper()
	users, err := json.Marshal([]UserInfo{
		{ID: "alice", Username: "alice", Password: hash([]byte("alice"), "alicepass1"), Groups: []string{"admins"}},
		{ID: "bob", Username: "bob", Password: hash([]byte("bob"), "bobpass123"), Groups: []string{RoleUser}, Email: "bob@example.com"},
		{ID: "carol", Username: "carol", Groups: []string{"admins"}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := writeUsersFile(t, string(users))
	u, err := New(Config{FilePath: path, UserAdminGroup: "admins", SelfRegistration: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return u, path
}

func readUsers(t *testing.T, path string) []UserInfo {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read users file: %v", err)
	}
	var users []UserInfo
	if err := json.Unmarshal(data, &users); err != nil {
		t.Fatalf("users file: %v", err)
	}
	return users
}

// memory is the published slice; callers make sure no writer is running.
func memory(u *User) []UserInfo {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return slices.Clone(u.users)
}

// mutators are every operation that changes the database, each expected to
// succeed on persistFixture.
var mutators = []struct {
	name string
	run  func(u *User) error
}{
	{"SelfRegister", func(u *User) error {
		_, err := u.SelfRegister("dave", "davepass1", []string{RoleUser}, "dave@example.com")
		return err
	}},
	{"Register", func(u *User) error { return u.Register("dave", "davepass1", nil, "") }},
	{"RegisterLocked", func(u *User) error { _, err := u.RegisterLocked("dave", nil, ""); return err }},
	{"AdminRegister", func(u *User) error { return u.AdminRegister("alice", "dave", "davepass1", nil, "") }},
	{"AdminRegisterLocked", func(u *User) error { _, err := u.AdminRegisterLocked("alice", "dave", nil, ""); return err }},
	{"ChangePassword", func(u *User) error { return u.ChangePassword("bob", "bobpass123", "newpass123") }},
	{"SetPassword", func(u *User) error { return u.SetPassword("bob", "newpass123") }},
	{"AdminDelete", func(u *User) error { return u.AdminDelete("alice", "bob") }},
	{"AdminResetPassword", func(u *User) error { return u.AdminResetPassword("alice", "bob", "newpass123") }},
	{"AdminUpdateUserGroups", func(u *User) error { return u.AdminUpdateUserGroups("alice", "bob", []string{"ops"}) }},
}

// Each mutator writes its own change, owner-only, so memory and the file
// never disagree and no caller has to remember to save.
func TestMutatorsPersist(t *testing.T) {
	for _, m := range mutators {
		t.Run(m.name, func(t *testing.T) {
			u, path := persistFixture(t)
			before := memory(u)

			if err := m.run(u); err != nil {
				t.Fatalf("%s: %v", m.name, err)
			}

			got := memory(u)
			if reflect.DeepEqual(got, before) {
				t.Fatal("memory unchanged after a successful mutation")
			}
			if disk := readUsers(t, path); !reflect.DeepEqual(disk, got) {
				t.Errorf("file differs from memory:\nfile   %+v\nmemory %+v", disk, got)
			}
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("users file mode = %o, want 600", perm)
			}
		})
	}
}

// A fixed temp name next to users.json could be a planted symlink, and the
// write would follow it.
func TestSaveUsers_DoesNotFollowPlantedTempLink(t *testing.T) {
	u, path := persistFixture(t)
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o600); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	if err := os.Symlink(victim, path+"~"); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := u.SaveUsers(); err != nil {
		t.Fatalf("SaveUsers: %v", err)
	}

	if data, _ := os.ReadFile(victim); string(data) != "untouched" {
		t.Errorf("symlink target overwritten: %q", data)
	}
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		t.Errorf("users file is not a regular file: %v, %v", info, err)
	}
}

// Two admins demoting each other: the admin check and the change must be one
// step, or both succeed and nobody is left to administer the database.
func TestAdminsDemotingEachOther(t *testing.T) {
	for range 50 {
		u, path := persistFixture(t)

		var wg sync.WaitGroup
		var errAlice, errCarol error
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			errAlice = u.AdminUpdateUserGroups("alice", "carol", []string{RoleUser})
		}()
		go func() {
			defer wg.Done()
			<-start
			errCarol = u.AdminUpdateUserGroups("carol", "alice", []string{RoleUser})
		}()
		close(start)
		wg.Wait()

		if (errAlice == nil) == (errCarol == nil) {
			t.Fatalf("want exactly one demotion to succeed, got %v and %v", errAlice, errCarol)
		}
		for _, users := range [][]UserInfo{memory(u), readUsers(t, path)} {
			if !slices.ContainsFunc(users, func(ui UserInfo) bool { return u.IsAdmin(&ui) }) {
				t.Fatalf("no admin left: %+v", users)
			}
		}
	}
}

// Concurrent writers each start from the last committed state, so after they
// finish memory holds every change and matches the file.
func TestConcurrentWritersMatchDisk(t *testing.T) {
	u, path := persistFixture(t)

	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers * 3)
	for i := range workers {
		go func() {
			defer wg.Done()
			if _, err := u.RegisterLocked("user"+string(rune('a'+i)), nil, ""); err != nil {
				t.Errorf("RegisterLocked: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := u.AdminUpdateUserGroups("alice", "bob", []string{"ops", string(rune('a' + i))}); err != nil {
				t.Errorf("AdminUpdateUserGroups: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			if err := u.SaveUsers(); err != nil {
				t.Errorf("SaveUsers: %v", err)
			}
		}()
	}
	wg.Wait()

	got := memory(u)
	if len(got) != 3+workers {
		t.Errorf("memory holds %d users, want %d", len(got), 3+workers)
	}
	if disk := readUsers(t, path); !reflect.DeepEqual(disk, got) {
		t.Errorf("file differs from memory:\nfile   %+v\nmemory %+v", disk, got)
	}
}

// users.json holds password hashes: every write leaves it owner-only,
// whatever the umask or the mode of the file it replaces.
func TestSaveUsers_OwnerOnly(t *testing.T) {
	u, path := persistFixture(t)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if err := u.SaveUsers(); err != nil {
		t.Fatalf("SaveUsers: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("users file mode = %o, want 600", perm)
	}
}

var errInjected = errors.New("injected failure")

// faultFS fails the step named by fail and hands everything else to the OS.
type faultFS struct {
	osFileSystem
	fail string
}

func (f faultFS) CreateTemp(dir, pattern string) (tempFile, error) {
	if f.fail == "create" {
		return nil, errInjected
	}
	tmp, err := f.osFileSystem.CreateTemp(dir, pattern)
	if err != nil {
		return nil, err
	}
	return faultFile{tempFile: tmp, fail: f.fail}, nil
}

func (f faultFS) Rename(oldpath, newpath string) error {
	if f.fail == "rename" {
		return errInjected
	}
	return f.osFileSystem.Rename(oldpath, newpath)
}

func (f faultFS) SyncDir(dir string) error {
	if f.fail == "sync dir" {
		return errInjected
	}
	return f.osFileSystem.SyncDir(dir)
}

type faultFile struct {
	tempFile
	fail string
}

func (f faultFile) Chmod(mode fs.FileMode) error {
	if f.fail == "chmod" {
		return errInjected
	}
	return f.tempFile.Chmod(mode)
}

func (f faultFile) Write(b []byte) (int, error) {
	if f.fail == "write" {
		// A short write: half the data reaches the temp file.
		n, _ := f.tempFile.Write(b[:len(b)/2])
		return n, errInjected
	}
	return f.tempFile.Write(b)
}

func (f faultFile) Sync() error {
	if f.fail == "sync file" {
		return errInjected
	}
	return f.tempFile.Sync()
}

func (f faultFile) Close() error {
	err := f.tempFile.Close()
	if f.fail == "close" {
		return errInjected
	}
	return err
}

func dirEntries(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// The rename is the commit boundary: a failure before it leaves memory and the
// file as they were; once the file is installed, memory follows it even if
// the directory cannot be synced.
func TestCommit_Faults(t *testing.T) {
	tests := []struct {
		fail          string
		wantCommitted bool
	}{
		{fail: "create"},
		{fail: "chmod"},
		{fail: "write"},
		{fail: "sync file"},
		{fail: "close"},
		{fail: "rename"},
		{fail: "sync dir", wantCommitted: true},
		{fail: "none", wantCommitted: true},
	}

	for _, tt := range tests {
		t.Run(tt.fail, func(t *testing.T) {
			u, path := persistFixture(t)
			u.fsys = faultFS{fail: tt.fail}
			before := memory(u)

			err := u.AdminUpdateUserGroups("alice", "bob", []string{"ops"})

			got := memory(u)
			if tt.wantCommitted {
				if err != nil {
					t.Fatalf("AdminUpdateUserGroups: %v", err)
				}
				if bob, _ := u.Get("bob"); !slices.Equal(bob.Groups, []string{"ops"}) {
					t.Errorf("bob's groups = %v, want [ops]", bob.Groups)
				}
			} else {
				if !errors.Is(err, ErrPersist) || !errors.Is(err, errInjected) {
					t.Fatalf("error = %v, want ErrPersist wrapping the injected failure", err)
				}
				if !reflect.DeepEqual(got, before) {
					t.Errorf("memory changed:\nbefore %+v\nafter  %+v", before, got)
				}
			}
			reloaded, err := New(Config{FilePath: path})
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			if disk := memory(reloaded); !reflect.DeepEqual(disk, got) {
				t.Errorf("reloaded file differs from memory:\nfile   %+v\nmemory %+v", disk, got)
			}
			if names := dirEntries(t, path); !slices.Equal(names, []string{"users.json"}) {
				t.Errorf("directory holds %v, want only users.json", names)
			}
		})
	}
}

// No mutator applies a change it could not write.
func TestMutatorsRollBackOnFailedWrite(t *testing.T) {
	for _, m := range mutators {
		t.Run(m.name, func(t *testing.T) {
			u, path := persistFixture(t)
			u.fsys = faultFS{fail: "rename"}
			before := memory(u)

			if err := m.run(u); !errors.Is(err, ErrPersist) {
				t.Fatalf("%s error = %v, want ErrPersist", m.name, err)
			}

			if got := memory(u); !reflect.DeepEqual(got, before) {
				t.Errorf("memory changed:\nbefore %+v\nafter  %+v", before, got)
			}
			if disk := readUsers(t, path); !reflect.DeepEqual(disk, before) {
				t.Errorf("file changed:\nbefore %+v\nfile   %+v", before, disk)
			}
		})
	}
}

// The seed of a new database goes through the same write: New fails and
// leaves no file behind when it cannot be saved.
func TestNew_SeedWriteFailure(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if f, err := os.CreateTemp(dir, "probe"); err == nil {
		_ = f.Close()
		t.Skip("directory permissions are not enforced (running as root?)")
	}

	path := filepath.Join(dir, "users.json")
	_, err := New(Config{FilePath: path, CreateIfMissing: true, Defaults: []UserInfo{{Username: "admin"}}})
	if !errors.Is(err, ErrPersist) {
		t.Fatalf("New error = %v, want ErrPersist", err)
	}
	if names := dirEntries(t, path); len(names) != 0 {
		t.Errorf("directory holds %v, want nothing", names)
	}
}
