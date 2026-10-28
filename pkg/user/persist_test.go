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
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
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

// holdFirstUpdate makes the next writer to enter update wait there, past its
// early checks, until release runs; writers after it pass straight through.
// held is closed once the first writer is waiting.
func holdFirstUpdate(t *testing.T) (held <-chan struct{}, release func()) {
	arrived := make(chan struct{})
	proceed := make(chan struct{})
	var taken atomic.Bool
	testBeforeUpdate = func() {
		if taken.CompareAndSwap(false, true) {
			close(arrived)
			<-proceed
		}
	}
	release = sync.OnceFunc(func() { close(proceed) })
	t.Cleanup(func() {
		release()
		testBeforeUpdate = nil
	})
	return arrived, release
}

// An admin whose early check passed and who is then demoted or deleted before
// the write must be refused: the binding check runs on the users the write
// changes, not on what the early check saw. Each row targets one requireAdmin.
func TestStaleAdminIsRefused(t *testing.T) {
	tests := []struct {
		name  string
		stale func(u *User) error // carol's write, held after its early check
		first func(u *User) error // alice's write, committed meanwhile
	}{
		{
			name:  "group update after a demotion",
			stale: func(u *User) error { return u.AdminUpdateUserGroups("carol", "alice", []string{RoleUser}) },
			first: func(u *User) error { return u.AdminUpdateUserGroups("alice", "carol", []string{RoleUser}) },
		},
		{
			name:  "delete after a deletion",
			stale: func(u *User) error { return u.AdminDelete("carol", "bob") },
			first: func(u *User) error { return u.AdminDelete("alice", "carol") },
		},
		{
			name:  "register after a demotion",
			stale: func(u *User) error { return u.AdminRegister("carol", "dave", "davepass1", []string{"admins"}, "") },
			first: func(u *User) error { return u.AdminUpdateUserGroups("alice", "carol", []string{RoleUser}) },
		},
		{
			name: "register locked after a demotion",
			stale: func(u *User) error {
				_, err := u.AdminRegisterLocked("carol", "dave", []string{"admins"}, "")
				return err
			},
			first: func(u *User) error { return u.AdminUpdateUserGroups("alice", "carol", []string{RoleUser}) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, path := persistFixture(t)
			held, release := holdFirstUpdate(t)

			staleErr := make(chan error, 1)
			go func() { staleErr <- tt.stale(u) }()
			<-held

			if err := tt.first(u); err != nil {
				t.Fatalf("alice's write: %v", err)
			}
			committed := readUsers(t, path)

			release()
			if err := <-staleErr; !errors.Is(err, errNotAdmin) {
				t.Fatalf("carol's write error = %v, want %v", err, errNotAdmin)
			}

			disk := readUsers(t, path)
			if !reflect.DeepEqual(disk, committed) {
				t.Errorf("file changed by the refused write:\nbefore %+v\nafter  %+v", committed, disk)
			}
			if got := memory(u); !reflect.DeepEqual(got, disk) {
				t.Errorf("memory differs from the file:\nmemory %+v\nfile   %+v", got, disk)
			}
			var admins []string
			for _, ui := range disk {
				if u.IsAdmin(&ui) {
					admins = append(admins, ui.Username)
				}
			}
			if !slices.Equal(admins, []string{"alice"}) {
				t.Errorf("admins = %v, want [alice]", admins)
			}
		})
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

// The read APIs hand out copies: a caller changing the groups it got back
// must not reach the published users, or a later write would save a change
// no mutator checked.
func TestReadAPIsReturnCopiesOfGroups(t *testing.T) {
	reads := []struct {
		name string
		bob  func(t *testing.T, u *User) UserInfo
	}{
		{"Get", func(t *testing.T, u *User) UserInfo {
			bob, ok := u.Get("bob")
			if !ok {
				t.Fatal("Get: bob not found")
			}
			return bob
		}},
		{"Authenticate", func(t *testing.T, u *User) UserInfo {
			bob, ok := u.Authenticate("bob", "bobpass123")
			if !ok {
				t.Fatal("Authenticate: bob refused")
			}
			return bob
		}},
		{"AdminList", func(t *testing.T, u *User) UserInfo {
			users, err := u.AdminList("alice")
			if err != nil {
				t.Fatalf("AdminList: %v", err)
			}
			i := slices.IndexFunc(users, func(ui UserInfo) bool { return ui.ID == "bob" })
			if i == -1 {
				t.Fatal("AdminList: bob not listed")
			}
			return users[i]
		}},
	}

	for _, r := range reads {
		t.Run(r.name, func(t *testing.T) {
			u, path := persistFixture(t)

			r.bob(t, u).Groups[0] = "admins"

			if bob, _ := u.Get("bob"); !slices.Equal(bob.Groups, []string{RoleUser}) {
				t.Errorf("bob's groups in memory = %v, want [%s]", bob.Groups, RoleUser)
			}
			if err := u.SaveUsers(); err != nil {
				t.Fatalf("SaveUsers: %v", err)
			}
			reloaded, err := New(Config{FilePath: path})
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			if bob, _ := reloaded.Get("bob"); !slices.Equal(bob.Groups, []string{RoleUser}) {
				t.Errorf("bob's groups on disk = %v, want [%s]", bob.Groups, RoleUser)
			}
		})
	}
}

// A change owns its copy of every user down to the groups: editing a group in
// place reaches neither memory nor the file unless the change commits.
func TestUpdate_CandidateGroupsAreOwned(t *testing.T) {
	tests := []struct {
		name   string
		fail   string // faultFS step; empty means the change refuses itself
		refuse bool
	}{
		{name: "refused change", refuse: true},
		{name: "failed write", fail: "rename"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, path := persistFixture(t)
			if tt.fail != "" {
				u.fsys = faultFS{fail: tt.fail}
			}
			before := readUsers(t, path)

			err := u.update(func(users []UserInfo) ([]UserInfo, error) {
				i, _ := getIndex(users, "bob")
				users[i].Groups[0] = "admins"
				if tt.refuse {
					return nil, errInjected
				}
				return users, nil
			})
			if !errors.Is(err, errInjected) {
				t.Fatalf("update error = %v, want the injected failure", err)
			}

			if bob, _ := u.Get("bob"); !slices.Equal(bob.Groups, []string{RoleUser}) {
				t.Errorf("bob's groups in memory = %v, want [%s]", bob.Groups, RoleUser)
			}
			if disk := readUsers(t, path); !reflect.DeepEqual(disk, before) {
				t.Errorf("file changed:\nbefore %+v\nfile   %+v", before, disk)
			}
			// What memory holds is what the next write saves.
			u.fsys = nil
			if err := u.SaveUsers(); err != nil {
				t.Fatalf("SaveUsers: %v", err)
			}
			if disk := readUsers(t, path); !reflect.DeepEqual(disk, before) {
				t.Errorf("file after the next write:\nbefore %+v\nfile   %+v", before, disk)
			}
		})
	}
}

// pauseFS stops a write just before its rename; resume decides how the rename
// ends (nil lets it run).
type pauseFS struct {
	osFileSystem
	paused chan<- struct{}
	resume <-chan error
}

func (p pauseFS) Rename(oldpath, newpath string) error {
	p.paused <- struct{}{}
	if err := <-p.resume; err != nil {
		return err
	}
	return p.osFileSystem.Rename(oldpath, newpath)
}

// Until the rename installs the new file, readers see the old state and the
// file is untouched; after it the change is visible only if the rename worked.
func TestReadersSeeOldStateUntilRename(t *testing.T) {
	tests := []struct {
		name      string
		renameErr error
	}{
		{name: "rename succeeds"},
		{name: "rename fails", renameErr: errInjected},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, path := persistFixture(t)
			paused := make(chan struct{})
			resume := make(chan error)
			u.fsys = pauseFS{paused: paused, resume: resume}
			before := readUsers(t, path)
			oldBob, _ := u.Get("bob")

			done := make(chan error, 1)
			go func() { done <- u.SetPassword("bob", "newpass123") }()
			<-paused

			// t.Error, not t.Fatal: the writer must be resumed either way.
			if bob, _ := u.Get("bob"); bob.Password != oldBob.Password {
				t.Error("Get sees the new password before the rename")
			}
			if _, ok := u.Authenticate("bob", "bobpass123"); !ok {
				t.Error("old password refused before the rename")
			}
			if _, ok := u.Authenticate("bob", "newpass123"); ok {
				t.Error("new password accepted before the rename")
			}
			if disk := readUsers(t, path); !reflect.DeepEqual(disk, before) {
				t.Errorf("file changed before the rename:\nbefore %+v\nfile   %+v", before, disk)
			}

			resume <- tt.renameErr
			err := <-done

			_, oldOK := u.Authenticate("bob", "bobpass123")
			_, newOK := u.Authenticate("bob", "newpass123")
			disk := readUsers(t, path)
			if tt.renameErr == nil {
				if err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				if oldOK || !newOK {
					t.Errorf("after the rename: old password accepted %v, new %v; want false, true", oldOK, newOK)
				}
				if got := memory(u); !reflect.DeepEqual(disk, got) {
					t.Errorf("file differs from memory:\nfile   %+v\nmemory %+v", disk, got)
				}
			} else {
				if !errors.Is(err, ErrPersist) {
					t.Fatalf("SetPassword error = %v, want ErrPersist", err)
				}
				if !oldOK || newOK {
					t.Errorf("after the failed rename: old password accepted %v, new %v; want true, false", oldOK, newOK)
				}
				if !reflect.DeepEqual(disk, before) {
					t.Errorf("file changed:\nbefore %+v\nfile   %+v", before, disk)
				}
			}
		})
	}
}

// A seed password that cannot be written leaves the account's old password in
// memory and on disk, and the server does not start.
func TestApplySeedPasswords_WriteFailure(t *testing.T) {
	seed := []UserInfo{{Username: "bob", Password: hash([]byte("bob"), "seedpass1")}}

	t.Run("store", func(t *testing.T) {
		u, path := persistFixture(t)
		u.Defaults = seed
		u.fsys = faultFS{fail: "rename"}
		before := readUsers(t, path)
		oldBob, _ := u.Get("bob")

		if err := u.applySeedPasswords(); !errors.Is(err, ErrPersist) {
			t.Fatalf("applySeedPasswords error = %v, want ErrPersist", err)
		}

		if bob, _ := u.Get("bob"); bob.Password != oldBob.Password {
			t.Error("bob's password in memory changed despite the failed write")
		}
		if disk := readUsers(t, path); !reflect.DeepEqual(disk, before) {
			t.Errorf("file changed:\nbefore %+v\nfile   %+v", before, disk)
		}
	})

	t.Run("New", func(t *testing.T) {
		_, path := persistFixture(t)
		before := readUsers(t, path)
		dir := filepath.Dir(path)
		if err := os.Chmod(dir, 0o500); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		if f, err := os.CreateTemp(dir, "probe"); err == nil {
			_ = f.Close()
			t.Skip("directory permissions are not enforced (running as root?)")
		}

		_, err := New(Config{FilePath: path, CreateIfMissing: true, UpdateSeedPasswords: true, Defaults: seed})
		if !errors.Is(err, ErrPersist) {
			t.Fatalf("New error = %v, want ErrPersist", err)
		}
		if disk := readUsers(t, path); !reflect.DeepEqual(disk, before) {
			t.Errorf("file changed:\nbefore %+v\nfile   %+v", before, disk)
		}
	})
}

// The per-user seed log reports a password that was set, so a write that
// fails leaves no success-looking line before the startup error.
func TestApplySeedPasswords_LogsOnlyCommitted(t *testing.T) {
	tests := []struct {
		fail       string
		wantLogged bool
	}{
		{fail: "rename"},
		{fail: "none", wantLogged: true},
	}

	for _, tt := range tests {
		t.Run(tt.fail, func(t *testing.T) {
			u, _ := persistFixture(t)
			u.Defaults = []UserInfo{{Username: "bob", Password: hash([]byte("bob"), "seedpass1")}}
			u.fsys = faultFS{fail: tt.fail}
			var logs bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(prev) })

			err := u.applySeedPasswords()

			if (err == nil) != tt.wantLogged {
				t.Fatalf("applySeedPasswords error = %v", err)
			}
			if logged := strings.Contains(logs.String(), "username=bob"); logged != tt.wantLogged {
				t.Errorf("bob's seed password logged = %v, want %v; log:\n%s", logged, tt.wantLogged, logs.String())
			}
		})
	}
}
