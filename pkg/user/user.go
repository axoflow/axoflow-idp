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
	"log/slog"
	"maps"
	"os"
	"slices"
	"sync"

	"github.com/oklog/ulid/v2"
)

const (
	RoleUser = "user"

	// LockedPasswordHash is stored as a user's password to mark the account as
	// having no usable password. It is neither an argon2id nor a bcrypt string
	// and is invalid base64, so verifyPassword rejects every input: the user
	// must set a password (e.g. via a reset link) before they can log in.
	LockedPasswordHash = "!"
)

type Config struct {
	SelfRegistration bool `json:"selfRegistration"`
	// AllowBootstrap opens self-service registration for the very first user
	// only: while the database is empty, /register works even with
	// SelfRegistration off, and the account becomes the bootstrap admin. As
	// soon as one user exists, registration closes again.
	AllowBootstrap  bool       `json:"allowBootstrap"`
	UserAdminGroup  string     `json:"userAdminGroup"`
	Defaults        []UserInfo `json:"users"`
	FilePath        string     `json:"filePath"`
	CreateIfMissing bool       `json:"createIfMissing"`
	// Static makes the user database read-only: every mutating operation
	// (registration, password change/reset, group update, deletion) is
	// rejected with ErrReadOnly. This lets the database be served from an
	// immutable source such as a Kubernetes Secret instead of a writable
	// volume.
	Static bool `json:"static"`
}

// ErrReadOnly is returned by every mutating operation when the user database is
// configured as static (read-only).
var ErrReadOnly = errors.New("user database is read-only")

// ErrRegistrationClosed is returned by SelfRegister when neither
// SelfRegistration nor an AllowBootstrap empty-database window permits
// creating the account.
var ErrRegistrationClosed = errors.New("registration is closed")

// ErrWeakPassword is wrapped by validatePassword when a password does not meet
// the minimum policy. Routes match it with errors.Is to show a friendly,
// retryable message instead of treating it as an opaque failure.
var ErrWeakPassword = errors.New("password does not meet the minimum requirements")

// dummyPasswordHash is a valid argon2id hash verified on the username-not-found
// path of Authenticate so that path spends the same ~100ms as a real password
// check, denying an attacker a timing oracle for enumerating valid usernames.
// LockedPasswordHash ("!") would not work here: it fails base64 decoding before
// argon2 runs, so it returns early and does not equalize the timing.
var dummyPasswordHash = hash([]byte("timing-equalization-salt"), "timing-equalization-password")

type UserInfo struct {
	ID       string
	Username string
	Password string
	Groups   []string
	Email    string
}

type User struct {
	Config
	mu     sync.RWMutex // guards users
	saveMu sync.Mutex   // serializes SaveUsers so concurrent saves never share the temp file
	users  []UserInfo
}

func ensureUserID(users []UserInfo) []UserInfo {
	for i, u := range users {
		if u.ID == "" {
			users[i].ID = ulid.Make().String()
		}
	}

	return users
}

func New(config Config) (*User, error) {
	u := User{
		Config: config,
		users:  []UserInfo{},
	}

	if !config.Static && config.FilePath != "" && config.CreateIfMissing {
		_, err := os.Stat(config.FilePath)
		if err != nil {
			if u.Defaults != nil {
				u.users = ensureUserID(u.Defaults)
			}

			if err := u.SaveUsers(); err != nil {
				return nil, fmt.Errorf("failed to create empty user db: %w", err)
			}
		}
	}

	if err := u.loadUsersFromFile(); err != nil {
		return nil, fmt.Errorf("failed to load users: %w", err)
	} else {
		slog.Info("users loaded", "count", len(u.users))
	}

	return &u, nil
}

func (u *User) getIndex(id string) (int, bool) {
	if id == "" {
		return -1, false
	}
	i := slices.IndexFunc(u.users, func(ui UserInfo) bool {
		return ui.ID == id
	})
	if i == -1 {
		return -1, false
	}

	return i, true
}

func (u *User) Get(id string) (UserInfo, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	i, ok := u.getIndex(id)
	if !ok {
		return UserInfo{}, false
	}

	return u.users[i], true
}

// Register creates a user without consulting the self-registration policy; it
// is the entry point for already-authorized callers (the admin paths).
func (u *User) Register(username string, password string, groups []string, email string) error {
	_, err := u.registerWithPassword(username, password, groups, email, false)
	return err
}

// SelfRegister creates a user through the public registration form and returns
// the new user's ID (so the caller can start a session for it). Unlike
// Register it enforces the self-registration policy under the write lock: the
// registration is allowed when SelfRegistration is enabled, or — with
// AllowBootstrap — while the database is still empty (the account then becomes
// the bootstrap admin). Otherwise it returns ErrRegistrationClosed.
func (u *User) SelfRegister(username string, password string, groups []string, email string) (string, error) {
	return u.registerWithPassword(username, password, groups, email, true)
}

func (u *User) registerWithPassword(username, password string, groups []string, email string, selfService bool) (string, error) {
	if u.Static {
		return "", ErrReadOnly
	}
	if err := validatePassword(password); err != nil {
		return "", err
	}

	// Hash before acquiring the lock: argon2id takes ~100ms and must not block other requests.
	id := ulid.Make().String()
	return u.register(id, username, hash([]byte(id), password), groups, email, selfService)
}

// RegisterLocked creates a user whose password cannot be matched (see
// LockedPasswordHash), so the account is unusable until a password is set, e.g.
// via a reset link. It returns the new user's ID.
func (u *User) RegisterLocked(username string, groups []string, email string) (string, error) {
	id := ulid.Make().String()
	return u.register(id, username, LockedPasswordHash, groups, email, false)
}

// register appends a user with an already-computed password hash, returning the
// user's ID on success. selfService marks a public-form registration, which is
// subject to the self-registration policy; authorized (admin) callers pass
// false.
func (u *User) register(id, username, hashedPassword string, groups []string, email string, selfService bool) (string, error) {
	if u.Static {
		return "", ErrReadOnly
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	// The policy check shares the lock with the append, so with AllowBootstrap
	// alone the window really closes after the first user: a concurrent burst
	// cannot register a second account.
	if selfService && !u.registrationOpen() {
		return "", ErrRegistrationClosed
	}

	// Bootstrap: the very first user in an empty database becomes an admin, so
	// a fresh deployment is manageable without hand-editing the user file. The
	// check lives under the lock, which makes it race-free: of two concurrent
	// registrations only the one that appends first sees an empty database.
	// It requires a persistent database (FilePath set): a memory-only database
	// starts empty on every boot, which would re-arm the grant on each restart
	// instead of once per deployment.
	if len(u.users) == 0 && u.UserAdminGroup != "" && u.FilePath != "" && !slices.Contains(groups, u.UserAdminGroup) {
		groups = append(slices.Clone(groups), u.UserAdminGroup)
		slog.Info("first user in an empty database registered as admin", "username", username, "group", u.UserAdminGroup)
	}

	if slices.IndexFunc(u.users, func(u UserInfo) bool {
		return u.Username == username
	}) != -1 {
		return "", errors.New("username already exists")
	}

	if email != "" && slices.IndexFunc(u.users, func(u UserInfo) bool {
		return u.Email == email
	}) != -1 {
		return "", errors.New("email already registered")
	}

	u.users = append(u.users, UserInfo{
		ID:       id,
		Username: username,
		Email:    email,
		Password: hashedPassword,
		Groups:   groups,
	})

	return id, nil
}

// Count reports how many users the database holds. An empty database means the
// deployment has not been bootstrapped yet: the first registration becomes an
// admin (see register) and the login page points there instead.
func (u *User) Count() int {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return len(u.users)
}

// RegistrationOpen reports whether the public registration form may create an
// account: always with SelfRegistration, or with AllowBootstrap while the
// database is still empty. Pages use it to pick what to render; the binding
// check is the one register makes under the write lock.
func (u *User) RegistrationOpen() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.registrationOpen()
}

// registrationOpen is RegistrationOpen for callers that already hold u.mu.
func (u *User) registrationOpen() bool {
	return u.SelfRegistration || (u.AllowBootstrap && len(u.users) == 0)
}

func (u *User) KnownGroups() []string {
	u.mu.RLock()
	defer u.mu.RUnlock()

	seen := map[string]struct{}{}
	for _, user := range u.users {
		for _, g := range user.Groups {
			seen[g] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(seen))
}

func (u *User) ChangePassword(userID string, oldPassword, newPassword string) error {
	if u.Static {
		return ErrReadOnly
	}
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	user, ok := u.Get(userID)
	if !ok {
		return errors.New("user not found")
	}

	// verifyPassword and hash run argon2id (~100ms each); keep them out of the lock.
	if !verifyPassword(user, oldPassword) {
		return errors.New("invalid old password")
	}
	newHash := hash([]byte(user.ID), newPassword)

	u.mu.Lock()
	defer u.mu.Unlock()
	i, ok := u.getIndex(userID)
	if !ok {
		return errors.New("user not found")
	}
	u.users[i].Password = newHash
	return nil
}

// SetPassword sets a user's password without requiring the current one. It is
// used by admin-initiated reset flows (e.g. the password-reset link), where the
// caller has already been authorized out of band.
func (u *User) SetPassword(userID, newPassword string) error {
	if u.Static {
		return ErrReadOnly
	}
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	user, ok := u.Get(userID)
	if !ok {
		return errors.New("user not found")
	}

	// hash runs argon2id (~100ms); keep it out of the lock.
	newHash := hash([]byte(user.ID), newPassword)

	u.mu.Lock()
	defer u.mu.Unlock()
	i, ok := u.getIndex(userID)
	if !ok {
		return errors.New("user not found")
	}
	u.users[i].Password = newHash
	return nil
}

func (u *User) Authenticate(username, password string) (UserInfo, bool) {
	u.mu.RLock()
	i := slices.IndexFunc(u.users, func(u UserInfo) bool {
		return u.Username == username
	})
	if i == -1 {
		u.mu.RUnlock()
		// Run a verify against a dummy hash so the not-found path takes the same
		// ~100ms as a real check, closing the username-enumeration timing oracle.
		_ = verifyPassword(UserInfo{Password: dummyPasswordHash}, password)
		return UserInfo{}, false
	}
	user := u.users[i]
	u.mu.RUnlock()

	// verifyPassword runs argon2id/bcrypt (~100ms); keep it out of the lock.
	return user, verifyPassword(user, password)
}

func (u *User) SaveUsers() error {
	if u.Static {
		return ErrReadOnly
	}
	if u.FilePath == "" {
		return nil
	}

	// Serialize saves: the temp file path is shared, so two concurrent saves
	// must not write it at the same time. Held across marshal+write+rename.
	u.saveMu.Lock()
	defer u.saveMu.Unlock()

	u.mu.RLock()
	data, err := json.Marshal(u.users)
	u.mu.RUnlock()
	if err != nil {
		return err
	}

	file, err := os.Create(u.FilePath + "~")
	if err != nil {
		return fmt.Errorf("create temp user file: %w", err)
	}

	_, err = file.Write(data)
	if err != nil {
		if err := file.Close(); err != nil {
			slog.Error("failed to close user file after write error", "error", err)
		}

		return fmt.Errorf("write user data: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close temp user file: %w", err)
	}

	if err := os.Rename(u.FilePath+"~", u.FilePath); err != nil {
		return fmt.Errorf("rename temp user file: %w", err)
	}

	return nil
}

func (u *User) loadUsersFromFile() error {
	if u.FilePath == "" {
		return nil
	}

	data, err := os.ReadFile(u.FilePath)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, &u.users); err != nil {
		return err
	}

	var errs []error
	seenIDs := map[string]struct{}{}
	seenUsernames := map[string]struct{}{}
	for _, user := range u.users {
		if user.ID == "" {
			errs = append(errs, fmt.Errorf("user %q has no id", user.Username))
		} else if _, dup := seenIDs[user.ID]; dup {
			errs = append(errs, fmt.Errorf("duplicate user id %q", user.ID))
		} else {
			seenIDs[user.ID] = struct{}{}
		}

		if _, dup := seenUsernames[user.Username]; dup {
			errs = append(errs, fmt.Errorf("duplicate username %q", user.Username))
		} else {
			seenUsernames[user.Username] = struct{}{}
		}
	}

	return errors.Join(errs...)
}
