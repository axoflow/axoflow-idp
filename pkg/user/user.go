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
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

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
	// AllowBootstrap opens /register for the first user only: while the
	// database is empty, registration works with SelfRegistration off, and
	// that account becomes the bootstrap admin.
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
	// UpdateSeedPasswords sets each seed user's configured password hash on
	// its existing account at every start, so a password changed in the IdP
	// does not last. Leave it off when the hash is regenerated at every
	// deploy: each deploy would reset the password. It takes effect only with
	// FilePath and CreateIfMissing on a database that is not Static; the
	// server's config validation refuses any other combination.
	UpdateSeedPasswords bool `json:"updateSeedPasswords"`
}

// ErrReadOnly is returned by every mutating operation when the user database is
// configured as static (read-only).
var ErrReadOnly = errors.New("user database is read-only")

// ErrRegistrationClosed is returned by SelfRegister when RegistrationOpen is
// false.
var ErrRegistrationClosed = errors.New("registration is closed")

// ErrWeakPassword is wrapped by validatePassword when a password does not meet
// the minimum policy. Routes match it with errors.Is to show a friendly,
// retryable message instead of treating it as an opaque failure.
var ErrWeakPassword = errors.New("password does not meet the minimum requirements")

// errInvalidUTF8 refuses a value that encoding/json would rewrite: it replaces
// each invalid UTF-8 byte with U+FFFD when users.json is written, so two names
// that differ only there become one on disk and the next start fails.
var errInvalidUTF8 = errors.New("username, email and groups must be valid UTF-8 text")

func validUTF8(groups []string, values ...string) bool {
	for _, v := range append(values, groups...) {
		if !utf8.ValidString(v) {
			return false
		}
	}
	return true
}

// newAccountIdentity applies the identity rules for a new account. Surrounding
// whitespace is dropped and control characters are refused so a name cannot
// pass for another that looks the same; register compares both fields
// case-insensitively. An empty email stays allowed: only the public form
// requires one. Login, seed matching and loading stay byte-exact, so accounts
// created before these rules keep working.
func newAccountIdentity(username, email string) (string, string, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", "", errors.New("username is required")
	}
	trimmedEmail := strings.TrimSpace(email)
	if email != "" && trimmedEmail == "" {
		return "", "", errors.New("email must not be blank")
	}
	if strings.ContainsFunc(username, unicode.IsControl) || strings.ContainsFunc(trimmedEmail, unicode.IsControl) {
		return "", "", errors.New("username and email must not contain control characters")
	}
	return username, trimmedEmail, nil
}

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

// clone is a copy of user that shares nothing with it, so a caller can
// change what a read returned without touching the published users.
func (user UserInfo) clone() UserInfo {
	user.Groups = slices.Clone(user.Groups)
	return user
}

type User struct {
	Config
	// Lock order: saveMu, then mu. Every writer holds saveMu for its whole
	// read-modify-write (see update); mu is taken only to copy the users and
	// to publish a new slice, which is never modified once published.
	mu     sync.RWMutex // guards users
	saveMu sync.Mutex   // serializes writers
	users  []UserInfo
	fsys   fileSystem // nil means the OS

	// generations counts, per user ID, the commits that wrote the user's
	// password or deleted the user, whether or not the hash changed. A reset
	// link records it when minted and is refused once it moved. It lives in
	// memory only, as the links do, and an entry is never reset or removed,
	// so a deleted ID keeps its count. Written by commit under saveMu and mu.
	generations map[string]uint64

	// afterVerify, when set, runs between ChangePassword's verification and
	// its commit, so a test can commit a competing change there.
	afterVerify func()
}

func ensureUserID(users []UserInfo) []UserInfo {
	out := make([]UserInfo, len(users))
	copy(out, users)
	for i := range out {
		if out[i].ID == "" {
			out[i].ID = ulid.Make().String()
		}
	}

	return out
}

func New(config Config) (*User, error) {
	u := User{
		Config: config,
		users:  []UserInfo{},
	}

	seeding := !config.Static && config.FilePath != "" && config.CreateIfMissing
	if seeding {
		switch _, err := os.Stat(config.FilePath); {
		case err == nil:
		case errors.Is(err, fs.ErrNotExist):
			seed, err := u.seedUsers()
			if err != nil {
				return nil, err
			}
			u.users = seed
			if err := u.SaveUsers(); err != nil {
				return nil, fmt.Errorf("failed to create user db: %w", err)
			}
			slog.Info("seeded new user database", "path", config.FilePath, "count", len(seed))
		default:
			return nil, fmt.Errorf("failed to stat user db %q: %w", config.FilePath, err)
		}
	}

	if err := u.loadUsersFromFile(); err != nil {
		return nil, fmt.Errorf("failed to load users: %w", err)
	}
	slog.Info("users loaded", "count", len(u.users))

	if seeding && config.UpdateSeedPasswords {
		if err := u.applySeedPasswords(); err != nil {
			return nil, fmt.Errorf("failed to apply seed passwords: %w", err)
		}
	}

	return &u, nil
}

// seedUsers is the configured seed with ids, validated.
func (u *User) seedUsers() ([]UserInfo, error) {
	seed := ensureUserID(u.Defaults)
	// loadUsersFromFile applies the same rules, so a bad seed on disk would fail every start.
	if err := validateUsers(seed); err != nil {
		return nil, fmt.Errorf("invalid seed users: %w", err)
	}
	return seed, nil
}

// applySeedPasswords sets each seed user's configured password hash on its
// account.
func (u *User) applySeedPasswords() error {
	seed, err := u.seedUsers()
	if err != nil {
		return err
	}

	u.saveMu.Lock()
	defer u.saveMu.Unlock()

	users := u.snapshot()
	var updated, updatedIDs []string
	for _, s := range seed {
		i := slices.IndexFunc(users, func(ui UserInfo) bool { return ui.Username == s.Username })
		missing := i == -1
		// An empty hash would lock the account.
		if missing || s.Password == "" || users[i].Password == s.Password {
			continue
		}

		users[i].Password = s.Password
		updated = append(updated, s.Username)
		updatedIDs = append(updatedIDs, users[i].ID)
	}

	if len(updated) == 0 {
		return nil
	}
	if err := u.commit(users, updatedIDs...); err != nil {
		return err
	}
	for _, username := range updated {
		slog.Info("seed user's password updated from the configuration", "username", username)
	}
	return nil
}

func getIndex(users []UserInfo, id string) (int, bool) {
	if id == "" {
		return -1, false
	}
	i := slices.IndexFunc(users, func(ui UserInfo) bool {
		return ui.ID == id
	})
	if i == -1 {
		return -1, false
	}

	return i, true
}

// CredentialGeneration reports userID's credential generation (see
// User.generations) and whether the user exists.
func (u *User) CredentialGeneration(userID string) (uint64, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	_, ok := getIndex(u.users, userID)
	return u.generations[userID], ok
}

func (u *User) Get(id string) (UserInfo, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()

	i, ok := getIndex(u.users, id)
	if !ok {
		return UserInfo{}, false
	}

	return u.users[i].clone(), true
}

// Register creates a user for an already-authorized caller; it does not
// consult RegistrationOpen.
func (u *User) Register(username string, password string, groups []string, email string) error {
	_, _, err := u.registerWithPassword(username, password, groups, email, nil)
	return err
}

// SelfRegister creates a user through the public registration form and returns
// the new user's ID and the password hash it stored, which the session issued
// to the registrant proves. It checks RegistrationOpen as it adds the account
// and returns ErrRegistrationClosed when the form is closed.
func (u *User) SelfRegister(username string, password string, groups []string, email string) (id, passwordHash string, err error) {
	return u.registerWithPassword(username, password, groups, email, u.selfServiceOpen)
}

func (u *User) registerWithPassword(username, password string, groups []string, email string, authorize func(users []UserInfo) error) (string, string, error) {
	if u.Static {
		return "", "", ErrReadOnly
	}
	if err := validatePassword(password); err != nil {
		return "", "", err
	}

	// Hash before acquiring the lock: argon2id takes ~100ms and must not block other requests.
	id := ulid.Make().String()
	passwordHash := hash([]byte(id), password)
	id, err := u.register(id, username, passwordHash, groups, email, authorize)
	if err != nil {
		return "", "", err
	}
	return id, passwordHash, nil
}

// RegisterLocked creates a user whose password cannot be matched (see
// LockedPasswordHash), so the account is unusable until a password is set, e.g.
// via a reset link. It returns the new user's ID.
func (u *User) RegisterLocked(username string, groups []string, email string) (string, error) {
	id := ulid.Make().String()
	return u.register(id, username, LockedPasswordHash, groups, email, nil)
}

// register appends a user with an already-computed password hash, returning the
// user's ID on success. authorize, when set, decides against the users the
// account is added to whether the caller may add it (an open registration
// form, an admin).
func (u *User) register(id, username, hashedPassword string, groups []string, email string, authorize func(users []UserInfo) error) (string, error) {
	if u.Static {
		return "", ErrReadOnly
	}
	if !validUTF8(groups, username, email) {
		return "", errInvalidUTF8
	}
	username, email, err := newAccountIdentity(username, email)
	if err != nil {
		return "", err
	}

	bootstrapAdmin := false
	err = u.update(func(users []UserInfo) ([]UserInfo, error) {
		if authorize != nil {
			if err := authorize(users); err != nil {
				return nil, err
			}
		}

		newGroups := slices.Clone(groups)
		// The first user becomes an admin, so a fresh deployment is manageable
		// without hand-editing the user file. A memory-only database is empty on
		// every boot and would re-arm the grant each restart, hence FilePath.
		if len(users) == 0 && u.UserAdminGroup != "" && u.FilePath != "" && !slices.Contains(newGroups, u.UserAdminGroup) {
			newGroups = append(newGroups, u.UserAdminGroup)
			bootstrapAdmin = true
		}

		// Existing names are compared trimmed as well: a database written
		// before newAccountIdentity may hold " alice ", which must still
		// block a new "alice" or "Alice". Stored values and byte-exact login
		// are untouched.
		if slices.IndexFunc(users, func(u UserInfo) bool {
			return strings.EqualFold(strings.TrimSpace(u.Username), username)
		}) != -1 {
			return nil, errors.New("username already exists")
		}

		if email != "" && slices.IndexFunc(users, func(u UserInfo) bool {
			return strings.EqualFold(strings.TrimSpace(u.Email), email)
		}) != -1 {
			return nil, errors.New("email already registered")
		}

		return append(users, UserInfo{
			ID:       id,
			Username: username,
			Email:    email,
			Password: hashedPassword,
			Groups:   newGroups,
		}), nil
	}, id)
	if err != nil {
		return "", err
	}

	if bootstrapAdmin {
		slog.Info("first user in an empty database registered as admin", "username", username, "group", u.UserAdminGroup)
	}
	return id, nil
}

// Count reports how many users the database holds.
func (u *User) Count() int {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return len(u.users)
}

// RegistrationOpen reports whether the public registration form may create an
// account: always with SelfRegistration, or with AllowBootstrap while the
// database is empty. register makes the binding check as it adds the account.
func (u *User) RegistrationOpen() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.registrationOpen(len(u.users))
}

// registrationOpen is RegistrationOpen for a database of n users.
func (u *User) registrationOpen(n int) bool {
	return u.SelfRegistration || (u.AllowBootstrap && n == 0)
}

// selfServiceOpen authorizes a public-form registration against the users it
// is added to, so a concurrent burst cannot slip a second account through the
// bootstrap window.
func (u *User) selfServiceOpen(users []UserInfo) error {
	if !u.registrationOpen(len(users)) {
		return ErrRegistrationClosed
	}
	return nil
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

// ChangePassword sets userID's password after verifying oldPassword, and
// returns the new hash so the caller can prove it when it issues a session.
func (u *User) ChangePassword(userID string, oldPassword, newPassword string) (string, error) {
	if u.Static {
		return "", ErrReadOnly
	}
	if err := validatePassword(newPassword); err != nil {
		return "", err
	}

	user, ok := u.Get(userID)
	if !ok {
		return "", errors.New("user not found")
	}

	// verifyPassword and hash run argon2id (~100ms each); keep them out of the lock.
	if !verifyPassword(user, oldPassword) {
		return "", errors.New("invalid old password")
	}
	newHash := hash([]byte(user.ID), newPassword)
	if u.afterVerify != nil {
		u.afterVerify()
	}

	err := u.update(func(users []UserInfo) ([]UserInfo, error) {
		i, ok := getIndex(users, userID)
		if !ok {
			return nil, errors.New("user not found")
		}
		// oldPassword was checked against user.Password; a reset that
		// committed since then wins.
		if users[i].Password != user.Password {
			return nil, errors.New("invalid old password")
		}
		users[i].Password = newHash
		return users, nil
	}, userID)
	if err != nil {
		return "", err
	}
	return newHash, nil
}

// SetPassword sets a user's password without requiring the current one or any
// authority. It is the library and test-fixture mutator; no route calls it
// (the reset link goes through SetPasswordByReset), and it does not touch the
// reset links or sessions a route would end.
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

	return u.update(func(users []UserInfo) ([]UserInfo, error) {
		i, ok := getIndex(users, userID)
		if !ok {
			return nil, errors.New("user not found")
		}
		users[i].Password = newHash
		return users, nil
	}, userID)
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
	user := u.users[i].clone()
	u.mu.RUnlock()

	// verifyPassword runs argon2id/bcrypt (~100ms); keep it out of the lock.
	return user, verifyPassword(user, password)
}

// SaveUsers writes the users held in memory to FilePath. Every mutating
// operation already writes its own change; New uses this for a new database.
func (u *User) SaveUsers() error {
	if u.Static {
		return ErrReadOnly
	}

	u.saveMu.Lock()
	defer u.saveMu.Unlock()

	return u.commit(u.snapshot())
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

	return validateUsers(u.users)
}

func validateUsers(users []UserInfo) error {
	var errs []error
	seenIDs := map[string]struct{}{}
	seenUsernames := map[string]struct{}{}

	for _, user := range users {
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
