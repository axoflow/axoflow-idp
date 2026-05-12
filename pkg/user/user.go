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
	"os"
	"slices"
	"sync"

	"github.com/oklog/ulid/v2"
)

const (
	RoleUser = "user"
)

type Config struct {
	SelfRegistration   bool       `json:"selfRegistration"`
	UserAdminGroup     string     `json:"userAdminGroup"`
	Defaults           []UserInfo `json:"users"`
	FilePath           string     `json:"filePath"`
	CreateIfMissing    bool       `json:"createIfMissing"`
	PasswordChangeable bool       `json:"passwordChangeable"`
}

type UserInfo struct {
	ID       ulid.ULID
	Username string
	Password string
	Groups   []string
	Email    string
}

type User struct {
	Config
	mu    sync.Mutex
	users []UserInfo
}

func ensureUserID(users []UserInfo) []UserInfo {
	for i, u := range users {
		if u.ID.IsZero() {
			users[i].ID = ulid.Make()
		}
	}

	return users
}

func New(config Config) (*User, error) {
	u := User{
		Config: config,
		users:  []UserInfo{},
	}

	if config.FilePath != "" && config.CreateIfMissing {
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

func (u *User) getIndex(id ulid.ULID) (int, bool) {
	i := slices.IndexFunc(u.users, func(ui UserInfo) bool {
		return ui.ID == id
	})
	if i == -1 {
		return -1, false
	}

	return i, true
}

func (u *User) Get(id ulid.ULID) (UserInfo, bool) {
	i, ok := u.getIndex(id)
	if !ok {
		return UserInfo{}, false
	}

	return u.users[i], true
}

func (u *User) Register(username string, password string, groups []string, email string) error {
	// Hash before acquiring the lock: argon2id takes ~100ms and must not block other requests.
	id := ulid.Make()
	hashedPassword := hash([]byte(id.String()), password)

	u.mu.Lock()
	defer u.mu.Unlock()

	if slices.IndexFunc(u.users, func(u UserInfo) bool {
		return u.Username == username
	}) != -1 {
		return errors.New("username already exists")
	}

	if email != "" && slices.IndexFunc(u.users, func(u UserInfo) bool {
		return u.Email == email
	}) != -1 {
		return errors.New("email already registered")
	}

	u.users = append(u.users, UserInfo{
		ID:       id,
		Username: username,
		Email:    email,
		Password: hashedPassword,
		Groups:   groups,
	})

	return nil
}

func (u *User) KnownGroups() []string {
	seen := map[string]struct{}{}
	for _, user := range u.users {
		for _, g := range user.Groups {
			seen[g] = struct{}{}
		}
	}
	groups := make([]string, 0, len(seen))
	for g := range seen {
		groups = append(groups, g)
	}
	slices.Sort(groups)
	return groups
}

func (u *User) ChangePassword(userID ulid.ULID, oldPassword, newPassword string) error {
	if !u.PasswordChangeable {
		return errors.New("password changes are disabled")
	}

	user, ok := u.Get(userID)
	if !ok {
		return errors.New("user not found")
	}

	i, _ := u.getIndex(userID)

	if !verifyPassword(user, oldPassword) {
		return errors.New("invalid old password")
	}
	u.users[i].Password = hash([]byte(user.ID.String()), newPassword)
	return nil
}

func (u *User) Authenticate(username, password string) (UserInfo, bool) {
	i := slices.IndexFunc(u.users, func(u UserInfo) bool {
		return u.Username == username
	})
	if i == -1 {
		return UserInfo{}, false
	}

	user := u.users[i]

	return user, verifyPassword(user, password)
}

func (u *User) SaveUsers() error {
	if u.FilePath == "" {
		return nil
	}

	data, err := json.Marshal(u.users)
	if err != nil {
		return err
	}

	file, err := os.Create(u.FilePath + "~")
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	if err != nil {
		if err := file.Close(); err != nil {
			slog.Error("failed to close user file after write error", "error", err)
		}

		return err
	}

	if err := file.Close(); err != nil {
		return err
	}

	if err := os.Rename(u.FilePath+"~", u.FilePath); err != nil {
		return err
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

	return nil
}
