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
	"errors"

	"slices"
)

func (u *User) IsAdmin(userInfo *UserInfo) bool {
	if u.UserAdminGroup == "" {
		return false
	}

	return slices.Contains(userInfo.Groups, u.UserAdminGroup)
}

func (u *User) AdminRegister(adminID string, username string, password string, groups []string, email string) error {
	if !u.getAndVerifyAdmin(adminID) {
		return errors.New("user is not an admin")
	}

	return u.Register(username, password, groups, email)
}

// AdminRegisterLocked registers a user with no usable password (see
// RegisterLocked) on behalf of an admin, returning the new user's ID so the
// caller can issue a password-reset link for them.
func (u *User) AdminRegisterLocked(adminID string, username string, groups []string, email string) (string, error) {
	if !u.getAndVerifyAdmin(adminID) {
		return "", errors.New("user is not an admin")
	}

	return u.RegisterLocked(username, groups, email)
}

func (u *User) AdminList(adminID string) ([]UserInfo, error) {
	if !u.getAndVerifyAdmin(adminID) {
		return nil, errors.New("user is not an admin")
	}

	u.mu.RLock()
	defer u.mu.RUnlock()

	users := make([]UserInfo, len(u.users))
	copy(users, u.users)
	for i := range users {
		users[i].Password = ""
	}

	return users, nil
}

func (u *User) AdminDelete(adminID string, targetID string) error {
	if u.Static {
		return ErrReadOnly
	}
	if !u.getAndVerifyAdmin(adminID) {
		return errors.New("user is not an admin")
	}

	if adminID == targetID {
		return errors.New("are you trying to delete yourself?")
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	i, ok := u.getIndex(targetID)
	if !ok {
		return errors.New("target user not found")
	}

	u.users = slices.Delete(u.users, i, i+1)
	return nil
}

func (u *User) AdminResetPassword(adminID string, targetID string, newPassword string) error {
	if u.Static {
		return ErrReadOnly
	}
	if !u.getAndVerifyAdmin(adminID) {
		return errors.New("user is not an admin")
	}

	// hash runs argon2id (~100ms); keep it out of the lock.
	newHash := hash([]byte(targetID), newPassword)

	u.mu.Lock()
	defer u.mu.Unlock()

	i, ok := u.getIndex(targetID)
	if !ok {
		return errors.New("target user not found")
	}

	u.users[i].Password = newHash
	return nil
}

func (u *User) AdminUpdateUserGroups(adminID string, targetID string, groups []string) error {
	if u.Static {
		return ErrReadOnly
	}
	if !u.getAndVerifyAdmin(adminID) {
		return errors.New("user is not an admin")
	}

	u.mu.Lock()
	defer u.mu.Unlock()

	i, ok := u.getIndex(targetID)
	if !ok {
		return errors.New("target user not found")
	}

	u.users[i].Groups = groups
	return nil
}

func (u *User) getAndVerifyAdmin(adminID string) bool {
	admin, ok := u.Get(adminID)
	if !ok {
		return false
	}

	return u.IsAdmin(&admin)
}
