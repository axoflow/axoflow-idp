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

	"github.com/oklog/ulid/v2"
)

var errNotAdmin = errors.New("user is not an admin")

func (u *User) IsAdmin(userInfo *UserInfo) bool {
	if u.UserAdminGroup == "" {
		return false
	}

	return slices.Contains(userInfo.Groups, u.UserAdminGroup)
}

func (u *User) AdminRegister(adminID string, username string, password string, groups []string, email string) error {
	if !u.getAndVerifyAdmin(adminID) {
		return errNotAdmin
	}

	_, _, err := u.registerWithPassword(username, password, groups, email, func(users []UserInfo) error {
		return u.requireAdmin(users, adminID)
	})
	return err
}

// AdminRegisterLocked registers a user with no usable password (see
// RegisterLocked) on behalf of an admin, returning the new user's ID so the
// caller can issue a password-reset link for them.
func (u *User) AdminRegisterLocked(adminID string, username string, groups []string, email string) (string, error) {
	if !u.getAndVerifyAdmin(adminID) {
		return "", errNotAdmin
	}

	return u.register(ulid.Make().String(), username, LockedPasswordHash, groups, email, func(users []UserInfo) error {
		return u.requireAdmin(users, adminID)
	})
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
		users[i] = users[i].clone()
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

	return u.update(func(users []UserInfo) ([]UserInfo, error) {
		if err := u.requireAdmin(users, adminID); err != nil {
			return nil, err
		}
		i, ok := getIndex(users, targetID)
		if !ok {
			return nil, errors.New("target user not found")
		}
		return slices.Delete(users, i, i+1), nil
	}, targetID)
}

func (u *User) AdminResetPassword(adminID string, targetID string, newPassword string) error {
	if u.Static {
		return ErrReadOnly
	}
	if !u.getAndVerifyAdmin(adminID) {
		return errors.New("user is not an admin")
	}
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	// Fetch first so a reset against a missing target fails fast instead of
	// wasting the ~100ms hash, and salt with the stored ID (mirrors
	// ChangePassword/SetPassword) rather than the caller-supplied parameter.
	user, ok := u.Get(targetID)
	if !ok {
		return errors.New("target user not found")
	}

	// hash runs argon2id (~100ms); keep it out of the lock.
	newHash, err := gatedHash([]byte(user.ID), newPassword)
	if err != nil {
		return err
	}

	return u.update(func(users []UserInfo) ([]UserInfo, error) {
		if err := u.requireAdmin(users, adminID); err != nil {
			return nil, err
		}
		i, ok := getIndex(users, targetID)
		if !ok {
			return nil, errors.New("target user not found") // concurrent deletion
		}
		users[i].Password = newHash
		return users, nil
	}, targetID)
}

// ErrResetRefused is returned by SetPasswordByReset when the link no longer
// carries the authority to set the password.
var ErrResetRefused = errors.New("password reset link is no longer valid")

// SetPasswordByReset sets targetID's password hash to newHash on the
// authority of a reset link minted by issuerID when targetID's credential
// generation was expectedGeneration (see CredentialGeneration). It checks, in
// the same writer transaction as the write, that issuerID is still in
// UserAdminGroup, that the target exists and that its generation is still
// expectedGeneration. Any password write for the target or its deletion that
// committed after the link was minted, including one that set the same hash
// or another link's redemption, has moved the generation, so the link is
// refused with ErrResetRefused.
func (u *User) SetPasswordByReset(targetID, issuerID string, expectedGeneration uint64, newHash string) error {
	if u.Static {
		return ErrReadOnly
	}

	return u.update(func(users []UserInfo) ([]UserInfo, error) {
		if err := u.requireAdmin(users, issuerID); err != nil {
			return nil, ErrResetRefused
		}
		i, ok := getIndex(users, targetID)
		// saveMu, held here, orders this read after every commit.
		if !ok || u.generations[targetID] != expectedGeneration {
			return nil, ErrResetRefused
		}
		users[i].Password = newHash
		return users, nil
	}, targetID)
}

func (u *User) AdminUpdateUserGroups(adminID string, targetID string, groups []string) error {
	if u.Static {
		return ErrReadOnly
	}
	if !u.getAndVerifyAdmin(adminID) {
		return errors.New("user is not an admin")
	}
	if !validUTF8(groups) {
		return errInvalidUTF8
	}

	// With the self-delete guard in AdminDelete this keeps at least one admin:
	// the caller is still one after every operation.
	if adminID == targetID && !slices.Contains(groups, u.UserAdminGroup) {
		return errors.New("cannot remove the admin group from yourself")
	}

	return u.update(func(users []UserInfo) ([]UserInfo, error) {
		if err := u.requireAdmin(users, adminID); err != nil {
			return nil, err
		}
		i, ok := getIndex(users, targetID)
		if !ok {
			return nil, errors.New("target user not found")
		}
		users[i].Groups = slices.Clone(groups)
		return users, nil
	})
}

// requireAdmin is the binding admin check of a write, made against the users
// it changes while it holds saveMu, so a concurrent demotion or deletion of
// the admin cannot slip in between. getAndVerifyAdmin before it only fails
// fast.
func (u *User) requireAdmin(users []UserInfo, adminID string) error {
	i, ok := getIndex(users, adminID)
	if !ok || !u.IsAdmin(&users[i]) {
		return errNotAdmin
	}
	return nil
}

func (u *User) getAndVerifyAdmin(adminID string) bool {
	admin, ok := u.Get(adminID)
	if !ok {
		return false
	}

	return u.IsAdmin(&admin)
}
