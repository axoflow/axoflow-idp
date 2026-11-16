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
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

// cheapHash is an argon2id PHC string with the smallest valid parameters, so
// a test can run many derivations quickly, under the race detector too.
func cheapHash(salt, password string) string {
	key := argon2.IDKey([]byte(password), []byte(salt), 1, 8, 1, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=8,t=1,p=1$%s$%s", argon2.Version,
		base64.RawStdEncoding.EncodeToString([]byte(salt)), base64.RawStdEncoding.EncodeToString(key))
}

// holdSlot takes a slot of the gate, as a running derivation would, until
// the returned release is called.
func holdSlot(t *testing.T) (release func()) {
	t.Helper()
	kdf.slots <- struct{}{}
	var once sync.Once
	release = func() { once.Do(func() { <-kdf.slots }) }
	t.Cleanup(release)
	return release
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// With the one slot of the gate taken and its one waiter's deadline passed,
// every kind of derivation is refused with ErrBusy and changes nothing.
func TestKDFGate_BusyRefusesEveryDerivation(t *testing.T) {
	u, err := New(Config{SelfRegistration: true, UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := u.Register("alice", "alicepass1", []string{"admins"}, ""); err != nil {
		t.Fatalf("Register alice: %v", err)
	}
	if err := u.Register("bob", "bobpass12", nil, ""); err != nil {
		t.Fatalf("Register bob: %v", err)
	}
	alice, _ := u.Authenticate("alice", "alicepass1")
	bob, _ := u.Authenticate("bob", "bobpass12")

	t.Cleanup(SetKDFGate(1, 1, 20*time.Millisecond))
	release := holdSlot(t)

	calls := []struct {
		name string
		call func() error
	}{
		{"login", func() error { _, err := u.Verify("alice", "alicepass1"); return err }},
		{"login of an unknown user", func() error { _, err := u.Verify("nobody", "whatever1"); return err }},
		{"self-registration", func() error { _, err := u.SelfRegister("carol", "carolpass1", nil, ""); return err }},
		{"admin registration", func() error { return u.AdminRegister(alice.ID, "dave", "davepass1", nil, "") }},
		{"reset link", func() error { return u.SetPassword(bob.ID, "bobpass99") }},
		{"change password", func() error { return u.ChangePassword(bob.ID, "bobpass12", "bobpass99") }},
		{"admin reset", func() error { return u.AdminResetPassword(alice.ID, bob.ID, "bobpass99") }},
	}
	for _, c := range calls {
		if err := c.call(); !errors.Is(err, ErrBusy) {
			t.Errorf("%s with the gate full = %v, want ErrBusy", c.name, err)
		}
	}
	if n := u.Count(); n != 2 {
		t.Errorf("%d users, want 2: a refused registration added one", n)
	}

	release()
	if _, err := u.Verify("bob", "bobpass12"); err != nil {
		t.Errorf("bob's login after the gate freed = %v, want nil: a refused write changed the password", err)
	}
}

// A caller that finds the slots taken waits for one, up to the deadline;
// once the waiters are full the next is refused at once.
func TestKDFGate_Waiters(t *testing.T) {
	u, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u.users = []UserInfo{{ID: "carol", Username: "carol", Password: cheapHash("carol", "carolpass1")}}

	t.Cleanup(SetKDFGate(1, 1, 10*time.Second))
	release := holdSlot(t)
	waiter := make(chan error, 1)
	go func() { _, err := u.Verify("carol", "carolpass1"); waiter <- err }()
	waitFor(t, "the waiter", func() bool { return len(kdf.waiters) == 1 })

	if _, err := u.Verify("carol", "carolpass1"); !errors.Is(err, ErrBusy) {
		t.Errorf("a caller beyond the waiters = %v, want ErrBusy", err)
	}
	release()
	if err := <-waiter; err != nil {
		t.Errorf("the waiter = %v, want nil once the slot freed", err)
	}
}

// A stored argon2id string is read from users.json: parameters outside the
// bounds would let it allocate or spin without limit, or panic in argon2.
func TestVerifyArgon2id_ParameterBounds(t *testing.T) {
	salt := base64.RawStdEncoding.EncodeToString([]byte("somesalt"))
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	phc := func(v, params, salt, key string) string {
		return "$argon2id$" + v + "$" + params + "$" + salt + "$" + key
	}
	valid := func(m, tm uint32, p uint8) string {
		k := argon2.IDKey([]byte("pw"), []byte("somesalt"), tm, m, p, 32)
		return phc("v=19", fmt.Sprintf("m=%d,t=%d,p=%d", m, tm, p), salt, base64.RawStdEncoding.EncodeToString(k))
	}
	tests := []struct {
		name, stored string
		want         bool
	}{
		{"memory at the bound", valid(32768, 1, 1), true},
		{"time at the bound", valid(8, 10, 1), true},
		{"threads at the bound", valid(32, 1, 4), true},
		{"memory over 32 MiB", phc("v=19", "m=32769,t=1,p=1", salt, key), false},
		{"memory of 1 GiB", phc("v=19", "m=1048576,t=1,p=1", salt, key), false},
		{"memory overflowing uint32", phc("v=19", "m=99999999999,t=1,p=1", salt, key), false},
		{"no time", phc("v=19", "m=8,t=0,p=1", salt, key), false},
		{"time over 10", phc("v=19", "m=8,t=11,p=1", salt, key), false},
		{"no threads", phc("v=19", "m=8,t=1,p=0", salt, key), false},
		{"threads over 4", phc("v=19", "m=40,t=1,p=5", salt, key), false},
		{"threads overflowing uint8", phc("v=19", "m=8,t=1,p=300", salt, key), false},
		{"another version", phc("v=16", "m=8,t=1,p=1", salt, key), false},
		{"no salt", phc("v=19", "m=8,t=1,p=1", "", key), false},
		{"salt over 1024 bytes", phc("v=19", "m=8,t=1,p=1", base64.RawStdEncoding.EncodeToString(make([]byte, 1025)), key), false},
		{"no digest", phc("v=19", "m=8,t=1,p=1", salt, ""), false},
		{"digest under 16 bytes", phc("v=19", "m=8,t=1,p=1", salt, base64.RawStdEncoding.EncodeToString(make([]byte, 15))), false},
		{"digest over 64 bytes", phc("v=19", "m=8,t=1,p=1", salt, base64.RawStdEncoding.EncodeToString(make([]byte, 65))), false},
		{"salt not base64", phc("v=19", "m=8,t=1,p=1", "!!", key), false},
		{"a part missing", "$argon2id$v=19$m=8,t=1,p=1$" + salt, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := func() (ok bool, err error) {
				defer func() {
					if p := recover(); p != nil {
						err = fmt.Errorf("panic: %v", p)
					}
				}()
				return verifyPassword(UserInfo{Password: tc.stored}, "pw")
			}()
			if err != nil || ok != tc.want {
				t.Fatalf("verifyPassword(%.60s) = %v, %v; want %v, nil", tc.stored, ok, err, tc.want)
			}
		})
	}
}
