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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// cheapHash is an argon2id PHC string with the smallest valid parameters, so
// a test can run many derivations quickly, under the race detector too.
func cheapHash(salt, password string) string {
	key := argon2.IDKey([]byte(password), []byte(salt), 1, 8, 1, 32)
	return fmt.Sprintf("$argon2id$v=%d$m=8,t=1,p=1$%s$%s", argon2.Version,
		base64.RawStdEncoding.EncodeToString([]byte(salt)), base64.RawStdEncoding.EncodeToString(key))
}

// holdFirstDerivation makes the next derivation wait in its slot until the
// returned release is called; entered is closed once it holds the slot.
func holdFirstDerivation(t *testing.T) (entered <-chan struct{}, release func()) {
	t.Helper()
	in, out := make(chan struct{}), make(chan struct{})
	var first atomic.Bool
	first.Store(true)
	testOnDerive = func() {
		if first.CompareAndSwap(true, false) {
			close(in)
			<-out
		}
	}
	var once sync.Once
	release = func() { once.Do(func() { close(out) }) }
	t.Cleanup(func() {
		release()
		testOnDerive = nil
	})
	return in, release
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
	entered, release := holdFirstDerivation(t)
	held := make(chan error, 1)
	go func() {
		_, err := u.Verify("alice", "alicepass1")
		held <- err
	}()
	<-entered

	calls := []struct {
		name string
		call func() error
	}{
		{"login", func() error { _, err := u.Verify("alice", "alicepass1"); return err }},
		{"login of an unknown user", func() error { _, err := u.Verify("nobody", "whatever1"); return err }},
		{"self-registration", func() error { _, _, err := u.SelfRegister("carol", "carolpass1", nil, ""); return err }},
		{"admin registration", func() error { return u.AdminRegister(alice.ID, "dave", "davepass1", nil, "") }},
		{"reset link", func() error { _, err := HashNewPassword(bob.ID, "bobpass99"); return err }},
		{"change password", func() error { _, err := u.ChangePassword(bob.ID, "bobpass12", "bobpass99"); return err }},
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
	if err := <-held; err != nil {
		t.Errorf("the login holding the slot = %v, want nil", err)
	}
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
	entered, release := holdFirstDerivation(t)
	held := make(chan error, 1)
	go func() { _, err := u.Verify("carol", "carolpass1"); held <- err }()
	<-entered
	waiter := make(chan error, 1)
	go func() { _, err := u.Verify("carol", "carolpass1"); waiter <- err }()
	waitFor(t, "the waiter", func() bool { return len(kdf.waiters) == 1 })

	if _, err := u.Verify("carol", "carolpass1"); !errors.Is(err, ErrBusy) {
		t.Errorf("a caller beyond the waiters = %v, want ErrBusy", err)
	}
	release()
	if err := <-held; err != nil {
		t.Errorf("the slot holder = %v, want nil", err)
	}
	if err := <-waiter; err != nil {
		t.Errorf("the waiter = %v, want nil once the slot freed", err)
	}
}

// The production gate under 64 concurrent logins: 4 derive at once, 32 wait,
// the rest and a 65th caller are refused without waiting for the deadline.
func TestKDFGate_ConcurrentLogins(t *testing.T) {
	u, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u.users = []UserInfo{{ID: "alice", Username: "alice", Password: cheapHash("alice", "alicepass1")}}

	const slots, waiters, deadline, logins = 4, 32, 2 * time.Second, 64
	t.Cleanup(SetKDFGate(slots, waiters, deadline))
	var active, maxActive, derived atomic.Int32
	release := make(chan struct{})
	testOnDerive = func() {
		n := active.Add(1)
		for m := maxActive.Load(); n > m && !maxActive.CompareAndSwap(m, n); m = maxActive.Load() {
		}
		<-release
		derived.Add(1)
		active.Add(-1)
	}
	t.Cleanup(func() { testOnDerive = nil })

	var busy, ok atomic.Int32
	var wg sync.WaitGroup
	for range logins {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch _, err := u.Verify("alice", "alicepass1"); {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrBusy):
				busy.Add(1)
			default:
				t.Errorf("login = %v", err)
			}
		}()
	}
	waitFor(t, "the gate to fill", func() bool {
		return active.Load() == slots && len(kdf.waiters) == waiters && busy.Load() == logins-slots-waiters
	})

	start := time.Now()
	_, err = u.Verify("alice", "alicepass1")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrBusy) || elapsed >= deadline {
		t.Errorf("the 65th login = %v after %v, want ErrBusy within %v", err, elapsed, deadline)
	}

	close(release)
	wg.Wait()
	if maxActive.Load() != slots || ok.Load() != slots+waiters || busy.Load() != logins-slots-waiters {
		t.Errorf("at most %d derivations at once, %d logins served, %d refused; want %d, %d, %d",
			maxActive.Load(), ok.Load(), busy.Load(), slots, slots+waiters, logins-slots-waiters)
	}
	t.Logf("%d concurrent logins, gate of %d slots and %d waiters: at most %d derivations at once, %d served, %d refused; the 65th refused after %v",
		logins, slots, waiters, maxActive.Load(), ok.Load(), busy.Load(), elapsed)
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
			var derivations int
			testOnDerive = func() { derivations++ }
			t.Cleanup(func() { testOnDerive = nil })

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
			// a refused value runs the dummy derivation instead of its own
			if derivations != 1 {
				t.Errorf("%d derivations, want 1", derivations)
			}
		})
	}
}

// A stored value that can never match is refused after the same derivation
// as a wrong password, through the same gate: its owner's account looks like
// any other to a caller who times the answer. A bcrypt hash compares the first
// 72 bytes only, so a longer password is refused rather than truncated.
func TestVerifyPassword_RefusalDerives(t *testing.T) {
	bcryptHash := func(password string) string {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		return string(h)
	}
	pw72 := strings.Repeat("p", 72)
	tests := []struct {
		name, stored, password string
		want                   bool
		wantDummy              bool
	}{
		{"argon2id, right password", cheapHash("salt-of-alice", "alicepass1"), "alicepass1", true, false},
		{"argon2id, wrong password", cheapHash("salt-of-alice", "alicepass1"), "wrong", false, false},
		{"bcrypt, right password", bcryptHash("alicepass1"), "alicepass1", true, false},
		{"bcrypt, a password of 72 bytes", bcryptHash(pw72), pw72, true, false},
		{"bcrypt, a password over 72 bytes", bcryptHash(pw72), pw72 + "x", false, true},
		{"locked", LockedPasswordHash, "!", false, true},
		{"empty", "", "", false, true},
		{"malformed argon2id", "$argon2id$v=19$m=8,t=1,p=1$c2FsdA", "pw", false, true},
		{"argon2id over the bounds", "$argon2id$v=19$m=1048576,t=1,p=1$c29tZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAA", "pw", false, true},
		{"malformed bcrypt", "$2a$10$tooshort", "pw", false, true},
		{"not base64", "not a hash!", "pw", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var derivations, dummies int
			testOnDerive = func() { derivations++ }
			testOnDummy = func() { dummies++ }
			t.Cleanup(func() { testOnDerive, testOnDummy = nil, nil })

			ok, err := verifyPassword(UserInfo{ID: "alice", Password: tc.stored}, tc.password)
			if err != nil || ok != tc.want {
				t.Fatalf("verifyPassword = %v, %v; want %v, nil", ok, err, tc.want)
			}
			if derivations != 1 || (dummies == 1) != tc.wantDummy {
				t.Errorf("%d derivations, %d against the dummy hash; want 1, dummy %v", derivations, dummies, tc.wantDummy)
			}
		})
	}

	t.Run("unknown user", func(t *testing.T) {
		u, err := New(Config{})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		var derivations, dummies int
		testOnDerive = func() { derivations++ }
		testOnDummy = func() { dummies++ }
		t.Cleanup(func() { testOnDerive, testOnDummy = nil, nil })
		if _, err := u.Verify("nobody", "pw"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Verify = %v, want ErrInvalidCredentials", err)
		}
		if derivations != 1 || dummies != 1 {
			t.Errorf("%d derivations, %d against the dummy hash; want 1 and 1", derivations, dummies)
		}
	})
}
