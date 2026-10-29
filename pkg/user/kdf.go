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
	"errors"
	"time"
)

// ErrBusy is returned instead of deriving a password hash when the server
// already runs as many derivations as it admits and as many callers wait for
// one as it lets queue. Routes answer it with 503 and Retry-After.
var ErrBusy = errors.New("too many password checks in progress")

// kdfGate admits password-hash derivations. Each takes ~100ms and 15 MiB
// (more for a stored hash with other parameters, up to the bounds of
// parseArgon2id), so unbounded concurrent sign-ins would exhaust the memory
// of a small pod. A fixed number of slots run at once, a bounded number of
// callers wait for one up to a deadline, and the rest are refused before
// allocating anything.
type kdfGate struct {
	slots, waiters chan struct{}
	wait           time.Duration
}

func newKDFGate(slots, waiters int, wait time.Duration) *kdfGate {
	return &kdfGate{slots: make(chan struct{}, slots), waiters: make(chan struct{}, waiters), wait: wait}
}

// run runs derive in a slot of the gate, or returns ErrBusy without running
// it. The caller must hold no lock: a waiter may block for the deadline.
func (g *kdfGate) run(derive func()) error {
	select {
	case g.slots <- struct{}{}:
	default:
		select {
		case g.waiters <- struct{}{}:
		default:
			return ErrBusy
		}
		timer := time.NewTimer(g.wait)
		select {
		case g.slots <- struct{}{}:
			timer.Stop()
			<-g.waiters
		case <-timer.C:
			<-g.waiters
			return ErrBusy
		}
	}
	defer func() { <-g.slots }()

	if testOnDerive != nil {
		testOnDerive()
	}
	derive()
	return nil
}

// kdf is the gate of every derivation a request can cause.
var kdf = newKDFGate(4, 32, 2*time.Second)

// SetKDFGate replaces the derivation gate until restore is called, for tests
// of the callers: SetKDFGate(0, 0, 0) makes every derivation ErrBusy. It must
// not be called while a derivation runs.
func SetKDFGate(slots, waiters int, wait time.Duration) (restore func()) {
	old := kdf
	kdf = newKDFGate(slots, waiters, wait)
	return func() { kdf = old }
}

// testOnDerive, when a test sets it, runs in the slot before each derivation.
// Nil in production.
var testOnDerive func()

// testOnDummy, when a test sets it, runs before each derivation against
// dummyPasswordHash. Nil in production.
var testOnDummy func()

// ErrIDTooLong is returned instead of a new password hash for a user whose
// ID, the hash's salt, is longer than the verifier accepts: the hash would
// never verify. Such a user keeps the password they have.
var ErrIDTooLong = errors.New("the user ID is too long to salt a password hash")

// gatedHash is hash run through kdf.
func gatedHash(salt []byte, password string) (string, error) {
	if len(salt) > maxSaltLen {
		return "", ErrIDTooLong
	}
	var h string
	err := kdf.run(func() { h = hash(salt, password) })
	return h, err
}
