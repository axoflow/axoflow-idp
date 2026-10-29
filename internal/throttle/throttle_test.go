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

package throttle

import (
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newTestLimiter() (*Limiter, *clock) {
	c := &clock{t: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	l := New()
	l.now = c.now
	return l, c
}

func fail(t *testing.T, l *Limiter, key string) {
	t.Helper()
	wait, done := l.Begin(key)
	if done == nil {
		t.Fatalf("Begin(%q) refused for %v", key, wait)
	}
	done(true)
}

// wait is how long key's cooldown refuses it for, read without starting an
// attempt.
func wait(l *Limiter, key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	el, ok := l.entries[digestOf(key)]
	if !ok {
		return 0
	}
	return max(el.Value.(*entry).until.Sub(l.now()), 0)
}

// Each step acts on the key "alice" and checks what it is refused for after.
func TestLimiter(t *testing.T) {
	type step struct {
		advance  time.Duration
		action   string // "fail", "succeed" or "" (only check)
		wantWait time.Duration
	}
	fails := func(n int) []step {
		s := make([]step, n)
		for i := range s {
			s[i] = step{action: "fail"}
		}
		return s
	}
	// five failures, the fifth starting the first cooldown
	cooling := func() []step { return append(fails(4), step{action: "fail", wantWait: FirstCooldown}) }
	tests := []struct {
		name  string
		steps []step
	}{
		{"four failures are free", fails(4)},
		{"the fifth starts a 10s cooldown", cooling()},
		{"the cooldown runs out", append(cooling(),
			step{advance: 4 * time.Second, wantWait: 6 * time.Second},
			step{advance: 6 * time.Second})},
		{"each failure after it doubles it, up to 30s", append(cooling(),
			step{advance: 10 * time.Second, action: "fail", wantWait: 20 * time.Second},
			step{advance: 20 * time.Second, action: "fail", wantWait: 30 * time.Second},
			step{advance: 30 * time.Second, action: "fail", wantWait: 30 * time.Second})},
		{"a success forgets the failures", append(append(fails(4), step{action: "succeed"}), fails(4)...)},
		{"failures expire with the window", append(fails(4),
			step{advance: Window, action: "fail"},
			step{action: "fail"}, step{action: "fail"}, step{action: "fail"})},
		{"a cooldown outlasts the window", append(cooling(),
			step{advance: 10 * time.Second, action: "fail", wantWait: 20 * time.Second},
			step{advance: 20 * time.Second, action: "fail", wantWait: 30 * time.Second},
			step{advance: Window - 40*time.Second, action: "fail", wantWait: 30 * time.Second},
			step{advance: 20 * time.Second, wantWait: 10 * time.Second})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, c := newTestLimiter()
			for i, s := range tc.steps {
				c.advance(s.advance)
				switch s.action {
				case "fail":
					fail(t, l, "alice")
				case "succeed":
					l.Succeed("alice")
				}
				if got := wait(l, "alice"); got != s.wantWait {
					t.Fatalf("step %d (%s after %v): Wait = %v, want %v", i, s.action, s.advance, got, s.wantWait)
				}
			}
			if got := wait(l, "bob"); got != 0 {
				t.Errorf("another key waits %v, want 0", got)
			}
		})
	}
}

// The limiter keeps at most MaxKeys keys, dropping the least recently failed.
func TestLimiterBounded(t *testing.T) {
	l, _ := newTestLimiter()
	for range FreeFailures - 1 {
		fail(t, l, "target")
	}
	for i := range MaxKeys {
		fail(t, l, "user"+strconv.Itoa(i))
		if i == MaxKeys/2 {
			fail(t, l, "target") // recently failed again, so it is kept longer
		}
	}
	if n := l.Len(); n != MaxKeys {
		t.Errorf("Len = %d, want %d", n, MaxKeys)
	}
	if wait(l, "target") == 0 {
		t.Error("a recently failed key was dropped")
	}
	fail(t, l, "one more")
	if n := l.Len(); n != MaxKeys {
		t.Errorf("Len = %d after one more key, want %d", n, MaxKeys)
	}
	if _, ok := l.entries[digestOf("user0")]; ok {
		t.Error("the least recently failed key was kept")
	}
}

// A username is attacker-sized, up to the request body bound: 10k distinct
// 60 KiB ones, each failed once, must not be retained. The retained bytes
// are the map keys plus the live heap the limiter added, measured as
// HeapAlloc after a GC, with only the limiter still reachable, minus
// HeapAlloc after a GC before the first failure.
func TestLimiterRetainsNoUsername(t *testing.T) {
	if testing.Short() {
		t.Skip("hashes 600 MiB")
	}
	const budget = 10 << 20
	l, _ := newTestLimiter()
	name := []byte(strings.Repeat("u", 60<<10))

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := range MaxKeys {
		copy(name, strconv.Itoa(i)+"-")
		fail(t, l, string(name))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(name)

	if n := l.Len(); n > MaxKeys {
		t.Errorf("Len = %d, want at most %d", n, MaxKeys)
	}
	var keyBytes int
	for k := range l.entries {
		keyBytes += len(k)
	}
	heap := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("%d keys: %d key bytes, heap grew by %d bytes", l.Len(), keyBytes, heap)
	if int64(keyBytes)+heap > budget {
		t.Errorf("retained %d key bytes and %d heap bytes, want under %d together", keyBytes, heap, budget)
	}
}

// An entry whose window and cooldown have both passed is dropped by the
// next failure of any key, or the next Begin; one whose cooldown still runs
// is kept, and so is one with an attempt in flight.
func TestLimiterDropsIdleEntries(t *testing.T) {
	for _, next := range []string{"fail", "begin"} {
		t.Run(next, func(t *testing.T) {
			l, c := newTestLimiter()
			fail(t, l, "idle")
			_, held := l.Begin("in flight") // older than every other entry, never failed
			for range FreeFailures {
				fail(t, l, "cooling")
			}
			for range 2 {
				c.advance(MaxCooldown)
				fail(t, l, "cooling") // its cooldown reaches 30s
			}
			c.advance(Window - time.Second - 2*MaxCooldown)
			fail(t, l, "cooling") // the window has not passed: a 30s cooldown
			c.advance(time.Second)
			want := 2 // "cooling" and "in flight"
			if next == "fail" {
				fail(t, l, "other")
				want++
			} else {
				_, done := l.Begin("other")
				done(false)
			}
			if n := l.Len(); n != want {
				t.Errorf("Len = %d, want %d: the idle entry was kept", n, want)
			}
			if wait(l, "cooling") == 0 {
				t.Error("an entry in cooldown was dropped")
			}
			if _, ok := l.entries[digestOf("in flight")]; !ok {
				t.Fatal("an entry with an attempt in flight was dropped")
			}
			if cooldown := held(true); cooldown != 0 || l.Len() != want {
				t.Errorf("the held attempt's failure = %v, Len %d; want 0 and %d", cooldown, l.Len(), want)
			}
		})
	}
}

// The attempts in flight count as failures would: a concurrent burst gets
// FreeFailures attempts before the first cooldown, and one at a time after
// a cooldown has run.
func TestLimiterBurst(t *testing.T) {
	l, c := newTestLimiter()
	var dones []func(bool) time.Duration
	for i := range 20 {
		wait, done := l.Begin("alice")
		if (done != nil) != (i < FreeFailures) {
			t.Fatalf("attempt %d: admitted %v, want %v", i+1, done != nil, i < FreeFailures)
		}
		if done == nil && wait != FirstCooldown {
			t.Errorf("attempt %d refused for %v, want %v", i+1, wait, FirstCooldown)
		}
		if done != nil {
			dones = append(dones, done)
		}
	}
	if wait, _ := l.Begin("bob"); wait != 0 {
		t.Errorf("another key is refused for %v", wait)
	}
	var cooldowns []time.Duration
	for _, done := range dones {
		cooldowns = append(cooldowns, done(true))
	}
	if want := []time.Duration{0, 0, 0, 0, FirstCooldown}; !slices.Equal(cooldowns, want) {
		t.Errorf("cooldowns started = %v, want %v", cooldowns, want)
	}

	c.advance(FirstCooldown)
	_, first := l.Begin("alice")
	if first == nil {
		t.Fatal("the attempt after the cooldown was refused")
	}
	if wait, done := l.Begin("alice"); done != nil || wait != FirstCooldown {
		t.Errorf("a second attempt beside it: admitted %v, wait %v; want refused for %v", done != nil, wait, FirstCooldown)
	}
	if cooldown := first(true); cooldown != 2*FirstCooldown {
		t.Errorf("its failure started %v, want %v", cooldown, 2*FirstCooldown)
	}
}

// A success forgets the failures, not the attempts still in flight: they
// keep counting against a burst, and their failures land on the same entry.
func TestLimiterSucceedWithAttemptsInFlight(t *testing.T) {
	l, _ := newTestLimiter()
	fail(t, l, "alice")
	_, ok := l.Begin("alice")
	var wrong []func(bool) time.Duration
	for range FreeFailures - 2 {
		_, done := l.Begin("alice")
		wrong = append(wrong, done)
	}
	ok(false)
	l.Succeed("alice")

	inFlight, admitted := len(wrong), 0
	for range FreeFailures {
		if _, done := l.Begin("alice"); done != nil {
			admitted++
			wrong = append(wrong, done)
		}
	}
	if admitted != FreeFailures-inFlight {
		t.Errorf("%d attempts admitted beside %d in flight, want %d", admitted, inFlight, FreeFailures-inFlight)
	}
	var started time.Duration
	for _, done := range wrong {
		started = done(true)
	}
	if started != FirstCooldown || wait(l, "alice") != FirstCooldown {
		t.Errorf("the fifth failure since the success started %v, wait %v; want %v", started, wait(l, "alice"), FirstCooldown)
	}
}

// Eviction passes over an entry with an attempt in flight; with every entry
// in flight, a new key's attempt is admitted without being tracked.
func TestLimiterEvictionKeepsAttemptsInFlight(t *testing.T) {
	l, _ := newTestLimiter()
	_, held := l.Begin("held") // the least recently failed entry
	for i := range MaxKeys {
		fail(t, l, "user"+strconv.Itoa(i))
	}
	if _, ok := l.entries[digestOf("held")]; !ok {
		t.Fatal("an entry with an attempt in flight was evicted")
	}
	if _, ok := l.entries[digestOf("user0")]; ok {
		t.Error("the least recently failed entry not in flight was kept")
	}
	held(true)

	l, _ = newTestLimiter()
	for i := range MaxKeys {
		l.Begin("user" + strconv.Itoa(i))
	}
	wait, done := l.Begin("one more")
	if wait != 0 || done == nil {
		t.Fatalf("Begin with every entry in flight = %v, admitted %v; want admitted", wait, done != nil)
	}
	if cooldown := done(true); cooldown != 0 || l.Len() != MaxKeys {
		t.Errorf("its failure = %v, Len %d; want 0 and %d", cooldown, l.Len(), MaxKeys)
	}
}

func TestCounter(t *testing.T) {
	c := &clock{t: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	counter := NewCounter(time.Minute)
	counter.now = c.now

	steps := []struct {
		advance    time.Duration
		key        string
		wantN      int
		wantReport bool
	}{
		{0, "app", 1, true},
		{time.Second, "app", 0, false},
		{time.Second, "app", 0, false},
		{time.Second, "other", 1, true},
		{time.Minute, "app", 3, true},
		{time.Second, "app", 0, false},
	}
	for i, s := range steps {
		c.advance(s.advance)
		if n, report := counter.Add(s.key); n != s.wantN || report != s.wantReport {
			t.Errorf("step %d: Add(%q) = %d, %v; want %d, %v", i, s.key, n, report, s.wantN, s.wantReport)
		}
	}
}
