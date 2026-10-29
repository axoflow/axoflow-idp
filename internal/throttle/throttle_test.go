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
	"strconv"
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
					l.Fail("alice")
				case "succeed":
					l.Succeed("alice")
				}
				if got := l.Wait("alice"); got != s.wantWait {
					t.Fatalf("step %d (%s after %v): Wait = %v, want %v", i, s.action, s.advance, got, s.wantWait)
				}
			}
			if got := l.Wait("bob"); got != 0 {
				t.Errorf("another key waits %v, want 0", got)
			}
		})
	}
}

// The limiter keeps at most MaxKeys keys, dropping the least recently failed.
func TestLimiterBounded(t *testing.T) {
	l, _ := newTestLimiter()
	for range FreeFailures {
		l.Fail("target")
	}
	for i := range MaxKeys {
		l.Fail("user" + strconv.Itoa(i))
		if i == MaxKeys/2 {
			l.Fail("target") // recently failed again, so it is kept longer
		}
	}
	if n := l.Len(); n != MaxKeys {
		t.Errorf("Len = %d, want %d", n, MaxKeys)
	}
	if l.Wait("target") == 0 {
		t.Error("a recently failed key was dropped")
	}
	l.Fail("one more")
	if n := l.Len(); n != MaxKeys {
		t.Errorf("Len = %d after one more key, want %d", n, MaxKeys)
	}
	if _, ok := l.entries["user0"]; ok {
		t.Error("the least recently failed key was kept")
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
