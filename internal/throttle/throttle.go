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

// Package throttle slows down password guessing against one account and
// rate-limits the logging of failed client authentications.
package throttle

import (
	"container/list"
	"crypto/sha256"
	"sync"
	"time"
)

const (
	// MaxKeys bounds the keys a Limiter tracks; the least recently failed
	// one is dropped for a new one.
	MaxKeys = 10000
	// Window is how long failures of a key are counted, from its first.
	Window = 10 * time.Minute
	// FreeFailures is how many failures within Window a key has before it is
	// refused for a cooldown.
	FreeFailures = 5
	// FirstCooldown is the first cooldown; each failure after it doubles it,
	// up to MaxCooldown.
	FirstCooldown = 10 * time.Second
	MaxCooldown   = 30 * time.Second
)

// Limiter counts failed sign-ins per key, a username, and refuses a key in
// cooldown. It is safe for concurrent use.
//
// A key is held as its SHA-256 digest: a username is as long as the request
// body allows, whether or not the account exists, and MaxKeys of them would
// otherwise be retained whole. The digest keeps the byte-exact identity the
// password check uses.
type Limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	order   *list.List // of *entry, the most recently failed first
	entries map[digest]*list.Element
}

type digest = [sha256.Size]byte

func digestOf(key string) digest { return sha256.Sum256([]byte(key)) }

type entry struct {
	key      digest
	first    time.Time // of the failures counted
	failures int
	inFlight int // attempts admitted and not yet done
	cooldown time.Duration
	until    time.Time
}

func New() *Limiter {
	return &Limiter{now: time.Now, order: list.New(), entries: map[digest]*list.Element{}}
}

// counting reports whether e's failures still count at now: its window is
// open or its cooldown still runs.
func (e *entry) counting(now time.Time) bool {
	return now.Sub(e.first) < Window || now.Before(e.until)
}

// live reports whether e is still needed at now. An entry with attempts in
// flight is, so their done finds it.
func (e *entry) live(now time.Time) bool {
	return e.inFlight > 0 || (e.failures > 0 && e.counting(now))
}

// forget drops e's failures and cooldown, as a new entry has none.
func (e *entry) forget() {
	e.first, e.failures, e.cooldown, e.until = time.Time{}, 0, 0, time.Time{}
}

// dropIdle drops the entries that no longer count. A failed attempt's done
// checks every entry: it follows a failed derivation, which the KDF gate
// bounds. Begin costs no derivation, so it stops at the least recently failed
// entry still live.
func (l *Limiter) dropIdle(now time.Time, all bool) {
	for el := l.order.Back(); el != nil; {
		prev := el.Prev()
		if e := el.Value.(*entry); !e.live(now) {
			l.remove(el)
		} else if !all {
			return
		}
		el = prev
	}
}

func (l *Limiter) remove(el *list.Element) {
	l.order.Remove(el)
	delete(l.entries, el.Value.(*entry).key)
}

// Begin admits an attempt of key, or refuses it for wait. An admitted attempt
// is counted until done is called with whether it failed; done returns the
// cooldown the failure started, zero when it started none. Counting the
// attempts in flight bounds a concurrent burst as a sequential run is bounded:
// no more than FreeFailures attempts before the first cooldown, and one at a
// time after a cooldown has run, as its failure starts the next.
func (l *Limiter) Begin(key string) (wait time.Duration, done func(failed bool) time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.dropIdle(now, false)
	d := digestOf(key)
	el, ok := l.entries[d]
	if !ok {
		if l.order.Len() >= MaxKeys && !l.evict() {
			// Every entry has an attempt in flight, which the KDF gate keeps
			// far below MaxKeys; this one is let through without counting it.
			return 0, func(bool) time.Duration { return 0 }
		}
		el = l.order.PushFront(&entry{key: d})
		l.entries[d] = el
	}
	e := el.Value.(*entry)
	if !e.counting(now) {
		e.forget()
	}
	if now.Before(e.until) {
		return e.until.Sub(now), nil
	}
	if e.inFlight > 0 && e.failures+e.inFlight >= FreeFailures {
		return FirstCooldown, nil
	}
	e.inFlight++
	return 0, func(failed bool) time.Duration { return l.done(el, failed) }
}

// evict drops the least recently failed entry with no attempt in flight, and
// reports whether there was one.
func (l *Limiter) evict() bool {
	for el := l.order.Back(); el != nil; el = el.Prev() {
		if el.Value.(*entry).inFlight == 0 {
			l.remove(el)
			return true
		}
	}
	return false
}

// done ends an attempt Begin admitted, recording its failure. The entry is
// still in the map: one with an attempt in flight is neither dropped nor
// evicted.
func (l *Limiter) done(el *list.Element, failed bool) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	e := el.Value.(*entry)
	e.inFlight--
	if !failed {
		if !e.live(now) {
			l.remove(el)
		}
		return 0
	}
	cooldown := e.fail(now)
	l.order.MoveToFront(el)
	l.dropIdle(now, true)
	return cooldown
}

// fail records a failure of e and returns the cooldown it started.
func (e *entry) fail(now time.Time) time.Duration {
	if !e.counting(now) {
		e.forget()
	}
	if e.failures == 0 {
		e.first = now
	}
	e.failures++
	if e.failures < FreeFailures {
		return 0
	}
	e.cooldown = min(max(2*e.cooldown, FirstCooldown), MaxCooldown)
	e.until = now.Add(e.cooldown)
	return e.cooldown
}

// Succeed forgets the failures of key. An entry with attempts in flight is
// kept for their done.
func (l *Limiter) Succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if el, ok := l.entries[digestOf(key)]; ok {
		el.Value.(*entry).forget()
		if el.Value.(*entry).inFlight == 0 {
			l.remove(el)
		}
	}
}

// Len is the number of keys tracked.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.order.Len()
}

// Counter counts events per key and says when to log them: at most once per
// interval for a key, with the count since its last report. The caller
// bounds the keys, such as to the registered clients.
type Counter struct {
	mu       sync.Mutex
	now      func() time.Time
	interval time.Duration
	counts   map[string]*count
}

type count struct {
	n        int
	reported time.Time
}

func NewCounter(interval time.Duration) *Counter {
	return &Counter{now: time.Now, interval: interval, counts: map[string]*count{}}
}

// Add counts an event of key. When report is true the caller logs n, the
// events of key since its last report, this one included.
func (c *Counter) Add(key string) (n int, report bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.counts[key]
	if !ok {
		e = &count{}
		c.counts[key] = e
	}
	e.n++
	if now := c.now(); e.reported.IsZero() || now.Sub(e.reported) >= c.interval {
		n, e.n, e.reported = e.n, 0, now
		return n, true
	}
	return 0, false
}
