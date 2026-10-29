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
type Limiter struct {
	mu      sync.Mutex
	now     func() time.Time
	order   *list.List // of *entry, the most recently failed first
	entries map[string]*list.Element
}

type entry struct {
	key      string
	first    time.Time // of the failures counted
	failures int
	cooldown time.Duration
	until    time.Time
}

func New() *Limiter {
	return &Limiter{now: time.Now, order: list.New(), entries: map[string]*list.Element{}}
}

// live reports whether e still counts at now: its window is open or its
// cooldown still runs.
func (e *entry) live(now time.Time) bool {
	return now.Sub(e.first) < Window || now.Before(e.until)
}

// Wait returns how long key is refused for, zero when it may try.
func (l *Limiter) Wait(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	el, ok := l.entries[key]
	if !ok {
		return 0
	}
	return max(el.Value.(*entry).until.Sub(l.now()), 0)
}

// Fail records a failure of key and returns the cooldown it started, zero
// when it started none.
func (l *Limiter) Fail(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	el, ok := l.entries[key]
	if ok {
		l.order.MoveToFront(el)
	} else {
		if l.order.Len() >= MaxKeys {
			oldest := l.order.Back()
			l.order.Remove(oldest)
			delete(l.entries, oldest.Value.(*entry).key)
		}
		el = l.order.PushFront(&entry{key: key, first: now})
		l.entries[key] = el
	}
	e := el.Value.(*entry)
	if !e.live(now) {
		*e = entry{key: key, first: now}
	}

	e.failures++
	if e.failures < FreeFailures {
		return 0
	}
	e.cooldown = min(max(2*e.cooldown, FirstCooldown), MaxCooldown)
	e.until = now.Add(e.cooldown)
	return e.cooldown
}

// Succeed forgets the failures of key.
func (l *Limiter) Succeed(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if el, ok := l.entries[key]; ok {
		l.order.Remove(el)
		delete(l.entries, key)
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
