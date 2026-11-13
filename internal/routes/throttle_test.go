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

package routes

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := newLimiter()
	l.now = func() time.Time { return now }

	steps := []struct {
		name    string
		advance time.Duration
		key     string
		want    time.Duration
	}{
		{"1st", 0, "bob", 0}, {"2nd", 0, "bob", 0}, {"3rd", 0, "bob", 0}, {"4th", 0, "bob", 0}, {"5th", 0, "bob", 0},
		{"6th waits for a refill", 0, "bob", attemptRefill},
		{"another username is not affected", 0, "alice", 0},
		{"part of a refill", attemptRefill / 2, "bob", attemptRefill / 2},
		{"a refill gives one attempt", attemptRefill / 2, "bob", 0},
		{"and only one", 0, "bob", attemptRefill},
		{"a full refill", attemptBurst * attemptRefill, "bob", 0},
		{"gives the whole burst", 0, "bob", 0},
	}
	for _, s := range steps {
		now = now.Add(s.advance)
		if got := l.take(s.key); got != s.want {
			t.Fatalf("%s: take = %v, want %v", s.name, got, s.want)
		}
	}
}

func TestLimiterBounded(t *testing.T) {
	now := time.Unix(0, 0)
	l := newLimiter()
	l.now = func() time.Time { return now }
	for range attemptBurst {
		l.take("bob")
	}
	for i := range maxTrackedUsers {
		l.take(strconv.Itoa(i))
	}
	if n := len(l.buckets); n != maxTrackedUsers {
		t.Errorf("%d buckets when none is full, want %d", n, maxTrackedUsers)
	}
	if l.take("bob") == 0 {
		t.Error("other usernames filling the limiter gave bob new attempts")
	}
	now = now.Add(attemptRefill) // every bucket but bob's is full again, the same as none
	l.take("new")
	if n := len(l.buckets); n != 2 {
		t.Errorf("%d buckets after the sweep, want 2", n)
	}
}

func TestLogin_Limit(t *testing.T) {
	r := newTestRoutes(t, false)
	login := func(password string, device *http.Cookie) (int, string, *http.Cookie) {
		rec := postForm(r.Login, "/login", device, url.Values{"username": {"bob"}, "password": {password}})
		for _, c := range rec.Result().Cookies() {
			if c.Name == "device" {
				return rec.Code, rec.Header().Get("Retry-After"), c
			}
		}
		return rec.Code, rec.Header().Get("Retry-After"), nil
	}

	code, _, device := login("bobpass1", nil)
	if code != http.StatusFound || device == nil {
		t.Fatalf("login = %d with device cookie %v, want 302 and one", code, device)
	}
	for i := range attemptBurst - 1 {
		if code, retry, _ := login("wrong", nil); code != http.StatusUnauthorized || retry != "" {
			t.Fatalf("miss %d = %d Retry-After %q, want 401 and none", i+1, code, retry)
		}
	}
	if code, retry, _ := login("bobpass1", nil); code != http.StatusUnauthorized || retry != "30" {
		t.Errorf("another browser = %d Retry-After %q, want 401 and 30", code, retry)
	}
	if code, _, _ := login("bobpass1", device); code != http.StatusFound {
		t.Errorf("the signed-in browser = %d, want 302", code)
	}
	r.csrfKey = generateCSRFKey() // a restart; the signing key, and deviceKey, stay
	if code, _, _ := login("bobpass1", device); code != http.StatusFound {
		t.Errorf("a device cookie from before a restart = %d, want 302", code)
	}
	r.deviceKey = generateCSRFKey() // another signing key
	if code, _, _ := login("bobpass1", device); code != http.StatusUnauthorized {
		t.Errorf("a device cookie from before a signing-key change = %d, want 401", code)
	}
}

func TestChangePassword_Limit(t *testing.T) {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("bob")
	change := func(current string) *httptest.ResponseRecorder {
		return postForm(r.ChangePassword, "/password", cookie, url.Values{"csrf_token": {csrf}, "current_password": {current}, "new_password": {"bobpass99"}})
	}
	for i := range attemptBurst {
		if rec := change("wrong"); rec.Code != http.StatusBadRequest {
			t.Fatalf("miss %d = %d, want 400", i+1, rec.Code)
		}
	}
	if rec := change("bobpass1"); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("6th attempt = %d Retry-After %q, want 429 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
}
