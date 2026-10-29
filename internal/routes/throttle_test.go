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
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/axoflow/axoflow-idp/internal/throttle"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

func loginAs(r *Routes, username, password string) (status int, retryAfter string, signedIn bool) {
	rec := postForm(r.Login, "/login", nil, url.Values{"username": {username}, "password": {password}})
	return rec.Code, rec.Header().Get("Retry-After"), sessionCookieOf(rec) != nil
}

// Five wrong passwords put the username in cooldown: the next attempt is
// refused like a wrong password, with Retry-After, even with the right one.
// Another account is not affected, and a success forgets the failures.
func TestLogin_Cooldown(t *testing.T) {
	t.Run("six failures", func(t *testing.T) {
		r := newTestRoutes(t, false)
		for i := range 5 {
			if status, retry, _ := loginAs(r, "bob", "wrong"); status != http.StatusUnauthorized || retry != "" {
				t.Fatalf("failure %d = %d Retry-After %q, want 401 and none", i+1, status, retry)
			}
		}
		if status, retry, signedIn := loginAs(r, "bob", "bobpass1"); status != http.StatusUnauthorized || retry != "10" || signedIn {
			t.Errorf("sixth attempt = %d Retry-After %q signed in %v, want 401, 10 and no session", status, retry, signedIn)
		}
		authQuery := url.Values{"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}}
		r2, _ := newOidcTestRoutes(t)
		r.oidc, r.store = r2.oidc, r2.store
		rec := postForm(r.OidcAuth, "/oidc/auth?"+authQuery.Encode(), nil, url.Values{"username": {"bob"}, "password": {"bobpass1"}})
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("Retry-After") == "" || sessionCookieOf(rec) != nil {
			t.Errorf("the /oidc/auth login form in cooldown = %d Retry-After %q, want 401 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
		}
		if status, _, signedIn := loginAs(r, "admin", "adminpass"); status != http.StatusFound || !signedIn {
			t.Errorf("another account = %d, want 302 and a session", status)
		}
	})

	t.Run("a success forgets the failures", func(t *testing.T) {
		r := newTestRoutes(t, false)
		for range 4 {
			loginAs(r, "bob", "wrong")
		}
		if status, _, _ := loginAs(r, "bob", "bobpass1"); status != http.StatusFound {
			t.Fatalf("login = %d, want 302", status)
		}
		for range 4 {
			loginAs(r, "bob", "wrong")
		}
		if status, retry, signedIn := loginAs(r, "bob", "bobpass1"); status != http.StatusFound || !signedIn {
			t.Errorf("login after 4+4 failures with a success between = %d Retry-After %q, want 302", status, retry)
		}
	})
}

// heldChecks holds each password derivation, the Verify of a sign-in and
// the ChangePassword of /password, until release is closed, so the requests
// of a burst all ask the cooldown before any of them records a failure. n
// counts the derivations, wherever a request reaches them.
type heldChecks struct {
	entered, release chan struct{}
	n                atomic.Int32
}

func holdPasswordChecks(r *Routes) *heldChecks {
	h := &heldChecks{entered: make(chan struct{}), release: make(chan struct{})}
	hold := func() {
		h.n.Add(1)
		select {
		case h.entered <- struct{}{}:
			<-h.release
		case <-h.release:
		}
	}
	r.hooks.verify = func(username, password string) (user.UserInfo, error) {
		hold()
		return r.user.Verify(username, password)
	}
	r.hooks.changePassword = func(userID, oldPassword, newPassword string) (string, error) {
		hold()
		return r.user.ChangePassword(userID, oldPassword, newPassword)
	}
	return h
}

// countPasswordChecks counts the password derivations without holding them.
func countPasswordChecks(r *Routes) *atomic.Int32 {
	var n atomic.Int32
	r.hooks.verify = func(username, password string) (user.UserInfo, error) {
		n.Add(1)
		return r.user.Verify(username, password)
	}
	r.hooks.changePassword = func(userID, oldPassword, newPassword string) (string, error) {
		n.Add(1)
		return r.user.ChangePassword(userID, oldPassword, newPassword)
	}
	return &n
}

type attempt struct {
	status     int
	retryAfter string
	signedIn   bool
}

func goLogin(r *Routes, username, password string, answers chan<- attempt) {
	go func() {
		status, retry, signedIn := loginAs(r, username, password)
		answers <- attempt{status, retry, signedIn}
	}()
}

// settle waits until n more requests are held or answered, and returns the
// answers.
func (h *heldChecks) settle(n int, answers <-chan attempt) []attempt {
	var got []attempt
	for range n {
		select {
		case <-h.entered:
		case a := <-answers:
			got = append(got, a)
		}
	}
	return got
}

// A concurrent burst of wrong passwords gets no more password checks than a
// sequential one: five, and the rest are refused with Retry-After before
// any is checked.
func TestLogin_CooldownBurst(t *testing.T) {
	r := newTestRoutes(t, false)
	held := holdPasswordChecks(r)
	answers := make(chan attempt, 20)
	for range 20 {
		goLogin(r, "bob", "wrong", answers)
	}
	refused := held.settle(20, answers)
	close(held.release)
	for range 20 - len(refused) {
		<-answers
	}

	if n := held.n.Load(); n != throttle.FreeFailures {
		t.Errorf("%d password derivations for a burst of 20, want %d", n, throttle.FreeFailures)
	}
	for _, a := range refused {
		if a.status != http.StatusUnauthorized || a.retryAfter == "" {
			t.Errorf("a refused attempt = %d Retry-After %q, want 401 with Retry-After", a.status, a.retryAfter)
		}
	}
	if status, retry, _ := loginAs(r, "bob", "bobpass1"); status != http.StatusUnauthorized || retry == "" {
		t.Errorf("after the burst = %d Retry-After %q, want 401 with Retry-After", status, retry)
	}
}

// The right password sent while five wrong ones are being checked is
// refused, not checked: the burst cannot reach it.
func TestLogin_CooldownBurstRefusesTheRightPassword(t *testing.T) {
	r := newTestRoutes(t, false)
	held := holdPasswordChecks(r)
	wrong, right := make(chan attempt, throttle.FreeFailures), make(chan attempt, 1)
	for range throttle.FreeFailures {
		goLogin(r, "bob", "wrong", wrong)
	}
	if early := held.settle(throttle.FreeFailures, wrong); len(early) != 0 {
		t.Fatalf("%d of the first five were answered before their check: %+v", len(early), early)
	}
	goLogin(r, "bob", "bobpass1", right)
	answered := held.settle(1, right)
	close(held.release)
	if len(answered) == 0 {
		answered = append(answered, <-right)
	}
	// Drain the wrong attempts: their derivations and cooldown log lines
	// must not outlive the test. SetKDFGate forbids derivations in flight,
	// and later tests capture the default logger.
	for range throttle.FreeFailures {
		<-wrong
	}

	if a := answered[0]; a.status != http.StatusUnauthorized || a.retryAfter == "" || a.signedIn {
		t.Errorf("the right password in the burst = %d Retry-After %q signed in %v, want 401 with Retry-After", a.status, a.retryAfter, a.signedIn)
	}
	if n := held.n.Load(); n != throttle.FreeFailures {
		t.Errorf("%d password derivations, want %d", n, throttle.FreeFailures)
	}
}

// A burst of wrong passwords at each door that checks an existing password,
// and at two of them at once for one username, derives five and refuses the
// rest before their derivation.
func TestCooldownBurst_EveryDoor(t *testing.T) {
	type door func(r *Routes, cookie *http.Cookie, csrf string) attempt
	signIn := func(r *Routes, _ *http.Cookie, _ string) attempt {
		status, retry, signedIn := loginAs(r, "bob", "wrong")
		return attempt{status, retry, signedIn}
	}
	authForm := func(r *Routes, _ *http.Cookie, _ string) attempt {
		q := url.Values{"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}}
		rec := postForm(r.OidcAuth, "/oidc/auth?"+q.Encode(), nil, url.Values{"username": {"bob"}, "password": {"wrong"}})
		return attempt{rec.Code, rec.Header().Get("Retry-After"), sessionCookieOf(rec) != nil}
	}
	changePassword := func(r *Routes, cookie *http.Cookie, csrf string) attempt {
		rec := changePasswordAs(r, cookie, csrf, "wrong")
		return attempt{rec.Code, rec.Header().Get("Retry-After"), false}
	}
	tests := []struct {
		name  string
		doors []door
	}{
		{"/login", []door{signIn}},
		{"the /oidc/auth login form", []door{authForm}},
		{"/password", []door{changePassword}},
		{"/login and /password together", []door{signIn, changePassword}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newOidcTestRoutes(t)
			cookie, csrf := r.authed("bob")
			held := holdPasswordChecks(r)
			answers := make(chan attempt, 20)
			for i := range 20 {
				go func() { answers <- tt.doors[i%len(tt.doors)](r, cookie, csrf) }()
			}
			refused := held.settle(20, answers)
			close(held.release)
			var derived []attempt
			for range 20 - len(refused) {
				derived = append(derived, <-answers)
			}

			if n := held.n.Load(); n != throttle.FreeFailures {
				t.Errorf("%d password derivations for a burst of 20, want %d", n, throttle.FreeFailures)
			}
			if len(derived) != throttle.FreeFailures {
				t.Errorf("%d answered after their derivation, want %d", len(derived), throttle.FreeFailures)
			}
			for _, a := range refused {
				if (a.status != http.StatusUnauthorized && a.status != http.StatusTooManyRequests) || a.retryAfter == "" || a.signedIn {
					t.Errorf("a refused attempt = %+v, want 401 or 429 with Retry-After", a)
				}
			}
			for _, a := range derived {
				if (a.status != http.StatusUnauthorized && a.status != http.StatusBadRequest) || a.retryAfter != "" || a.signedIn {
					t.Errorf("a derived attempt = %+v, want a miss without Retry-After", a)
				}
			}
		})
	}
}

// A sign-in the derivation gate refuses derived nothing, so it is not a
// failure: any number of them leave the username out of cooldown.
func TestLogin_BusyIsNotAFailure(t *testing.T) {
	r := newTestRoutes(t, false)
	restore := user.SetKDFGate(0, 0, 0)
	for i := range 2 * throttle.FreeFailures {
		if status, _, _ := loginAs(r, "bob", "wrong"); status != http.StatusServiceUnavailable {
			t.Fatalf("busy attempt %d = %d, want 503", i+1, status)
		}
	}
	restore()
	if status, retry, signedIn := loginAs(r, "bob", "bobpass1"); status != http.StatusFound || !signedIn {
		t.Errorf("login after busy refusals = %d Retry-After %q, want 302 and a session", status, retry)
	}
}

func changePasswordAs(r *Routes, cookie *http.Cookie, csrf, current string) *httptest.ResponseRecorder {
	return postForm(r.ChangePassword, "/password", cookie, url.Values{"csrf_token": {csrf}, "current_password": {current}, "new_password": {"bobpass99"}})
}

// The current-password check of /password is behind the sign-in cooldown of
// the account's username: a session holder guesses no faster than the
// sign-in form allows, and an account in cooldown is not checked there.
func TestChangePassword_Cooldown(t *testing.T) {
	t.Run("five wrong current passwords", func(t *testing.T) {
		r := newTestRoutes(t, false)
		checks := countPasswordChecks(r)
		warnings := captureWarnings(t)
		cookie, csrf := r.authed("bob")
		for i := range throttle.FreeFailures {
			if rec := changePasswordAs(r, cookie, csrf, "wrong"); rec.Code != http.StatusBadRequest {
				t.Fatalf("miss %d = %d, want 400", i+1, rec.Code)
			}
		}
		rec := changePasswordAs(r, cookie, csrf, "bobpass1")
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "10" || !strings.Contains(rec.Body.String(), "Too many attempts; try again later") {
			t.Errorf("sixth attempt = %d Retry-After %q, want 429, 10 and the form saying so", rec.Code, rec.Header().Get("Retry-After"))
		}
		if n := checks.Load(); n != throttle.FreeFailures {
			t.Errorf("%d current-password checks, want %d", n, throttle.FreeFailures)
		}
		if _, ok := r.user.Authenticate("bob", "bobpass1"); !ok {
			t.Error("the password changed")
		}
		if status, retry, _ := loginAs(r, "bob", "bobpass1"); status != http.StatusUnauthorized || retry == "" {
			t.Errorf("sign-in after the misses = %d Retry-After %q, want 401 with Retry-After", status, retry)
		}
		misses := 0
		for _, w := range warnings() {
			if strings.Contains(w, `"msg":"password change refused: wrong current password"`) && strings.Contains(w, `"user_id":"bob"`) {
				misses++
			}
		}
		if misses != throttle.FreeFailures {
			t.Errorf("%d misses logged, want %d: %q", misses, throttle.FreeFailures, warnings())
		}
	})

	t.Run("a username in sign-in cooldown", func(t *testing.T) {
		r := newTestRoutes(t, false)
		for range throttle.FreeFailures {
			loginAs(r, "bob", "wrong")
		}
		checks := countPasswordChecks(r)
		cookie, csrf := r.authed("bob")
		if rec := changePasswordAs(r, cookie, csrf, "bobpass1"); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
			t.Errorf("/password in cooldown = %d Retry-After %q, want 429 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
		}
		if n := checks.Load(); n != 0 {
			t.Errorf("%d current-password checks in cooldown, want 0", n)
		}
	})

	t.Run("the right password after fewer misses", func(t *testing.T) {
		r := newTestRoutes(t, false)
		cookie, csrf := r.authed("bob")
		for range throttle.FreeFailures - 1 {
			changePasswordAs(r, cookie, csrf, "wrong")
		}
		if rec := changePasswordAs(r, cookie, csrf, "bobpass1"); rec.Code != http.StatusSeeOther {
			t.Fatalf("change with the right password = %d, want 303", rec.Code)
		}
		for range throttle.FreeFailures - 1 {
			loginAs(r, "bob", "wrong")
		}
		if status, retry, signedIn := loginAs(r, "bob", "bobpass99"); status != http.StatusFound || !signedIn {
			t.Errorf("sign-in after 4+4 misses with the change between = %d Retry-After %q, want 302: the change did not clear the count", status, retry)
		}
	})

	t.Run("a busy refusal", func(t *testing.T) {
		r := newTestRoutes(t, false)
		cookie, csrf := r.authed("bob")
		restore := user.SetKDFGate(0, 0, 0)
		for i := range 2 * throttle.FreeFailures {
			if rec := changePasswordAs(r, cookie, csrf, "wrong"); rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("busy attempt %d = %d, want 503", i+1, rec.Code)
			}
		}
		restore()
		if rec := changePasswordAs(r, cookie, csrf, "bobpass1"); rec.Code != http.StatusSeeOther {
			t.Errorf("change after busy refusals = %d, want 303", rec.Code)
		}
	})
}

// An admin's password reset, or one through a reset link, ends the cooldown.
func TestLogin_CooldownEndsWithAReset(t *testing.T) {
	tests := []struct {
		name  string
		reset func(t *testing.T, r *Routes)
	}{
		{"admin reset", func(t *testing.T, r *Routes) {
			cookie, csrf := r.authed("admin1")
			if rec := postForm(r.AdminResetPassword, "/admin/users/reset-password", cookie, url.Values{"csrf_token": {csrf}, "user_id": {"bob"}, "new_password": {"bobpass99"}}); rec.Code != http.StatusSeeOther {
				t.Fatalf("admin reset = %d, want 303", rec.Code)
			}
		}},
		{"reset link", func(t *testing.T, r *Routes) {
			generation, _ := r.user.CredentialGeneration("bob")
			token, err := r.resetTokens.Create("bob", "admin1", generation)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			if rec := postForm(r.SetPassword, "/set-password", nil, url.Values{"token": {token}, "new_password": {"bobpass99"}}); rec.Code != http.StatusSeeOther {
				t.Fatalf("set-password = %d, want 303", rec.Code)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRoutes(t, false)
			for range 5 {
				loginAs(r, "bob", "wrong")
			}
			if _, retry, _ := loginAs(r, "bob", "bobpass1"); retry == "" {
				t.Fatal("bob is not in cooldown")
			}
			tc.reset(t, r)
			if status, retry, signedIn := loginAs(r, "bob", "bobpass99"); status != http.StatusFound || !signedIn {
				t.Errorf("login after the reset = %d Retry-After %q, want 302", status, retry)
			}
		})
	}
}

// captureWarnings sends slog's default logger to a buffer for the test and
// returns the WARN records written to it.
func captureWarnings(t *testing.T) func() []string {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return func() []string {
		return strings.FieldsFunc(buf.String(), func(r rune) bool { return r == '\n' })
	}
}

// A confidential client's wrong secret at /token or /revoke is counted and
// logged once a minute, never refused for longer: a valid exchange of the
// same client still works. A public client's errors and the grant's are not
// logged.
func TestClientSecretFailures(t *testing.T) {
	r, cookie := newPublicClientRoutes(t)
	r.confidential = map[string]bool{"app": true, "app2": true}
	r.secretFailures = throttle.NewCounter(time.Minute)
	warnings := captureWarnings(t)

	for range 50 {
		if rec := postRevoke(t, r, url.Values{"token": {"x"}, "client_id": {"app"}, "client_secret": {"guess"}}); rec.Code != http.StatusUnauthorized {
			t.Fatalf("revoke with a wrong secret = %d, want 401", rec.Code)
		}
	}
	if rec := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}, "client_secret": {"guess"}, "redirect_uri": {testRedirectURI}, "code": {"x"}}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token with a wrong secret = %d, want 401", rec.Code)
	}

	// not a confidential client's wrong secret
	postRevoke(t, r, url.Values{"token": {"x"}, "client_id": {"cli"}})
	postRevoke(t, r, url.Values{"token": {"x"}, "client_id": {"unknown"}, "client_secret": {"guess"}})
	postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "client_id": {"cli"}, "redirect_uri": {loopbackCallback}, "code": {"x"}})
	postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "client_id": {"app2"}, "client_secret": {"s3cret2"}, "redirect_uri": {testRedirectURI}, "code": {"x"}})
	postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "client_id": {"app2"}, "client_secret": {"s3cret2"}, "redirect_uri": {"https://elsewhere/cb"}, "code": {"x"}})

	q := url.Values{"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}}
	code := issueCode(t, r, cookie, q)
	if rec := postToken(t, r, url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirectURI}, "code": {code}}); rec.Code != http.StatusOK {
		t.Errorf("a valid exchange after the guessing = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	got := warnings()
	if len(got) != 1 || !strings.Contains(got[0], `"client_id":"app"`) || !strings.Contains(got[0], `"failures":1`) {
		t.Errorf("warnings = %q, want one for app with failures 1", got)
	}
}

// The cooldown warning names a username by a bounded form: a 60 KiB one
// does not reach the log whole. The line is measured without its timestamp,
// whose length depends on the clock and the zone. Its 64-byte prefix is
// escaped by the JSON handler, so the ASCII row's line (176 bytes, about 218
// with the timestamp) is a sample, not the bound: a control byte becomes
// \u00XX and an invalid UTF-8 byte \ufffd, 6 bytes each, which is the
// longest escape of one byte. The bound is 6 × 64 bytes for the prefix plus
// 128 for the rest, which takes 112 in the ASCII row (the message, the keys,
// the "...", the cooldown, and the 12 hex characters of the digest, which
// only help correlate lines and may be shared by two usernames).
func TestLoginFailed_LogsABoundedUsername(t *testing.T) {
	tests := []struct {
		name   string
		prefix string // the username's first 64 bytes
		logged string // the username the line decodes to
		max    int
	}{
		{"ASCII", "mallory" + strings.Repeat("x", 57), "mallory" + strings.Repeat("x", 57) + "...", 200},
		{"control bytes", strings.Repeat("\x00", 64), strings.Repeat("\x00", 64) + "...", 6*64 + 128},
		{"invalid UTF-8", strings.Repeat("\xff", 64), strings.Repeat("\ufffd", 64) + "...", 6*64 + 128},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRoutes(t, false)
			var buf bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					if len(groups) == 0 && a.Key == slog.TimeKey {
						return slog.Attr{}
					}
					return a
				},
			})))
			t.Cleanup(func() { slog.SetDefault(old) })

			username := tc.prefix + strings.Repeat("x", 60<<10)
			for range throttle.FreeFailures {
				_, done := r.logins.Begin(username)
				if cooldown := done(true); cooldown > 0 {
					r.loginFailed(username, cooldown)
				}
			}
			line := strings.TrimSuffix(buf.String(), "\n")
			t.Logf("warning of %d bytes: %s", len(line), line)
			var logged struct{ Username string }
			if err := json.Unmarshal([]byte(line), &logged); err != nil || strings.Count(line, "\n") != 0 || len(line) > tc.max {
				t.Errorf("warning of %d bytes (%v), want one JSON line of at most %d: %.600s", len(line), err, tc.max, line)
			}
			if logged.Username != tc.logged {
				t.Errorf("logged username %q, want %q", logged.Username, tc.logged)
			}
		})
	}
}
