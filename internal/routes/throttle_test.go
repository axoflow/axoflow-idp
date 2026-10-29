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
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/axoflow/axoflow-idp/internal/throttle"
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
// whose length depends on the clock and the zone.
func TestLoginFailed_LogsABoundedUsername(t *testing.T) {
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

	username := "mallory" + strings.Repeat("x", 60<<10)
	for range throttle.FreeFailures {
		r.loginFailed(username)
	}
	line := strings.TrimSuffix(buf.String(), "\n")
	t.Logf("warning of %d bytes: %s", len(line), line)
	if strings.Count(line, "\n") != 0 || len(line) >= 200 || !strings.Contains(line, `"username":"mallory`) {
		t.Errorf("warning of %d bytes, want one line under 200 naming the username's start: %.300s", len(line), line)
	}
}
