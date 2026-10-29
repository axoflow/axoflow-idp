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
	"strings"
	"testing"
	"time"

	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

// newIssueRoutes is newTestRoutes with the registration form open.
func newIssueRoutes(t *testing.T) *Routes {
	t.Helper()
	r := newTestRoutes(t, false)
	u, err := user.New(user.Config{FilePath: r.user.FilePath, UserAdminGroup: "admins", SelfRegistration: true})
	if err != nil {
		t.Fatalf("user store: %v", err)
	}
	r.user = u
	r.oidc = &oidc.Oidc{}
	return r
}

// resolvingSession reports whether rec set a session cookie that the store
// still resolves.
func resolvingSession(r *Routes, rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" && c.MaxAge >= 0 && c.Value != "" {
			if _, err := r.session.Get(c.Value); err == nil {
				return true
			}
		}
	}
	return false
}

// A session is issued on the strength of a password. If the password is
// rotated after it was proved but before the session exists, the rotation's
// sign-out cannot see that session, so the issuer must not keep it.
func TestIssueSession_RotationAfterProofLeavesNoSession(t *testing.T) {
	// Each issuer proves a password for an account; at the hook the account
	// is username with password current.
	issuers := []struct {
		name     string
		username string
		current  string
		issue    func(r *Routes) *httptest.ResponseRecorder
	}{
		{"login", "bob", "bobpass1", func(r *Routes) *httptest.ResponseRecorder {
			return postForm(r.Login, "/login", nil, url.Values{"username": {"bob"}, "password": {"bobpass1"}})
		}},
		{"registration", "carol", "password123", func(r *Routes) *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(url.Values{
				"username": {"carol"}, "email": {"carol@example.com"}, "password": {"password123"}, "password_confirm": {"password123"},
			}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			r.Register(rec, req)
			return rec
		}},
		{"password change", "bob", "bobnew123", func(r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("bob")
			return postForm(r.ChangePassword, "/password", cookie, url.Values{
				"csrf_token": {csrf}, "current_password": {"bobpass1"}, "new_password": {"bobnew123"},
			})
		}},
	}
	rotations := []struct {
		name   string
		rotate func(t *testing.T, r *Routes, id, current string)
	}{
		{"none", nil},
		{"own change", func(t *testing.T, r *Routes, id, current string) {
			cookie, csrf := r.authed(id)
			if rec := postForm(r.ChangePassword, "/password", cookie, url.Values{
				"csrf_token": {csrf}, "current_password": {current}, "new_password": {"rotated12"},
			}); rec.Code != http.StatusSeeOther {
				t.Errorf("own change: status %d", rec.Code)
			}
		}},
		{"admin reset", func(t *testing.T, r *Routes, id, _ string) {
			cookie, csrf := r.authed("admin1")
			if rec := postForm(r.AdminResetPassword, "/admin/users/reset-password", cookie, url.Values{
				"csrf_token": {csrf}, "user_id": {id}, "new_password": {"rotated12"},
			}); rec.Code != http.StatusSeeOther {
				t.Errorf("admin reset: status %d", rec.Code)
			}
		}},
		{"reset link", func(t *testing.T, r *Routes, id, _ string) {
			if code := redeem(r, mintLink(t, r, "admin1", id), "rotated12"); code != http.StatusSeeOther {
				t.Errorf("reset link: status %d", code)
			}
		}},
	}

	for _, is := range issuers {
		for _, rot := range rotations {
			t.Run(is.name+"/"+rot.name, func(t *testing.T) {
				r := newIssueRoutes(t)
				if rot.rotate != nil {
					r.hooks.beforeIssueSession = func() {
						r.hooks.beforeIssueSession = nil // the rotation's own issuance runs unhindered
						account, ok := r.user.Authenticate(is.username, is.current)
						if !ok {
							t.Fatalf("%s cannot sign in with %q at the hook", is.username, is.current)
						}
						rot.rotate(t, r, account.ID, is.current)
					}
				}

				rec := is.issue(r)

				if got, want := resolvingSession(r, rec), rot.rotate == nil; got != want {
					t.Errorf("response carries a resolving session = %v, want %v (status %d)", got, want, rec.Code)
				}
			})
		}
	}
}

// A rotation that commits after the issuer created the session but before it
// re-read the password must still leave no session: no Set-Cookie at all, and
// nothing in the store. The rotation goes through the library, so no route's
// sign-out removes the session for the issuer.
func TestIssueSession_RotationAfterCreateLeavesNoSession(t *testing.T) {
	issuers := []struct {
		name     string
		username string
		current  string
		issue    func(r *Routes) *httptest.ResponseRecorder
		status   int
		location string
	}{
		{"login", "bob", "bobpass1", func(r *Routes) *httptest.ResponseRecorder {
			return postForm(r.Login, "/login", nil, url.Values{"username": {"bob"}, "password": {"bobpass1"}})
		}, http.StatusUnauthorized, ""},
		{"registration", "carol", "password123", func(r *Routes) *httptest.ResponseRecorder {
			return postForm(r.Register, "/register", nil, url.Values{
				"username": {"carol"}, "email": {"carol@example.com"}, "password": {"password123"}, "password_confirm": {"password123"},
			})
		}, http.StatusCreated, ""},
		{"password change", "bob", "bobnew123", func(r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("bob")
			return postForm(r.ChangePassword, "/password", cookie, url.Values{
				"csrf_token": {csrf}, "current_password": {"bobpass1"}, "new_password": {"bobnew123"},
			})
		}, http.StatusSeeOther, "/login"},
	}
	for _, is := range issuers {
		t.Run(is.name, func(t *testing.T) {
			r := newIssueRoutes(t)
			var accountID string
			r.hooks.afterCreateSession = func() {
				account, ok := r.user.Authenticate(is.username, is.current)
				if !ok {
					t.Fatalf("%s cannot sign in with %q at the hook", is.username, is.current)
				}
				accountID = account.ID
				if err := r.user.AdminResetPassword("admin1", account.ID, "rotated12"); err != nil {
					t.Fatalf("rotate: %v", err)
				}
			}

			rec := is.issue(r)

			if rec.Code != is.status {
				t.Errorf("status = %d, want %d", rec.Code, is.status)
			}
			if loc := rec.Header().Get("Location"); loc != is.location {
				t.Errorf("Location = %q, want %q", loc, is.location)
			}
			if c := rec.Header()["Set-Cookie"]; len(c) != 0 {
				t.Errorf("response sets cookies %q, want none", c)
			}
			if accountID == "" {
				t.Fatal("the hook did not run")
			}
			if n := r.session.Count(accountID); n != 0 {
				t.Errorf("the store holds %d sessions for %s, want 0", n, is.username)
			}
		})
	}
}

func TestSessionCookieMaxAgeFollowsCookieTTL(t *testing.T) {
	for _, tc := range []struct {
		ttl  time.Duration
		want int
	}{
		{168 * time.Hour, 604800},
		{time.Hour, 3600},
		{1500 * time.Millisecond, 1},
	} {
		t.Run(tc.ttl.String(), func(t *testing.T) {
			r := newTestRoutes(t, false)
			r.cookieTTL = tc.ttl
			rec := postForm(r.Login, "/login", nil, url.Values{"username": {"bob"}, "password": {"bobpass1"}})
			for _, c := range rec.Result().Cookies() {
				if c.Name == "session" {
					if c.MaxAge != tc.want {
						t.Errorf("Max-Age = %d, want %d", c.MaxAge, tc.want)
					}
					return
				}
			}
			t.Fatalf("no session cookie (status %d)", rec.Code)
		})
	}
}
