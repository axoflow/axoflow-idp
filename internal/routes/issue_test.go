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
