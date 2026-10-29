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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/axoflow/axoflow-idp/internal/resettoken"
	"github.com/axoflow/axoflow-idp/pkg/user"
	"golang.org/x/crypto/bcrypt"
)

// With the derivation gate full, every route that derives a password hash
// answers 503 with Retry-After and changes nothing: no session, no account,
// no password, and the reset link stays usable.
func TestKDFBusy_Is503(t *testing.T) {
	authQuery := url.Values{"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}}
	tests := []struct {
		name string
		send func(t *testing.T, r *Routes) *httptest.ResponseRecorder
	}{
		{"POST /login", func(_ *testing.T, r *Routes) *httptest.ResponseRecorder {
			return postForm(r.Login, "/login", nil, url.Values{"username": {"bob"}, "password": {"bobpass1"}})
		}},
		{"POST /oidc/auth login form", func(_ *testing.T, r *Routes) *httptest.ResponseRecorder {
			return postForm(r.OidcAuth, "/oidc/auth?"+authQuery.Encode(), nil, url.Values{"username": {"bob"}, "password": {"bobpass1"}})
		}},
		{"POST /register", func(_ *testing.T, r *Routes) *httptest.ResponseRecorder {
			r.user.SelfRegistration = true
			return postForm(r.Register, "/register", nil, url.Values{
				"username": {"carol"}, "email": {"carol@example.com"}, "password": {"carolpass1"}, "password_confirm": {"carolpass1"},
			})
		}},
		{"POST /password", func(_ *testing.T, r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("bob")
			return postForm(r.ChangePassword, "/password", cookie, url.Values{"csrf_token": {csrf}, "current_password": {"bobpass1"}, "new_password": {"bobpass99"}})
		}},
		{"POST /set-password", func(t *testing.T, r *Routes) *httptest.ResponseRecorder {
			generation, _ := r.user.CredentialGeneration("bob")
			token, err := r.resetTokens.Create("bob", "admin1", generation)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			rec := postForm(r.SetPassword, "/set-password", nil, url.Values{"token": {token}, "new_password": {"bobpass99"}})
			if _, ok := r.resetTokens.Peek(token); !ok {
				t.Error("a refused reset spent the link")
			}
			return rec
		}},
		{"POST /admin/register", func(_ *testing.T, r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("admin1")
			return postForm(r.AdminRegister, "/admin/register", cookie, url.Values{"csrf_token": {csrf}, "username": {"carol"}, "password": {"carolpass1"}})
		}},
		{"POST /admin/users/reset-password", func(_ *testing.T, r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("admin1")
			return postForm(r.AdminResetPassword, "/admin/users/reset-password", cookie, url.Values{"csrf_token": {csrf}, "user_id": {"bob"}, "new_password": {"bobpass99"}})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newOidcTestRoutes(t)

			restore := user.SetKDFGate(0, 0, 0)
			rec := tc.send(t, r)
			restore()

			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "2" {
				t.Errorf("status = %d Retry-After %q, want 503 and 2", rec.Code, rec.Header().Get("Retry-After"))
			}
			if c := sessionCookieOf(rec); c != nil {
				t.Errorf("a refused request set the session cookie %v", c)
			}
			if n := r.user.Count(); n != 2 {
				t.Errorf("%d users, want 2", n)
			}
			if _, ok := r.user.Authenticate("bob", "bobpass1"); !ok {
				t.Error("bob's password changed")
			}
		})
	}
}

// A user whose ID is too long to salt a password hash keeps their password:
// each password write answers a generic 500, logs the cause, and spends no
// reset link and no session.
func TestPasswordWrite_LongIDKeepsThePassword(t *testing.T) {
	long := strings.Repeat("i", 300)
	old, err := bcrypt.GenerateFromPassword([]byte("oldpass12"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	users := fmt.Sprintf(`[{"ID":"admin1","Username":"admin","Groups":["admins"],"Password":%q},{"ID":%q,"Username":"longid","Password":%q}]`,
		string(old), long, string(old))
	tests := []struct {
		name   string
		submit func(r *Routes) *httptest.ResponseRecorder
	}{
		{"reset link", func(r *Routes) *httptest.ResponseRecorder {
			generation, _ := r.user.CredentialGeneration(long)
			token, err := r.resetTokens.Create(long, "admin1", generation)
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			rec := postForm(r.SetPassword, "/set-password", nil, url.Values{"token": {token}, "new_password": {"newpass12"}})
			if !tokenHeld(r, token) {
				t.Error("the reset link was spent")
			}
			return rec
		}},
		{"change password", func(r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed(long)
			rec := postForm(r.ChangePassword, "/password", cookie, url.Values{"csrf_token": {csrf}, "current_password": {"oldpass12"}, "new_password": {"newpass12"}})
			if _, err := r.session.Get(cookie.Value); err != nil {
				t.Errorf("the session ended: %v", err)
			}
			return rec
		}},
		{"admin reset", func(r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("admin1")
			return postForm(r.AdminResetPassword, "/admin/users/reset-password", cookie, url.Values{"csrf_token": {csrf}, "user_id": {long}, "new_password": {"newpass12"}})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newBootstrapRoutes(t, users, user.Config{UserAdminGroup: "admins"})
			r.resetTokens = resettoken.New(time.Hour)
			warnings := captureWarnings(t)
			rec := tc.submit(r)
			if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "too long") {
				t.Errorf("status = %d, want a generic 500: %.200s", rec.Code, rec.Body.String())
			}
			if logged := warnings(); len(logged) != 1 || !strings.Contains(logged[0], user.ErrIDTooLong.Error()) {
				t.Errorf("logged %q, want the cause", logged)
			}
			if _, ok := r.user.Authenticate("longid", "oldpass12"); !ok {
				t.Error("the old password no longer verifies")
			}
		})
	}
}
