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
	"testing"

	"github.com/axoflow/axoflow-idp/pkg/user"
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
