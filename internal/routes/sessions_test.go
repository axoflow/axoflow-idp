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
)

func TestAdminDeleteUser_EndsTheUsersSessions(t *testing.T) {
	r := newTestRoutes(t, false)
	bobSession := r.session.Create("bob")
	cookie, csrf := r.authed("admin1")

	rec := postForm(r.AdminDeleteUser, "/admin/users/delete", cookie, url.Values{"csrf_token": {csrf}, "user_id": {"bob"}})

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if _, err := r.session.Get(bobSession); err == nil {
		t.Error("the deleted user's session is still held")
	}
	if _, err := r.session.Get(cookie.Value); err != nil {
		t.Error("the admin's session was ended")
	}
}

// Signing in on the /oidc/auth form replaces the browser's session cookie, so
// the session behind the old cookie is ended rather than left behind.
func TestOidcAuth_LoginEndsTheReplacedSession(t *testing.T) {
	tests := []struct {
		name         string
		username     string
		password     string
		wantReplaced bool
	}{
		{"same user", "bob", "bobpass1", true},
		{"another user", "admin", "adminpass", true},
		{"failed login", "bob", "wrong", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, oldCookie := newOidcTestRoutes(t)
			q := url.Values{"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}}
			req := httptest.NewRequest(http.MethodPost, "/oidc/auth?"+q.Encode(),
				strings.NewReader(url.Values{"username": {tt.username}, "password": {tt.password}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(oldCookie)
			rec := httptest.NewRecorder()

			r.OidcAuth(rec, req)

			_, err := r.session.Get(oldCookie.Value)
			if replaced := err != nil; replaced != tt.wantReplaced {
				t.Errorf("old session ended = %v, want %v (status %d)", replaced, tt.wantReplaced, rec.Code)
			}
			if tt.wantReplaced && !resolvingSession(r, rec) {
				t.Errorf("no new session issued (status %d)", rec.Code)
			}
		})
	}
}
