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
	"strings"
	"testing"

	"github.com/axoflow/axoflow-idp/pkg/user"
)

func TestRenderError_Modes(t *testing.T) {
	r := newTestRoutes(t, false)

	tests := []struct {
		name      string
		fetchMode bool
		wantHTML  bool
	}{
		{name: "browser request gets the styled page", fetchMode: false, wantHTML: true},
		{name: "fetch request stays plain text", fetchMode: true, wantHTML: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/whatever", nil)
			if tt.fetchMode {
				req.Header.Set("X-Requested-With", "fetch")
			}
			rec := httptest.NewRecorder()

			r.renderError(rec, req, http.StatusForbidden, "Access Denied", "Admin access is required for this page.")

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
			isHTML := strings.Contains(rec.Body.String(), "<!doctype html>")
			if isHTML != tt.wantHTML {
				t.Errorf("html = %v, want %v (body %q)", isHTML, tt.wantHTML, head(rec.Body.String(), 80))
			}
			if !strings.Contains(rec.Body.String(), "Admin access is required") {
				t.Errorf("body does not contain the message")
			}
		})
	}
}

func TestNotFound_RendersStyledPage(t *testing.T) {
	r := newTestRoutes(t, false)
	rec := httptest.NewRecorder()

	r.NotFound(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if !strings.Contains(rec.Body.String(), "Page Not Found") {
		t.Errorf("body does not contain the 404 title")
	}
}

func TestRegister_DisabledRendersStyledPage(t *testing.T) {
	r := newBootstrapRoutes(t, `[{"ID":"alice","Username":"alice"}]`, user.Config{UserAdminGroup: "admins"})
	rec := httptest.NewRecorder()

	r.Register(rec, httptest.NewRequest(http.MethodGet, "/register", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if !strings.Contains(rec.Body.String(), "Registration Closed") {
		t.Errorf("body does not contain the styled title, got %q", head(rec.Body.String(), 120))
	}
}

// The expired-session page sends the user to sign in again, not to the home
// page (which would just bounce an unauthenticated visitor around).
func TestSessionExpired_LinksToLogin(t *testing.T) {
	r := newTestRoutes(t, false)
	rec := httptest.NewRecorder()

	r.renderSessionExpired(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rec.Body.String(), `href="/login"`) {
		t.Errorf("body does not link to /login, got %q", head(rec.Body.String(), 400))
	}
}

// The users API is a JSON endpoint, so its errors must stay plain text even
// for browser-shaped requests — a machine client must never get an HTML page.
func TestAdminUsersAPI_ErrorsStayPlainText(t *testing.T) {
	r := newTestRoutes(t, false)

	tests := []struct {
		name       string
		userID     string
		wantStatus int
	}{
		{name: "no session", userID: "", wantStatus: http.StatusUnauthorized},
		{name: "not an admin", userID: "bob", wantStatus: http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/users/api", nil)
			if tt.userID != "" {
				cookie, _ := r.authed(tt.userID)
				req.AddCookie(cookie)
			}
			rec := httptest.NewRecorder()

			r.AdminUsersAPI(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if strings.Contains(rec.Body.String(), "<!doctype html>") {
				t.Errorf("body is HTML, want plain text, got %q", head(rec.Body.String(), 80))
			}
		})
	}
}

// head returns the first n bytes of s for a failure message.
func head(s string, n int) string {
	return s[:min(len(s), n)]
}
