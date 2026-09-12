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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/axoflow/axoflow-idp/internal/session"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

// newBootstrapRoutes builds a Routes over a user database with the given
// contents and self-registration setting, so the empty-database ("not
// bootstrapped yet") paths can be exercised.
func newBootstrapRoutes(t *testing.T, users string, selfRegistration, static bool) *Routes {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(users), 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}

	u, err := user.New(user.Config{
		FilePath:         path,
		Static:           static,
		SelfRegistration: selfRegistration,
		UserAdminGroup:   "admins",
	})
	if err != nil {
		t.Fatalf("user store: %v", err)
	}

	tpl, err := parseTemplates(filepath.Join("..", "..", "templates"), "")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	return &Routes{
		session:  session.New(),
		user:     u,
		template: tpl,
		baseURL:  "https://idp.example.com",
		csrfKey:  generateCSRFKey(),
	}
}

func TestLogin_RedirectsToRegisterWhenDatabaseIsEmpty(t *testing.T) {
	tests := []struct {
		name             string
		users            string
		selfRegistration bool
		static           bool
		wantRedirect     bool
	}{
		{
			name:             "empty database with self-registration",
			users:            `[]`,
			selfRegistration: true,
			wantRedirect:     true,
		},
		{
			name:             "empty database without self-registration",
			users:            `[]`,
			selfRegistration: false,
			wantRedirect:     false,
		},
		{
			name:             "empty but static database",
			users:            `[]`,
			selfRegistration: true,
			static:           true,
			wantRedirect:     false,
		},
		{
			name:             "database with a user",
			users:            `[{"ID":"alice","Username":"alice","Groups":["user"]}]`,
			selfRegistration: true,
			wantRedirect:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newBootstrapRoutes(t, tt.users, tt.selfRegistration, tt.static)
			rec := httptest.NewRecorder()

			r.Login(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

			if tt.wantRedirect {
				if rec.Code != http.StatusFound {
					t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
				}
				if loc := rec.Header().Get("Location"); loc != "/register" {
					t.Errorf("redirect = %q, want /register", loc)
				}
				return
			}
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d (body should be the login form)", rec.Code, http.StatusOK)
			}
		})
	}
}

// The bootstrap redirect is scoped to the path prefix the IdP is served under.
func TestLogin_BootstrapRedirectHonorsPrefix(t *testing.T) {
	r := newBootstrapRoutes(t, `[]`, true, false)
	r.prefix = "/idp"
	rec := httptest.NewRecorder()

	r.Login(rec, httptest.NewRequest(http.MethodGet, "/idp/login", nil))

	if loc := rec.Header().Get("Location"); loc != "/idp/register" {
		t.Errorf("redirect = %q, want /idp/register", loc)
	}
}

// POST /login is left alone: Authenticate fails safely on an empty database.
func TestLogin_PostIsNotRedirectedWhenDatabaseIsEmpty(t *testing.T) {
	r := newBootstrapRoutes(t, `[]`, true, false)
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	r.Login(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// A self-demotion attempt from the admin panel's fetch-based modal gets a
// plain-text error (shown inside the modal); a plain form post gets the full
// panel with the error banner.
func TestAdminUpdateUserGroups_SelfDemotionErrorModes(t *testing.T) {
	tests := []struct {
		name       string
		fetchMode  bool
		wantInBody string
	}{
		{name: "fetch request gets plain text", fetchMode: true, wantInBody: "cannot remove the admin group from yourself"},
		{name: "form post gets the panel with a banner", fetchMode: false, wantInBody: "<table"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestRoutes(t, false)
			cookie, csrf := r.authed("admin1")

			form := url.Values{"user_id": {"admin1"}, "groups": {"user"}, "csrf_token": {csrf}}
			req := httptest.NewRequest(http.MethodPost, "/admin/users/update-groups", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.fetchMode {
				req.Header.Set("X-Requested-With", "fetch")
			}
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()

			r.AdminUpdateUserGroups(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
			}
			if !strings.Contains(rec.Body.String(), tt.wantInBody) {
				t.Errorf("body does not contain %q", tt.wantInBody)
			}
			if !strings.Contains(rec.Body.String(), "cannot remove the admin group from yourself") {
				t.Errorf("body does not contain the error message")
			}
		})
	}
}

// With AllowBootstrap alone (self-registration off), the login page redirects
// to /register only while the database is empty.
func TestLogin_AllowBootstrapRedirect(t *testing.T) {
	tests := []struct {
		name         string
		users        string
		wantRedirect bool
	}{
		{name: "empty database", users: `[]`, wantRedirect: true},
		{name: "after the first user", users: `[{"ID":"alice","Username":"alice","Groups":["user"]}]`, wantRedirect: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "users.json")
			if err := os.WriteFile(path, []byte(tt.users), 0o600); err != nil {
				t.Fatalf("write users: %v", err)
			}
			u, err := user.New(user.Config{FilePath: path, AllowBootstrap: true, UserAdminGroup: "admins"})
			if err != nil {
				t.Fatalf("user store: %v", err)
			}
			tpl, err := parseTemplates(filepath.Join("..", "..", "templates"), "")
			if err != nil {
				t.Fatalf("parse templates: %v", err)
			}
			r := &Routes{session: session.New(), user: u, template: tpl, csrfKey: generateCSRFKey()}
			rec := httptest.NewRecorder()

			r.Login(rec, httptest.NewRequest(http.MethodGet, "/login", nil))

			if tt.wantRedirect && (rec.Code != http.StatusFound || rec.Header().Get("Location") != "/register") {
				t.Errorf("got %d %q, want 302 /register", rec.Code, rec.Header().Get("Location"))
			}
			if !tt.wantRedirect && rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200 (login form)", rec.Code)
			}
		})
	}
}

// A registration that loses the bootstrap race (or arrives after the window
// closed) gets a 403 from the POST as well, enforced inside user.SelfRegister.
func TestRegister_BootstrapWindowCloses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(`[]`), 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}
	u, err := user.New(user.Config{FilePath: path, AllowBootstrap: true, UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("user store: %v", err)
	}
	tpl, err := parseTemplates(filepath.Join("..", "..", "templates"), "")
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	r := &Routes{session: session.New(), user: u, template: tpl, csrfKey: generateCSRFKey()}

	post := func(username string) *httptest.ResponseRecorder {
		form := url.Values{
			"username":         {username},
			"email":            {username + "@example.com"},
			"password":         {"password123"},
			"password_confirm": {"password123"},
		}
		req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		r.Register(rec, req)
		return rec
	}

	if rec := post("first"); rec.Code != http.StatusCreated {
		t.Fatalf("first registration status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if rec := post("second"); rec.Code != http.StatusForbidden {
		t.Errorf("second registration status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
