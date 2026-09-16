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
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

// newBootstrapRoutes builds a Routes over a user database with the given
// contents and policy. cfg.FilePath is filled in by the helper.
func newBootstrapRoutes(t *testing.T, users string, cfg user.Config) *Routes {
	t.Helper()
	cfg.FilePath = filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(cfg.FilePath, []byte(users), 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}

	u, err := user.New(cfg)
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
		oidc:     &oidc.Oidc{},
		template: tpl,
		baseURL:  "https://idp.example.com",
		csrfKey:  generateCSRFKey(),
	}
}

// postRegister submits the public registration form for username.
func postRegister(t *testing.T, r *Routes, username string) *httptest.ResponseRecorder {
	t.Helper()
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

func TestLogin_RedirectsToRegisterWhenDatabaseIsEmpty(t *testing.T) {
	const withUser = `[{"ID":"alice","Username":"alice","Groups":["user"]}]`

	tests := []struct {
		name         string
		users        string
		cfg          user.Config
		wantRedirect bool
	}{
		{
			name:         "empty database with self-registration",
			users:        `[]`,
			cfg:          user.Config{SelfRegistration: true},
			wantRedirect: true,
		},
		{
			name:         "empty database with allowBootstrap only",
			users:        `[]`,
			cfg:          user.Config{AllowBootstrap: true},
			wantRedirect: true,
		},
		{
			name:  "empty database with registration closed",
			users: `[]`,
		},
		{
			name:  "empty but static database",
			users: `[]`,
			cfg:   user.Config{SelfRegistration: true, Static: true},
		},
		{
			name:  "database with a user and self-registration",
			users: withUser,
			cfg:   user.Config{SelfRegistration: true},
		},
		{
			name:  "database with a user and allowBootstrap only",
			users: withUser,
			cfg:   user.Config{AllowBootstrap: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.UserAdminGroup = "admins"
			r := newBootstrapRoutes(t, tt.users, tt.cfg)
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
	r := newBootstrapRoutes(t, `[]`, user.Config{SelfRegistration: true, UserAdminGroup: "admins"})
	r.prefix = "/idp"
	rec := httptest.NewRecorder()

	r.Login(rec, httptest.NewRequest(http.MethodGet, "/idp/login", nil))

	if loc := rec.Header().Get("Location"); loc != "/idp/register" {
		t.Errorf("redirect = %q, want /idp/register", loc)
	}
}

// POST /login is left alone: Authenticate fails safely on an empty database.
func TestLogin_PostIsNotRedirectedWhenDatabaseIsEmpty(t *testing.T) {
	r := newBootstrapRoutes(t, `[]`, user.Config{SelfRegistration: true, UserAdminGroup: "admins"})
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	r.Login(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAdminUpdateUserGroups_SelfDemotionErrorModes(t *testing.T) {
	tests := []struct {
		name      string
		fetchMode bool
		wantPanel bool
	}{
		{name: "fetch request gets plain text", fetchMode: true, wantPanel: false},
		{name: "form post gets the panel with a banner", fetchMode: false, wantPanel: true},
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
			body := rec.Body.String()
			if !strings.Contains(body, "cannot remove the admin group from yourself") {
				t.Errorf("body does not contain the error message")
			}
			if gotPanel := strings.Contains(body, "<table"); gotPanel != tt.wantPanel {
				t.Errorf("body is the admin panel = %v, want %v", gotPanel, tt.wantPanel)
			}
		})
	}
}

func TestRegister_BootstrapWindowCloses(t *testing.T) {
	r := newBootstrapRoutes(t, `[]`, user.Config{AllowBootstrap: true, UserAdminGroup: "admins"})

	if rec := postRegister(t, r, "first"); rec.Code != http.StatusCreated {
		t.Fatalf("first registration status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if rec := postRegister(t, r, "second"); rec.Code != http.StatusForbidden {
		t.Errorf("second registration status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestRegister_AutoLogin(t *testing.T) {
	r := newBootstrapRoutes(t, `[]`, user.Config{AllowBootstrap: true, UserAdminGroup: "admins"})

	rec := postRegister(t, r, "first")
	if rec.Code != http.StatusCreated {
		t.Fatalf("registration status = %d, want %d", rec.Code, http.StatusCreated)
	}

	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("registration response did not set a session cookie")
	}

	// The session must authenticate: /login with it redirects to the profile.
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	r.Login(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Errorf("GET /login with session = %d %q, want 302 /", rec.Code, rec.Header().Get("Location"))
	}
}
