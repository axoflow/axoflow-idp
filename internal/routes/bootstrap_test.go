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
	"os"
	"path/filepath"
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
