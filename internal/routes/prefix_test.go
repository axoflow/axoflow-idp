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
	"path/filepath"
	"strings"
	"testing"
)

// newPrefixedTestRoutes wires routes as if baseUrl carried the given path, so
// both the Go side and the templates are built from the same prefix.
func newPrefixedTestRoutes(t *testing.T, prefix string) (*Routes, *http.Cookie) {
	t.Helper()
	r, cookie := newOidcTestRoutes(t)
	r.prefix = prefix
	tpl, err := parseTemplates(filepath.Join("..", "..", "templates"), prefix)
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}
	r.template = tpl
	return r, cookie
}

func cookiePath(t *testing.T, rec *httptest.ResponseRecorder, name string) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c.Path
		}
	}
	t.Fatalf("no %q cookie in response", name)
	return ""
}

func TestPathPrefix(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		root   string
	}{
		{name: "served from the host root", prefix: "", root: "/"},
		{name: "served under /idp", prefix: "/idp", root: "/idp/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, cookie := newPrefixedTestRoutes(t, tc.prefix)

			// Redirects stay inside the prefix.
			req := httptest.NewRequest(http.MethodGet, tc.root+"login", nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			r.Login(rec, req)
			if loc := rec.Header().Get("Location"); loc != tc.root {
				t.Errorf("login redirect = %q, want %q", loc, tc.root)
			}

			// Rendered pages link back through the prefix.
			req = httptest.NewRequest(http.MethodGet, tc.root, nil)
			req.AddCookie(cookie)
			rec = httptest.NewRecorder()
			r.Index(rec, req)
			wantLink := `href="` + tc.prefix + `/password"`
			if !strings.Contains(rec.Body.String(), wantLink) {
				t.Errorf("index page does not contain %s", wantLink)
			}

			// The session cookie is scoped to the prefix, and the cookie that
			// clears it must use the same path or logout cannot delete it.
			rec = httptest.NewRecorder()
			r.setSessionCookie(rec, "a-session-id")
			sessionPath := cookiePath(t, rec, "session")
			if sessionPath != tc.root {
				t.Errorf("session cookie path = %q, want %q", sessionPath, tc.root)
			}

			req = httptest.NewRequest(http.MethodPost, tc.root+"logout", nil)
			req.AddCookie(cookie)
			rec = httptest.NewRecorder()
			r.Logout(rec, req)
			if got := cookiePath(t, rec, "session"); got != sessionPath {
				t.Errorf("logout cookie path = %q, want %q (the session cookie path)", got, sessionPath)
			}
		})
	}
}
