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

// Browser-facing failures render the styled error page; requests from the
// admin panel's fetch-based modals keep getting plain text for the inline
// error line.
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
				t.Errorf("html = %v, want %v (body %q)", isHTML, tt.wantHTML, rec.Body.String()[:80])
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

// GET /register with registration closed renders the styled page too.
func TestRegister_DisabledRendersStyledPage(t *testing.T) {
	r := newBootstrapRoutes(t, `[{"ID":"alice","Username":"alice"}]`, user.Config{UserAdminGroup: "admins"})
	rec := httptest.NewRecorder()

	r.Register(rec, httptest.NewRequest(http.MethodGet, "/register", nil))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if !strings.Contains(rec.Body.String(), "Registration Closed") {
		t.Errorf("body does not contain the styled title, got %q", rec.Body.String()[:120])
	}
}
