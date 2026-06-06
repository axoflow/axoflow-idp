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
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/axoflow/axoflow-idp/internal/resettoken"
	"github.com/axoflow/axoflow-idp/internal/session"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

func newTestRoutes(t *testing.T, static bool) *Routes {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(path, []byte(`[
		{"ID":"admin1","Username":"admin","Groups":["admins"]},
		{"ID":"bob","Username":"bob","Groups":["user"]}
	]`), 0o600); err != nil {
		t.Fatalf("write users: %v", err)
	}
	// Seed passwords with a writable store, then reopen with the desired mode.
	seed, err := user.New(user.Config{FilePath: path, UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("seed user store: %v", err)
	}
	for id, pw := range map[string]string{"admin1": "adminpass", "bob": "bobpass"} {
		if err := seed.SetPassword(id, pw); err != nil {
			t.Fatalf("seed password: %v", err)
		}
	}
	if err := seed.SaveUsers(); err != nil {
		t.Fatalf("save seed: %v", err)
	}

	u, err := user.New(user.Config{FilePath: path, Static: static, UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("user store: %v", err)
	}

	tpl, err := template.ParseGlob(filepath.Join("..", "..", "templates", "*.html"))
	if err != nil {
		t.Fatalf("parse templates: %v", err)
	}

	return &Routes{
		session:     session.New(),
		user:        u,
		template:    tpl,
		resetTokens: resettoken.New(time.Hour),
		baseURL:     "https://idp.example.com",
		csrfKey:     generateCSRFKey(),
	}
}

func (r *Routes) authed(userID string) (*http.Cookie, string) {
	sid := r.session.Create(userID)
	return &http.Cookie{Name: "session", Value: sid}, r.csrfToken(sid)
}

// --- ChangePassword (flow A) ---

func TestChangePassword_RequiresLogin(t *testing.T) {
	r := newTestRoutes(t, false)
	req := httptest.NewRequest(http.MethodGet, "/password", nil)
	rec := httptest.NewRecorder()

	r.ChangePassword(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("redirect = %q, want /login", loc)
	}
}

func TestChangePassword_WrongCurrentPassword(t *testing.T) {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("bob")

	form := url.Values{"current_password": {"WRONG"}, "new_password": {"newsecret"}, "csrf_token": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	r.ChangePassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if _, ok := r.user.Authenticate("bob", "bobpass"); !ok {
		t.Error("password must be unchanged after a failed attempt")
	}
}

func TestChangePassword_BadCSRF(t *testing.T) {
	r := newTestRoutes(t, false)
	cookie, _ := r.authed("bob")

	form := url.Values{"current_password": {"bobpass"}, "new_password": {"newsecret"}, "csrf_token": {"bad"}}
	req := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	r.ChangePassword(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestChangePassword_Success(t *testing.T) {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("bob")
	// A second device/session that must be invalidated.
	otherSession := r.session.Create("bob")

	form := url.Values{"current_password": {"bobpass"}, "new_password": {"newsecret"}, "csrf_token": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	r.ChangePassword(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if _, ok := r.user.Authenticate("bob", "newsecret"); !ok {
		t.Error("new password should authenticate")
	}
	if _, err := r.session.Get(otherSession); err == nil {
		t.Error("other sessions should have been invalidated")
	}
	if cookies := rec.Result().Cookies(); len(cookies) == 0 || cookies[0].Name != "session" {
		t.Error("a fresh session cookie should be set")
	}
}

func TestChangePassword_StaticRejected(t *testing.T) {
	r := newTestRoutes(t, true) // static / read-only user DB
	cookie, csrf := r.authed("bob")

	form := url.Values{"current_password": {"bobpass"}, "new_password": {"newsecret"}, "csrf_token": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	r.ChangePassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if _, ok := r.user.Authenticate("bob", "newsecret"); ok {
		t.Error("password must not change in static mode")
	}
	if _, ok := r.user.Authenticate("bob", "bobpass"); !ok {
		t.Error("original password must still work in static mode")
	}
}

// --- AdminCreateResetLink ---

var linkRe = regexp.MustCompile(`/set-password\?token=([A-Za-z0-9_\-]+)`)

func TestAdminCreateResetLink_NonAdminForbidden(t *testing.T) {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("bob") // bob is not an admin

	form := url.Values{"user_id": {"admin1"}, "csrf_token": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/reset-link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	r.AdminCreateResetLink(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestAdminCreateResetLink_SelfRejected(t *testing.T) {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("admin1")

	form := url.Values{"user_id": {"admin1"}, "csrf_token": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/reset-link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	r.AdminCreateResetLink(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestAdminCreateResetLink_Success(t *testing.T) {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("admin1")

	form := url.Values{"user_id": {"bob"}, "csrf_token": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/admin/users/reset-link", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	r.AdminCreateResetLink(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	m := linkRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("response should contain a /set-password link")
	}
	// The minted token must resolve to bob.
	userID, ok := r.resetTokens.Consume(m[1])
	if !ok || userID != "bob" {
		t.Errorf("token resolved to (%q,%v), want (bob,true)", userID, ok)
	}
}

func TestAdminPanel_HighlightsAdminGroup(t *testing.T) {
	r := newTestRoutes(t, false)
	cookie, _ := r.authed("admin1")

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	r.AdminPanel(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `class="badge admin"`) {
		t.Error("admin-group membership should be highlighted")
	}
	if !strings.Contains(body, "Member of the administrator group") {
		t.Error("admin badge should carry an explanatory tooltip")
	}
}

func TestAdminRegister_WithResetLink(t *testing.T) {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("admin1")

	form := url.Values{
		"auth_method": {"reset_link"},
		"username":    {"newuser"},
		"email":       {"new@example.com"},
		"groups":      {"user"},
		"csrf_token":  {csrf},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/register", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()

	r.AdminRegister(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	m := linkRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("response should contain a /set-password link")
	}
	// The new user exists but cannot log in until they use the link.
	if _, ok := r.user.Authenticate("newuser", ""); ok {
		t.Error("locked user should not authenticate with empty password")
	}

	userID, ok := r.resetTokens.Consume(m[1])
	if !ok {
		t.Fatal("minted token should be valid")
	}
	if err := r.user.SetPassword(userID, "chosen"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	if _, ok := r.user.Authenticate("newuser", "chosen"); !ok {
		t.Error("user should authenticate after setting a password via the link")
	}
}

// --- SetPassword (flow C) ---

func TestSetPassword_GetWithoutTokenIsInvalid(t *testing.T) {
	r := newTestRoutes(t, false)
	req := httptest.NewRequest(http.MethodGet, "/set-password", nil)
	rec := httptest.NewRecorder()

	r.SetPassword(rec, req)

	if !strings.Contains(rec.Body.String(), "invalid or has expired") {
		t.Error("expected invalid-link message")
	}
}

func TestSetPassword_Success(t *testing.T) {
	r := newTestRoutes(t, false)
	tok, _ := r.resetTokens.Create("bob")
	existing := r.session.Create("bob") // should be invalidated

	form := url.Values{"token": {tok}, "new_password": {"freshpass"}}
	req := httptest.NewRequest(http.MethodPost, "/set-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	r.SetPassword(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	if loc := rec.Header().Get("Location"); loc != "/login?flash=password_reset" {
		t.Errorf("redirect = %q", loc)
	}
	if _, ok := r.user.Authenticate("bob", "freshpass"); !ok {
		t.Error("new password should authenticate")
	}
	if _, ok := r.resetTokens.Consume(tok); ok {
		t.Error("token should already be consumed")
	}
	if _, err := r.session.Get(existing); err == nil {
		t.Error("existing sessions should be invalidated")
	}
}

func TestSetPassword_InvalidToken(t *testing.T) {
	r := newTestRoutes(t, false)
	form := url.Values{"token": {"nope"}, "new_password": {"freshpass"}}
	req := httptest.NewRequest(http.MethodPost, "/set-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	r.SetPassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestSetPassword_EmptyPasswordDoesNotConsumeToken(t *testing.T) {
	r := newTestRoutes(t, false)
	tok, _ := r.resetTokens.Create("bob")

	form := url.Values{"token": {tok}, "new_password": {""}}
	req := httptest.NewRequest(http.MethodPost, "/set-password", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	r.SetPassword(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	// Token must still be usable.
	if _, ok := r.resetTokens.Consume(tok); !ok {
		t.Error("token should not be consumed on an empty-password submission")
	}
}
