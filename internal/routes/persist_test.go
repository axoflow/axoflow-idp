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
	"reflect"
	"strings"
	"testing"

	"github.com/axoflow/axoflow-idp/pkg/user"
)

// readOnlyDir makes the directory holding the user database unwritable until
// the returned func runs (or the test ends), so every save fails before the
// new file is installed.
func readOnlyDir(t *testing.T, u *user.User) func() {
	t.Helper()
	dir := filepath.Dir(u.FilePath)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	restore := func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("chmod: %v", err)
		}
	}
	t.Cleanup(restore)
	if f, err := os.CreateTemp(dir, "probe"); err == nil {
		_ = f.Close()
		t.Skip("directory permissions are not enforced (running as root?)")
	}
	return restore
}

func postForm(handler http.HandlerFunc, path string, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// A failed save leaves memory as it was and answers with a generic 500: the
// cause names the file path, so it goes to the log only.
func TestSaveFailure_EveryRouteIsGenericAndRollsBack(t *testing.T) {
	tests := []struct {
		name string
		send func(r *Routes) *httptest.ResponseRecorder
	}{
		{"change password", func(r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("bob")
			return postForm(r.ChangePassword, "/password", cookie, url.Values{
				"csrf_token": {csrf}, "current_password": {"bobpass1"}, "new_password": {"newpass123"},
			})
		}},
		{"set password", func(r *Routes) *httptest.ResponseRecorder {
			tok, _ := r.resetTokens.Create("bob")
			return postForm(r.SetPassword, "/set-password", nil, url.Values{"token": {tok}, "new_password": {"newpass123"}})
		}},
		{"admin register", func(r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("admin1")
			return postForm(r.AdminRegister, "/admin/register", cookie, url.Values{
				"csrf_token": {csrf}, "username": {"dave"}, "password": {"davepass1"},
			})
		}},
		{"admin register with reset link", func(r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("admin1")
			return postForm(r.AdminRegister, "/admin/register", cookie, url.Values{
				"csrf_token": {csrf}, "username": {"dave"}, "auth_method": {"reset_link"},
			})
		}},
		{"admin delete", func(r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("admin1")
			return postForm(r.AdminDeleteUser, "/admin/users/delete", cookie, url.Values{"csrf_token": {csrf}, "user_id": {"bob"}})
		}},
		{"admin reset password", func(r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("admin1")
			return postForm(r.AdminResetPassword, "/admin/users/reset-password", cookie, url.Values{
				"csrf_token": {csrf}, "user_id": {"bob"}, "new_password": {"newpass123"},
			})
		}},
		{"admin update groups", func(r *Routes) *httptest.ResponseRecorder {
			cookie, csrf := r.authed("admin1")
			return postForm(r.AdminUpdateUserGroups, "/admin/users/update-groups", cookie, url.Values{
				"csrf_token": {csrf}, "user_id": {"bob"}, "groups": {"ops"},
			})
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestRoutes(t, false)
			before, _ := r.user.AdminList("admin1")
			bob, _ := r.user.Get("bob")
			readOnlyDir(t, r.user)

			rec := tt.send(r)

			if rec.Code != http.StatusInternalServerError {
				t.Errorf("status = %d, want 500", rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "could not save the user database") {
				t.Errorf("body lacks the generic message: %s", head(body, 300))
			}
			if strings.Contains(body, filepath.Dir(r.user.FilePath)) {
				t.Error("body discloses the database path")
			}
			if after, _ := r.user.AdminList("admin1"); !reflect.DeepEqual(after, before) {
				t.Errorf("memory changed despite the failed save:\nbefore %+v\nafter  %+v", before, after)
			}
			if got, _ := r.user.Get("bob"); got.Password != bob.Password {
				t.Error("bob's password changed despite the failed save")
			}
		})
	}
}

// Issue #24: a failed first registration must not leave a bootstrap admin in
// memory only (lost at the next restart) with the window closed behind it.
func TestRegister_FailedSaveReopensBootstrap(t *testing.T) {
	r := newBootstrapRoutes(t, `[]`, user.Config{AllowBootstrap: true, UserAdminGroup: "admins"})
	restore := readOnlyDir(t, r.user)

	rec := postRegister(t, r, "alice")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), filepath.Dir(r.user.FilePath)) {
		t.Error("body discloses the database path")
	}
	if n := r.user.Count(); n != 0 {
		t.Fatalf("memory holds %d users after the failed save, want 0", n)
	}
	if !r.user.RegistrationOpen() {
		t.Fatal("bootstrap window closed after the failed save")
	}

	restore()
	if rec := postRegister(t, r, "alice"); rec.Code != http.StatusCreated {
		t.Fatalf("retry status = %d, want 201", rec.Code)
	}
	reloaded, err := user.New(user.Config{FilePath: r.user.FilePath, UserAdminGroup: "admins"})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	alice, ok := reloaded.Authenticate("alice", "password123")
	if !ok || reloaded.Count() != 1 || !reloaded.IsAdmin(&alice) {
		t.Errorf("reloaded database holds %d users, alice %+v (login %v); want alice alone, as admin", reloaded.Count(), alice, ok)
	}
}
