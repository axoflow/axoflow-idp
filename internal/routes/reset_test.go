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
	"net/url"
	"sync"
	"testing"
)

// addAdmin registers a second admin, so admin1 can demote or delete it.
func addAdmin(t *testing.T, r *Routes) string {
	t.Helper()
	if err := r.user.AdminRegister("admin1", "admin2", "admin2pass", []string{"admins"}, ""); err != nil {
		t.Fatalf("AdminRegister: %v", err)
	}
	admin2, ok := r.user.Authenticate("admin2", "admin2pass")
	if !ok {
		t.Fatal("admin2 cannot sign in")
	}
	return admin2.ID
}

// mintLink has issuer create a reset link for target through the admin panel.
func mintLink(t *testing.T, r *Routes, issuer, target string) string {
	t.Helper()
	cookie, csrf := r.authed(issuer)
	rec := postForm(r.AdminCreateResetLink, "/admin/users/reset-link", cookie, url.Values{"csrf_token": {csrf}, "user_id": {target}})
	m := linkRe.FindStringSubmatch(rec.Body.String())
	if rec.Code != http.StatusOK || m == nil {
		t.Fatalf("mint link: status %d", rec.Code)
	}
	tok, err := url.QueryUnescape(m[1])
	if err != nil {
		t.Fatalf("unescape token: %v", err)
	}
	return tok
}

func redeem(r *Routes, token, password string) int {
	return postForm(r.SetPassword, "/set-password", nil, url.Values{"token": {token}, "new_password": {password}}).Code
}

// A reset link carries its issuer's authority and stands for the target's
// password as it was: whatever takes either away, before the redemption or
// while it runs, makes the link refuse.
func TestSetPassword_LinkRefusedOnceRevoked(t *testing.T) {
	type routesAndIssuer struct {
		r      *Routes
		issuer string
	}
	tests := []struct {
		name    string
		revoke  func(t *testing.T, x routesAndIssuer)
		bobPass string // bob's password afterwards
	}{
		{"issuer demoted", func(t *testing.T, x routesAndIssuer) {
			cookie, csrf := x.r.authed("admin1")
			if rec := postForm(x.r.AdminUpdateUserGroups, "/admin/users/update-groups", cookie, url.Values{
				"csrf_token": {csrf}, "user_id": {x.issuer}, "groups": {"user"},
			}); rec.Code != http.StatusSeeOther {
				t.Fatalf("demote: status %d", rec.Code)
			}
		}, "bobpass1"},
		{"issuer deleted", func(t *testing.T, x routesAndIssuer) {
			cookie, csrf := x.r.authed("admin1")
			if rec := postForm(x.r.AdminDeleteUser, "/admin/users/delete", cookie, url.Values{
				"csrf_token": {csrf}, "user_id": {x.issuer},
			}); rec.Code != http.StatusSeeOther {
				t.Fatalf("delete: status %d", rec.Code)
			}
		}, "bobpass1"},
		{"target changed own password", func(t *testing.T, x routesAndIssuer) {
			cookie, csrf := x.r.authed("bob")
			if rec := postForm(x.r.ChangePassword, "/password", cookie, url.Values{
				"csrf_token": {csrf}, "current_password": {"bobpass1"}, "new_password": {"bobsown12"},
			}); rec.Code != http.StatusSeeOther {
				t.Fatalf("change password: status %d", rec.Code)
			}
		}, "bobsown12"},
		{"admin reset the target", func(t *testing.T, x routesAndIssuer) {
			cookie, csrf := x.r.authed("admin1")
			if rec := postForm(x.r.AdminResetPassword, "/admin/users/reset-password", cookie, url.Values{
				"csrf_token": {csrf}, "user_id": {"bob"}, "new_password": {"adminset1"},
			}); rec.Code != http.StatusSeeOther {
				t.Fatalf("admin reset: status %d", rec.Code)
			}
		}, "adminset1"},
	}

	for _, tt := range tests {
		for _, between := range []bool{false, true} {
			name := tt.name + " before redemption"
			if between {
				name = tt.name + " between consume and commit"
			}
			t.Run(name, func(t *testing.T) {
				r := newTestRoutes(t, false)
				x := routesAndIssuer{r, addAdmin(t, r)}
				tok := mintLink(t, r, x.issuer, "bob")
				if between {
					r.hooks.afterResetConsume = func() { tt.revoke(t, x) }
				} else {
					tt.revoke(t, x)
				}

				if code := redeem(r, tok, "linkpass1"); code != http.StatusBadRequest {
					t.Errorf("redemption status = %d, want 400", code)
				}
				if _, ok := r.user.Authenticate("bob", "linkpass1"); ok {
					t.Error("the link's password was set")
				}
				if _, ok := r.user.Authenticate("bob", tt.bobPass); !ok {
					t.Errorf("bob's password is no longer %q", tt.bobPass)
				}
			})
		}
	}
}

func TestSetPassword_CurrentAdminsLinkWorks(t *testing.T) {
	r := newTestRoutes(t, false)
	issuer := addAdmin(t, r)
	tok := mintLink(t, r, issuer, "bob")

	if code := redeem(r, tok, "linkpass1"); code != http.StatusSeeOther {
		t.Fatalf("redemption status = %d, want 303", code)
	}
	if _, ok := r.user.Authenticate("bob", "linkpass1"); !ok {
		t.Error("the link's password does not authenticate")
	}
}

// Two presentations of one link set at most one password.
func TestSetPassword_ConcurrentRedemptionsOneWins(t *testing.T) {
	r := newTestRoutes(t, false)
	tok := mintLink(t, r, "admin1", "bob")

	passwords := []string{"firstpass1", "secondpass2"}
	codes := make([]int, len(passwords))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, pw := range passwords {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i] = redeem(r, tok, pw)
		}()
	}
	close(start)
	wg.Wait()

	won := 0
	for i, code := range codes {
		_, authenticates := r.user.Authenticate("bob", passwords[i])
		switch code {
		case http.StatusSeeOther:
			won++
			if !authenticates {
				t.Errorf("redemption %d answered 303 but its password does not authenticate", i)
			}
		case http.StatusBadRequest:
			if authenticates {
				t.Errorf("redemption %d answered 400 but its password was set", i)
			}
		default:
			t.Errorf("redemption %d status = %d", i, code)
		}
	}
	if won != 1 {
		t.Errorf("%d redemptions answered 303 (codes %v), want exactly 1", won, codes)
	}
}
