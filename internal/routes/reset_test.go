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
	"time"
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

// A reset link carries its issuer's authority and the target's credential
// generation at the moment it was minted: whatever takes the authority away
// or writes the target's password, before the redemption or while it runs,
// makes the link refuse.
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

// tokenHeld reports whether the reset store still holds token.
func tokenHeld(r *Routes, token string) bool {
	_, ok := r.resetTokens.Peek(token)
	return ok
}

// assertOnlyPassword checks that bob signs in with want and with none of
// refused.
func assertOnlyPassword(t *testing.T, r *Routes, want string, refused ...string) {
	t.Helper()
	if _, ok := r.user.Authenticate("bob", want); !ok {
		t.Errorf("bob's password is no longer %q", want)
	}
	for _, pw := range refused {
		if _, ok := r.user.Authenticate("bob", pw); ok {
			t.Errorf("bob's password is %q", pw)
		}
	}
}

// A password write that commits before the redemption reads anything, and
// whose route has not yet revoked the link (here: no route at all), still
// refuses a link minted before it.
func TestSetPassword_LinkRefusedAfterAnUnrevokedWrite(t *testing.T) {
	tests := []struct {
		name  string
		write func(r *Routes) error
	}{
		{"own change", func(r *Routes) error {
			_, err := r.user.ChangePassword("bob", "bobpass1", "rotated12")
			return err
		}},
		{"admin reset", func(r *Routes) error { return r.user.AdminResetPassword("admin1", "bob", "rotated12") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestRoutes(t, false)
			tok := mintLink(t, r, "admin1", "bob")
			if err := tt.write(r); err != nil {
				t.Fatalf("write: %v", err)
			}

			if code := redeem(r, tok, "linkpass1"); code != http.StatusBadRequest {
				t.Errorf("redemption status = %d, want 400", code)
			}
			assertOnlyPassword(t, r, "rotated12", "linkpass1", "bobpass1")
			if tokenHeld(r, tok) {
				t.Error("the refused link is still held")
			}
		})
	}
}

// A link minted while another link's redemption is between Consume and its
// commit predates the password that redemption sets, so it must not work.
func TestSetPassword_LinkMintedDuringARedemptionIsRefused(t *testing.T) {
	r := newTestRoutes(t, false)
	first := mintLink(t, r, "admin1", "bob")
	var second string
	r.hooks.afterResetConsume = func() {
		r.hooks.afterResetConsume = nil
		second = mintLink(t, r, "admin1", "bob")
	}

	if code := redeem(r, first, "firstpass1"); code != http.StatusSeeOther {
		t.Fatalf("first redemption status = %d, want 303", code)
	}
	if tokenHeld(r, second) {
		t.Error("the link minted during the redemption survived its success")
	}
	if code := redeem(r, second, "secondpass2"); code != http.StatusBadRequest {
		t.Errorf("second redemption status = %d, want 400", code)
	}
	assertOnlyPassword(t, r, "firstpass1", "secondpass2", "bobpass1")
	if tokenHeld(r, second) {
		t.Error("the second link is still held")
	}
}

// Setting the password a user already has is still a password write: the hash
// is the same (the salt is the user ID), but a link minted before it refuses.
func TestSetPassword_LinkRefusedAfterASamePasswordReset(t *testing.T) {
	for _, between := range []bool{false, true} {
		name := "before redemption"
		if between {
			name = "between consume and commit"
		}
		t.Run(name, func(t *testing.T) {
			r := newTestRoutes(t, false)
			before, _ := r.user.Get("bob")
			tok := mintLink(t, r, "admin1", "bob")
			reset := func() {
				if err := r.user.AdminResetPassword("admin1", "bob", "bobpass1"); err != nil {
					t.Errorf("AdminResetPassword: %v", err)
				}
				if after, _ := r.user.Get("bob"); after.Password != before.Password {
					t.Error("the same password produced another hash; the test needs equal hashes")
				}
			}
			if between {
				r.hooks.afterResetConsume = reset
			} else {
				reset()
			}

			if code := redeem(r, tok, "linkpass1"); code != http.StatusBadRequest {
				t.Errorf("redemption status = %d, want 400", code)
			}
			assertOnlyPassword(t, r, "bobpass1", "linkpass1")
		})
	}
}

// A link for a deleted user does not reach a new account with that username.
func TestSetPassword_LinkRefusedForAReRegisteredUsername(t *testing.T) {
	r := newTestRoutes(t, false)
	tok := mintLink(t, r, "admin1", "bob")
	if err := r.user.AdminDelete("admin1", "bob"); err != nil {
		t.Fatalf("AdminDelete: %v", err)
	}
	r.user.SelfRegistration = true
	if _, _, err := r.user.SelfRegister("bob", "newbob123", nil, ""); err != nil {
		t.Fatalf("SelfRegister: %v", err)
	}

	if code := redeem(r, tok, "linkpass1"); code != http.StatusBadRequest {
		t.Errorf("redemption status = %d, want 400", code)
	}
	assertOnlyPassword(t, r, "newbob123", "linkpass1")
}

// Two presentations of one link set at most one password, even when both
// have passed Peek, the user lookup and the hashing before either consumes.
func TestSetPassword_ConcurrentRedemptionsOneWins(t *testing.T) {
	r := newTestRoutes(t, false)
	tok := mintLink(t, r, "admin1", "bob")
	before, _ := r.user.CredentialGeneration("bob")

	passwords := []string{"firstpass1", "secondpass2"}
	var atConsume sync.WaitGroup
	atConsume.Add(len(passwords))
	release := make(chan struct{})
	go func() {
		atConsume.Wait()
		close(release)
	}()
	r.hooks.beforeResetConsume = func() {
		atConsume.Done()
		select {
		case <-release:
		case <-time.After(10 * time.Second):
			t.Error("the other redemption never reached Consume")
		}
	}

	codes := make([]int, len(passwords))
	var wg sync.WaitGroup
	for i, pw := range passwords {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = redeem(r, tok, pw)
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the redemptions did not finish")
	}

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
	if after, _ := r.user.CredentialGeneration("bob"); after != before+1 {
		t.Errorf("bob's generation went from %d to %d, want exactly one commit", before, after)
	}
}
