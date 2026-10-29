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
	"strings"
	"testing"

	"github.com/axoflow/axoflow-idp/pkg/user"
)

// originHeaders are the request headers a browser sends with a form POST,
// by where the page with the form came from.
var originHeaders = map[string]map[string]string{
	"no headers (a non-browser client)": {},
	"Sec-Fetch-Site same-origin":        {"Sec-Fetch-Site": "same-origin"},
	"Sec-Fetch-Site none":               {"Sec-Fetch-Site": "none"},
	"Origin of the IdP":                 {"Origin": "https://idp.example.com"},
	"Sec-Fetch-Site cross-site":         {"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"},
	"Sec-Fetch-Site same-site":          {"Sec-Fetch-Site": "same-site", "Origin": "https://app.idp.example.com"},
	"foreign Origin":                    {"Origin": "https://evil.example"},
}

func crossOrigin(name string) bool {
	return strings.Contains(name, "cross-site") || strings.Contains(name, "same-site") || strings.Contains(name, "foreign")
}

func originPost(target string, headers map[string]string, form url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Host = "idp.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func sessionCookieOf(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" && c.Value != "" {
			return c
		}
	}
	return nil
}

// A page of another site must not sign the browser in to an account of the
// attacker's choosing (login CSRF): the credential-submitting POSTs refuse
// a cross-origin request, and accept a same-origin or header-less one.
func TestLoginCrossOrigin(t *testing.T) {
	authQuery := url.Values{"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}}
	tests := []struct {
		name   string
		send   func(r *Routes, headers map[string]string) *httptest.ResponseRecorder
		wantOK int
	}{
		{"POST /login", func(r *Routes, headers map[string]string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			r.Login(rec, originPost("/login", headers, url.Values{"username": {"bob"}, "password": {"bobpass1"}}))
			return rec
		}, http.StatusFound},
		{"POST /idp/login", func(r *Routes, headers map[string]string) *httptest.ResponseRecorder {
			r.prefix = "/idp"
			rec := httptest.NewRecorder()
			r.Login(rec, originPost("/idp/login", headers, url.Values{"username": {"bob"}, "password": {"bobpass1"}}))
			return rec
		}, http.StatusFound},
		{"POST /register", func(r *Routes, headers map[string]string) *httptest.ResponseRecorder {
			r.user.SelfRegistration = true
			rec := httptest.NewRecorder()
			r.Register(rec, originPost("/register", headers, url.Values{
				"username": {"carol"}, "email": {"carol@example.com"}, "password": {"carolpass1"}, "password_confirm": {"carolpass1"},
			}))
			return rec
		}, http.StatusCreated},
		{"POST /oidc/auth login form", func(r *Routes, headers map[string]string) *httptest.ResponseRecorder {
			rec := httptest.NewRecorder()
			r.OidcAuth(rec, originPost("/oidc/auth?"+authQuery.Encode(), headers, url.Values{"username": {"bob"}, "password": {"bobpass1"}}))
			return rec
		}, http.StatusFound},
	}
	for _, tc := range tests {
		for name, headers := range originHeaders {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				r, _ := newOidcTestRoutes(t)
				rec := tc.send(r, headers)
				want := tc.wantOK
				if crossOrigin(name) {
					want = http.StatusForbidden
				}
				if rec.Code != want {
					t.Fatalf("status = %d, want %d: %s", rec.Code, want, rec.Body.String())
				}
				if c := sessionCookieOf(rec); (c != nil) == crossOrigin(name) {
					t.Errorf("session cookie = %v, want one only for an accepted request", c)
				}
				if _, ok := r.user.Authenticate("carol", "carolpass1"); ok && crossOrigin(name) {
					t.Error("a refused registration created the account")
				}
			})
		}
	}
}

// A relying party may send its authorization request as a cross-site form
// POST (OIDC Core §3.1.2.1); it carries no credentials, so it is not refused.
func TestOidcAuth_DirectPostFromTheRelyingParty(t *testing.T) {
	r, cookie := newOidcTestRoutes(t)
	form := url.Values{"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}, "state": {"s"}}
	req := originPost("/oidc/auth", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://app.example.com"}, form)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	r.OidcAuth(rec, req)
	if q := locationQuery(t, rec); rec.Code != http.StatusFound || q.Get("code") == "" || q.Get("state") != "s" {
		t.Fatalf("direct POST = %d %v, want 302 with a code", rec.Code, q)
	}
}

// The login form of /oidc/auth signs in only for a valid authorization
// request: an invalid one is refused, even with the right password, without
// a new session and without ending the one the browser holds. A valid one,
// of a public or a confidential client, signs in; a relying party's own
// credential-less POST, sent cross-site, still gets its code.
func TestOidcAuth_InvalidRequestCreatesNoSession(t *testing.T) {
	app := func() url.Values {
		return url.Values{"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}}
	}
	tests := []struct {
		name  string
		query url.Values
		// rp sends the request as the relying party's POST, without credentials
		rp     bool
		wantOK bool
	}{
		{"unsupported response_type", with(app(), "response_type", "token"), false, false},
		{"no openid scope", with(app(), "scope", "profile"), false, false},
		{"implicit without nonce", with(app(), "response_type", "id_token"), false, false},
		{"a resource the client may not ask for", with(app(), "resource", cliResource), false, false},
		{"a public client without PKCE", with(cliAuthQuery(), "code_challenge", ""), false, false},
		{"a public client with plain PKCE", with(cliAuthQuery(), "code_challenge_method", "plain"), false, false},
		{"a public client with another resource", with(cliAuthQuery(), "resource", "https://elsewhere.example.com"), false, false},
		{"a public client", cliAuthQuery(), false, true},
		{"a confidential client", app(), false, true},
		{"the relying party's POST, cross-site", app(), true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, cookie := newPublicClientRoutes(t)
			var req *http.Request
			if tc.rp {
				req = originPost("/oidc/auth", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://app.example.com"}, tc.query)
			} else {
				req = originPost("/oidc/auth?"+tc.query.Encode(), nil, url.Values{"username": {"bob"}, "password": {"bobpass1"}})
			}
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			r.OidcAuth(rec, req)

			location, _ := url.Parse(rec.Header().Get("Location"))
			// an implicit request's error is in the fragment
			params, _ := url.ParseQuery(location.RawQuery + "&" + location.Fragment)
			if rec.Code != http.StatusFound || params.Has("code") != tc.wantOK || params.Has("error") == tc.wantOK {
				t.Fatalf("status = %d Location %q, want a redirect with a code %v", rec.Code, location, tc.wantOK)
			}
			_, oldErr := r.session.Get(cookie.Value)
			setCookie := rec.Result().Header.Values("Set-Cookie")
			switch {
			case !tc.wantOK && (len(setCookie) != 0 || oldErr != nil || r.session.Count("bob") != 1):
				t.Errorf("Set-Cookie %q, old session %v, %d sessions; want none, live, 1", setCookie, oldErr, r.session.Count("bob"))
			case tc.wantOK && !tc.rp && (sessionCookieOf(rec) == nil || oldErr == nil):
				t.Errorf("Set-Cookie %q, old session %v; want a new session replacing it", setCookie, oldErr)
			case tc.rp && (len(setCookie) != 0 || oldErr != nil):
				t.Errorf("Set-Cookie %q, old session %v; want the session kept as it was", setCookie, oldErr)
			}
		})
	}
}

// The login form of /oidc/auth with the right password but an unregistered
// redirect_uri is refused in place, and the session the browser already
// holds is neither replaced nor ended.
func TestOidcAuth_UnregisteredRedirectKeepsTheSession(t *testing.T) {
	r, cookie := newPublicClientRoutes(t)
	q := cliAuthQuery()
	q.Set("redirect_uri", "http://127.0.0.1:9999/callback")
	req := originPost("/oidc/auth?"+q.Encode(), nil, url.Values{"username": {"bob"}, "password": {"bobpass1"}})
	req.AddCookie(cookie)
	before := r.session.Count("bob")
	rec := httptest.NewRecorder()
	r.OidcAuth(rec, req)

	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("status = %d Location %q, want 400 in place", rec.Code, rec.Header().Get("Location"))
	}
	if setCookie := rec.Result().Header.Values("Set-Cookie"); len(setCookie) != 0 {
		t.Errorf("Set-Cookie %q, want none", setCookie)
	}
	if n := r.session.Count("bob"); n != before {
		t.Errorf("%d sessions, want %d", n, before)
	}
	if id, err := r.session.Get(cookie.Value); err != nil || id != "bob" {
		t.Errorf("the old session resolves to %q, %v; want bob", id, err)
	}
}

// with returns q with key set to value, or deleted for "".
func with(q url.Values, key, value string) url.Values {
	if value == "" {
		q.Del(key)
	} else {
		q.Set(key, value)
	}
	return q
}

// Credentials and the CSRF token are read from the request body: in the URL
// they reach access logs, proxies and the browser history.
func TestFormSecretsFromTheBodyOnly(t *testing.T) {
	t.Run("login fields in the query", func(t *testing.T) {
		r := newTestRoutes(t, false)
		creds := url.Values{"username": {"bob"}, "password": {"bobpass1"}}
		rec := httptest.NewRecorder()
		r.Login(rec, originPost("/login?"+creds.Encode(), nil, nil))
		if rec.Code != http.StatusUnauthorized || sessionCookieOf(rec) != nil {
			t.Errorf("status = %d, want 401 and no session", rec.Code)
		}
	})

	t.Run("login form fields in the query of /oidc/auth", func(t *testing.T) {
		r, _ := newOidcTestRoutes(t)
		q := url.Values{"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}, "username": {"bob"}, "password": {"bobpass1"}}
		rec := httptest.NewRecorder()
		r.OidcAuth(rec, originPost("/oidc/auth?"+q.Encode(), nil, nil))
		if sessionCookieOf(rec) != nil || rec.Header().Get("Location") != "" {
			t.Errorf("status = %d Location %q, want the login page, no sign-in", rec.Code, rec.Header().Get("Location"))
		}
	})

	t.Run("csrf_token in the query", func(t *testing.T) {
		r := newTestRoutes(t, false)
		cookie, csrf := r.authed("bob")
		req := originPost("/password?csrf_token="+url.QueryEscape(csrf), nil, url.Values{"current_password": {"bobpass1"}, "new_password": {"newsecret1"}})
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		r.ChangePassword(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rec.Code)
		}
		if _, ok := r.user.Authenticate("bob", "bobpass1"); !ok {
			t.Error("the password changed")
		}
	})
}

// postSplit posts body to handler with cookie, the named fields moved from
// the body to the URL query.
func postSplit(handler http.HandlerFunc, path string, cookie *http.Cookie, body url.Values, keys ...string) *httptest.ResponseRecorder {
	query := url.Values{}
	for _, k := range keys {
		query[k] = body[k]
		body.Del(k)
	}
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	return postForm(handler, path, cookie, body)
}

// Every form write reads its passwords, the reset token of a POST and a
// registration's identity from the body: under valid authorization, any one
// of these fields in the query, the others in the body, writes nothing, and
// leaves the account, its sessions and the reset link as they were. One
// field per row, so that each reader is pinned on its own: with two in the
// query, the other missing field would refuse the write anyway. In the body
// they write.
func TestFormWritesReadTheBody(t *testing.T) {
	tests := []struct {
		name string
		keys []string // the fields put in the query
		// submit posts the form and reports whether it wrote; when it did
		// not, it checks that nothing changed
		submit func(t *testing.T, keys []string) bool
	}{
		{"register, username", []string{"username"}, submitRegister},
		{"register, email", []string{"email"}, submitRegister},
		{"register, password", []string{"password"}, submitRegister},
		{"register, password_confirm", []string{"password_confirm"}, submitRegister},
		{"change password, current_password", []string{"current_password"}, submitChangePassword},
		{"change password, new_password", []string{"new_password"}, submitChangePassword},
		{"set-password, token", []string{"token"}, submitSetPassword},
		{"set-password, new_password", []string{"new_password"}, submitSetPassword},
		{"admin register, password", []string{"password"}, submitAdminRegister},
		{"admin reset, new_password", []string{"new_password"}, submitAdminReset},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.submit(t, tc.keys) {
				t.Errorf("%v in the query wrote", tc.keys)
			}
			if !tc.submit(t, nil) {
				t.Error("the form in the body did not write")
			}
		})
	}
}

func submitRegister(t *testing.T, keys []string) bool {
	r := newBootstrapRoutes(t, `[{"ID":"a1","Username":"alice","Password":"!"}]`, user.Config{SelfRegistration: true})
	body := url.Values{"username": {"carol"}, "email": {"carol@example.com"}, "password": {"carolpass1"}, "password_confirm": {"carolpass1"}}
	rec := postSplit(r.Register, "/register", nil, body, keys...)
	written := r.user.Count() == 2
	if !written && sessionCookieOf(rec) != nil {
		t.Error("a refused registration set a session cookie")
	}
	return written
}

func submitChangePassword(t *testing.T, keys []string) bool {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("bob")
	body := url.Values{"csrf_token": {csrf}, "current_password": {"bobpass1"}, "new_password": {"newsecret1"}}
	postSplit(r.ChangePassword, "/password", cookie, body, keys...)
	if _, ok := r.user.Authenticate("bob", "newsecret1"); ok {
		return true
	}
	assertOnlyPassword(t, r, "bobpass1")
	if _, err := r.session.Get(cookie.Value); err != nil {
		t.Errorf("bob's session ended: %v", err)
	}
	return false
}

func submitSetPassword(t *testing.T, keys []string) bool {
	r := newTestRoutes(t, false)
	generation, _ := r.user.CredentialGeneration("bob")
	token, err := r.resetTokens.Create("bob", "admin1", generation)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	bobCookie, _ := r.authed("bob")
	postSplit(r.SetPassword, "/set-password", nil, url.Values{"token": {token}, "new_password": {"linkpass1"}}, keys...)
	if _, ok := r.user.Authenticate("bob", "linkpass1"); ok {
		return true
	}
	assertOnlyPassword(t, r, "bobpass1")
	if !tokenHeld(r, token) {
		t.Error("the reset link was spent")
	}
	if _, err := r.session.Get(bobCookie.Value); err != nil {
		t.Errorf("bob's session ended: %v", err)
	}
	return false
}

func submitAdminRegister(t *testing.T, keys []string) bool {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("admin1")
	body := url.Values{"csrf_token": {csrf}, "username": {"carol"}, "email": {"carol@example.com"}, "password": {"carolpass1"}}
	postSplit(r.AdminRegister, "/admin/register", cookie, body, keys...)
	return r.user.Count() == 3
}

func submitAdminReset(t *testing.T, keys []string) bool {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("admin1")
	bobCookie, _ := r.authed("bob")
	body := url.Values{"csrf_token": {csrf}, "user_id": {"bob"}, "new_password": {"bobpass99"}}
	postSplit(r.AdminResetPassword, "/admin/users/reset-password", cookie, body, keys...)
	if _, ok := r.user.Authenticate("bob", "bobpass99"); ok {
		return true
	}
	assertOnlyPassword(t, r, "bobpass1")
	if _, err := r.session.Get(bobCookie.Value); err != nil {
		t.Errorf("bob's session ended: %v", err)
	}
	return false
}

// A field sent in both the query and the body is taken from the body: the
// write uses the body's identity, password and reset token. req.Form puts
// the body's value first as well, so these rows pin out a reader of the URL
// query; the rows above pin out req.Form.
func TestFormWritesPreferTheBody(t *testing.T) {
	tests := []struct {
		name   string
		query  url.Values // a field of the valid body, with another value
		submit func(t *testing.T, query url.Values)
	}{
		{"register, username", url.Values{"username": {"mallory"}}, registerFromTheBody},
		{"register, email", url.Values{"email": {"mallory@example.com"}}, registerFromTheBody},
		{"register, password", url.Values{"password": {"mallorypass1"}}, registerFromTheBody},
		{"register, password_confirm", url.Values{"password_confirm": {"mallorypass1"}}, registerFromTheBody},
		{"change password, current_password", url.Values{"current_password": {"wrongpass1"}}, changePasswordFromTheBody},
		{"change password, new_password", url.Values{"new_password": {"querypass1"}}, changePasswordFromTheBody},
		{"set-password, token", url.Values{"token": {"admin1"}}, setPasswordFromTheBody},
		{"set-password, new_password", url.Values{"new_password": {"querypass1"}}, setPasswordFromTheBody},
		{"admin register, password", url.Values{"password": {"querypass1"}}, adminRegisterFromTheBody},
		{"admin reset, new_password", url.Values{"new_password": {"querypass1"}}, adminResetFromTheBody},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.submit(t, tc.query)
		})
	}
}

func registerFromTheBody(t *testing.T, query url.Values) {
	r := newBootstrapRoutes(t, `[{"ID":"a1","Username":"alice","Password":"!"}]`, user.Config{SelfRegistration: true})
	body := url.Values{"username": {"carol"}, "email": {"carol@example.com"}, "password": {"carolpass1"}, "password_confirm": {"carolpass1"}}
	postForm(r.Register, "/register?"+query.Encode(), nil, body)
	carol, ok := r.user.Authenticate("carol", "carolpass1")
	if !ok || carol.Email != "carol@example.com" || r.user.Count() != 2 {
		t.Errorf("carol registered %v with email %q, %d users; want the body's account, 2 users", ok, carol.Email, r.user.Count())
	}
}

func changePasswordFromTheBody(t *testing.T, query url.Values) {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("bob")
	body := url.Values{"csrf_token": {csrf}, "current_password": {"bobpass1"}, "new_password": {"newsecret1"}}
	postForm(r.ChangePassword, "/password?"+query.Encode(), cookie, body)
	assertOnlyPassword(t, r, "newsecret1", "bobpass1", query.Get("new_password"))
}

// setPasswordFromTheBody puts a valid link of query's token user in the
// query, so that reading the query would spend a real link.
func setPasswordFromTheBody(t *testing.T, query url.Values) {
	r := newTestRoutes(t, false)
	link := func(id string) string {
		generation, _ := r.user.CredentialGeneration(id)
		token, err := r.resetTokens.Create(id, "admin1", generation)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		return token
	}
	token := link("bob")
	var other string
	if id := query.Get("token"); id != "" {
		other = link(id)
		query.Set("token", other)
	}
	postForm(r.SetPassword, "/set-password?"+query.Encode(), nil, url.Values{"token": {token}, "new_password": {"linkpass1"}})
	assertOnlyPassword(t, r, "linkpass1", "bobpass1", query.Get("new_password"))
	if tokenHeld(r, token) {
		t.Error("the body's link was not spent")
	}
	if other != "" && !tokenHeld(r, other) {
		t.Error("the query's link was spent")
	}
	if _, ok := r.user.Authenticate("admin", "adminpass"); !ok {
		t.Error("admin's password changed")
	}
}

func adminRegisterFromTheBody(t *testing.T, query url.Values) {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("admin1")
	body := url.Values{"csrf_token": {csrf}, "username": {"carol"}, "email": {"carol@example.com"}, "password": {"carolpass1"}}
	postForm(r.AdminRegister, "/admin/register?"+query.Encode(), cookie, body)
	if _, ok := r.user.Authenticate("carol", "carolpass1"); !ok {
		t.Error("carol does not sign in with the body's password")
	}
	if _, ok := r.user.Authenticate("carol", query.Get("password")); ok {
		t.Error("carol signs in with the query's password")
	}
}

func adminResetFromTheBody(t *testing.T, query url.Values) {
	r := newTestRoutes(t, false)
	cookie, csrf := r.authed("admin1")
	body := url.Values{"csrf_token": {csrf}, "user_id": {"bob"}, "new_password": {"bobpass99"}}
	postForm(r.AdminResetPassword, "/admin/users/reset-password?"+query.Encode(), cookie, body)
	assertOnlyPassword(t, r, "bobpass99", "bobpass1", query.Get("new_password"))
}
