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

// crossOrigin reports whether originHeaders[name] is a page of another origin.
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
// request: an invalid one is refused without creating a session, even with
// the right password.
func TestOidcAuth_InvalidRequestCreatesNoSession(t *testing.T) {
	tests := []struct {
		name   string
		change func(q url.Values)
	}{
		{"unsupported response_type", func(q url.Values) { q.Set("response_type", "token") }},
		{"no openid scope", func(q url.Values) { q.Set("scope", "profile") }},
		{"implicit without nonce", func(q url.Values) { q.Set("response_type", "id_token") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := newOidcTestRoutes(t)
			q := url.Values{"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}}
			tc.change(q)
			rec := httptest.NewRecorder()
			r.OidcAuth(rec, originPost("/oidc/auth?"+q.Encode(), nil, url.Values{"username": {"bob"}, "password": {"bobpass1"}}))
			if rec.Code != http.StatusFound || !strings.Contains(rec.Header().Get("Location"), "error=") {
				t.Fatalf("status = %d Location %q, want an error redirect", rec.Code, rec.Header().Get("Location"))
			}
			if c := sessionCookieOf(rec); c != nil {
				t.Errorf("Set-Cookie %v, want no session for an invalid request", c)
			}
			// newOidcTestRoutes holds one session for bob already
			if n := r.session.Count("bob"); n != 1 {
				t.Errorf("bob holds %d sessions, want 1", n)
			}
		})
	}
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
