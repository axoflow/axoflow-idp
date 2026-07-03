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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/axoflow/axoflow-idp/internal/codestore"
	"github.com/axoflow/axoflow-idp/pkg/keychain"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
)

const testRedirectURI = "https://app.example.com/cb"

// newOidcTestRoutes returns routes wired with a real OIDC provider and a
// codestore, plus a session cookie for the seeded "bob" user.
func newOidcTestRoutes(t *testing.T) (*Routes, *http.Cookie) {
	t.Helper()
	r := newTestRoutes(t, false)

	o, err := oidc.New(oidc.Config{
		BaseUrl:           "https://idp.example.com",
		Clients:           []oidc.Client{{Id: "app", RedirectUri: testRedirectURI, ClientSecret: "s"}},
		Keychain:          keychain.New(),
		SigningKeyPath:    filepath.Join(t.TempDir(), "signing-key.json"),
		GenerateIfMissing: true,
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	r.oidc = o
	r.store = codestore.New()

	cookie := &http.Cookie{Name: "session", Value: r.session.Create("bob")}
	return r, cookie
}

func authGet(t *testing.T, r *Routes, cookie *http.Cookie, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oidc/auth?"+q.Encode(), nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	r.OidcAuth(rec, req)
	return rec
}

func locationQuery(t *testing.T, rec *httptest.ResponseRecorder) url.Values {
	t.Helper()
	loc := rec.Header().Get("Location")
	if loc == "" {
		t.Fatalf("no Location header (status %d)", rec.Code)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	return u.Query()
}

func TestOidcAuth_CodeSuccessEncodesState(t *testing.T) {
	r, cookie := newOidcTestRoutes(t)
	state := "a b&c=d#e" // special chars that would break naive interpolation

	rec := authGet(t, r, cookie, url.Values{
		"scope":         {"openid"},
		"response_type": {"code"},
		"client_id":     {"app"},
		"redirect_uri":  {testRedirectURI},
		"state":         {state},
	})

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	q := locationQuery(t, rec)
	if got := q.Get("state"); got != state {
		t.Errorf("state = %q, want %q", got, state)
	}
	if q.Get("code") == "" {
		t.Error("code must be present on success")
	}
}

func TestOidcAuth_IDTokenSuccessEchoesState(t *testing.T) {
	r, cookie := newOidcTestRoutes(t)
	state := "x y&z"

	rec := authGet(t, r, cookie, url.Values{
		"scope":         {"openid"},
		"response_type": {"id_token"},
		"client_id":     {"app"},
		"redirect_uri":  {testRedirectURI},
		"state":         {state},
	})

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	q := locationQuery(t, rec)
	if got := q.Get("state"); got != state {
		t.Errorf("state = %q, want %q", got, state)
	}
	if q.Get("id_token") == "" {
		t.Error("id_token must be present on success")
	}
}

func TestOidcAuth_ErrorRedirectEchoesState(t *testing.T) {
	r, cookie := newOidcTestRoutes(t)
	state := "s t&u"

	// Missing "openid" scope: a valid client/redirect_uri, so the error is
	// redirected back with the state echoed.
	rec := authGet(t, r, cookie, url.Values{
		"scope":         {"profile"},
		"response_type": {"code"},
		"client_id":     {"app"},
		"redirect_uri":  {testRedirectURI},
		"state":         {state},
	})

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	q := locationQuery(t, rec)
	if q.Get("error") != "invalid_scope" {
		t.Errorf("error = %q, want invalid_scope", q.Get("error"))
	}
	if got := q.Get("state"); got != state {
		t.Errorf("state = %q, want %q", got, state)
	}
}

func TestOidcAuth_UnregisteredRedirectIsNotRedirect(t *testing.T) {
	r, cookie := newOidcTestRoutes(t)

	// A domain-suffix bypass attempt: must be rejected in place, never a 302
	// to the attacker-controlled host.
	rec := authGet(t, r, cookie, url.Values{
		"scope":         {"openid"},
		"response_type": {"code"},
		"client_id":     {"app"},
		"redirect_uri":  {"https://app.example.com.evil.com/cb"},
		"state":         {"s"},
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("must not redirect to an unregistered uri, got Location %q", loc)
	}
}

func newTokenTestRoutes(t *testing.T) *Routes {
	t.Helper()
	o, err := oidc.New(oidc.Config{
		BaseUrl: "https://idp.example.com",
		Clients: []oidc.Client{
			{Id: "app", RedirectUri: "https://app.example.com/cb", ClientSecret: "s3cret"},
		},
		Keychain:          keychain.New(),
		SigningKeyPath:    filepath.Join(t.TempDir(), "signing-key.json"),
		GenerateIfMissing: true,
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	return &Routes{oidc: o, store: codestore.New()}
}

func postToken(t *testing.T, r *Routes, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.OidcToken(rec, req)
	return rec
}

func TestOidcToken_ErrorEnvelope(t *testing.T) {
	valid := func() url.Values {
		return url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"app"},
			"client_secret": {"s3cret"},
			"redirect_uri":  {"https://app.example.com/cb"},
		}
	}
	with := func(k, v string) url.Values {
		f := valid()
		f.Set(k, v)
		return f
	}

	tests := []struct {
		name       string
		form       url.Values
		wantStatus int
		wantError  string
	}{
		{"unsupported grant type", with("grant_type", "password"), http.StatusBadRequest, "unsupported_grant_type"},
		{"unknown client", with("client_id", "nope"), http.StatusUnauthorized, "invalid_client"},
		{"wrong client secret", with("client_secret", "totally-wrong"), http.StatusUnauthorized, "invalid_client"},
		{"redirect uri mismatch", with("redirect_uri", "https://evil.example.com/cb"), http.StatusBadRequest, "invalid_grant"},
		{"unknown code", with("code", "does-not-exist"), http.StatusBadRequest, "invalid_grant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTokenTestRoutes(t)
			rec := postToken(t, r, tt.form)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d (body=%q)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response body is not JSON: %v (body=%q)", err, rec.Body.String())
			}
			if body.Error != tt.wantError {
				t.Errorf("error = %q, want %q", body.Error, tt.wantError)
			}
		})
	}
}

func TestOidcToken_Success(t *testing.T) {
	r := newTokenTestRoutes(t)
	code := r.store.Create("the-id-token")
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"app"},
		"client_secret": {"s3cret"},
		"redirect_uri":  {"https://app.example.com/cb"},
		"code":          {code},
	}
	rec := postToken(t, r, form)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%q)", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	var body struct {
		IDToken   string `json:"id_token"`
		TokenType string `json:"token_type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if body.IDToken != "the-id-token" {
		t.Errorf("id_token = %q, want %q", body.IDToken, "the-id-token")
	}
	if body.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", body.TokenType)
	}
}
