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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/axoflow/axoflow-idp/internal/codestore"
	"github.com/axoflow/axoflow-idp/internal/tokenstore"
	"github.com/axoflow/axoflow-idp/pkg/keychain"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

const testRedirectURI = "https://app.example.com/cb"

// testSigningKey is generated once: a 4096-bit RSA key takes up to seconds.
var testSigningKey = sync.OnceValues(func() ([]byte, error) {
	dir, err := os.MkdirTemp("", "signing-key")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "signing-key.json")
	if _, err := oidc.New(oidc.Config{
		BaseUrl:           "https://idp.example.com",
		Clients:           []oidc.Client{{Id: "app", RedirectUri: testRedirectURI, ClientSecret: "s"}},
		Keychain:          keychain.New(),
		SigningKeyPath:    path,
		GenerateIfMissing: true,
	}); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
})

// testSigningKeyPath writes testSigningKey to a file of the test.
func testSigningKeyPath(t *testing.T) string {
	t.Helper()
	key, err := testSigningKey()
	if err != nil {
		t.Fatalf("signing key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "signing-key.json")
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	return path
}

// newOidcTestRoutes returns routes wired with a real OIDC provider and a
// codestore, plus a session cookie for the seeded "bob" user.
func newOidcTestRoutes(t *testing.T) (*Routes, *http.Cookie) {
	t.Helper()
	r := newTestRoutes(t, false)

	o, err := oidc.New(oidc.Config{
		BaseUrl:        "https://idp.example.com",
		Clients:        []oidc.Client{{Id: "app", RedirectUri: testRedirectURI, ClientSecret: "s"}},
		Keychain:       keychain.New(),
		SigningKeyPath: testSigningKeyPath(t),
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
			// same callback as app, so only the client binding refuses its code
			{Id: "other", RedirectUri: "https://app.example.com/cb", ClientSecret: "0ther"},
		},
		Keychain:       keychain.New(),
		SigningKeyPath: testSigningKeyPath(t),
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
	r := newTokenTestRoutes(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
	code := r.store.Create("the-id-token", "app", "https://app.example.com/cb")
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
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if body.IDToken != "the-id-token" {
		t.Errorf("id_token = %q, want %q", body.IDToken, "the-id-token")
	}
	if body.AccessToken != "the-id-token" {
		t.Errorf("access_token = %q, want it to equal the id_token", body.AccessToken)
	}
	if body.ExpiresIn != 24*3600 {
		t.Errorf("expires_in = %d, want %d", body.ExpiresIn, 24*3600)
	}
	if body.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", body.TokenType)
	}
}

func TestOidcToken_CodeOfAnotherClient(t *testing.T) {
	r := newTokenTestRoutes(t)
	code := r.store.Create("the-id-token", "app", "https://app.example.com/cb")

	rec := postToken(t, r, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"other"},
		"client_secret": {"0ther"},
		"redirect_uri":  {"https://app.example.com/cb"},
		"code":          {code},
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_grant") {
		t.Fatalf("redeemed by another client: status %d, body %q", rec.Code, rec.Body.String())
	}

	rec = postToken(t, r, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"app"},
		"client_secret": {"s3cret"},
		"redirect_uri":  {"https://app.example.com/cb"},
		"code":          {code},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("the refused redemption must spend the code: status %d", rec.Code)
	}
}

func TestOidcRevokeBadClientCredentials(t *testing.T) {
	r := newTokenTestRoutes(t)
	r.tokenStore = tokenstore.New(tokenstore.Config{})

	form := url.Values{
		"token":         {"some-token"},
		"client_id":     {"app"},
		"client_secret": {"wrong-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.OidcRevoke(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (RFC 7009 §2.1: failed client auth is not a 200)", rec.Code, http.StatusUnauthorized)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if body.Error != "invalid_client" {
		t.Errorf("error = %q, want %q", body.Error, "invalid_client")
	}
}

// A client revokes only its own tokens: another client's revocation is
// answered 200 and records nothing.
func TestOidcRevoke_Ownership(t *testing.T) {
	r := newTokenTestRoutes(t)
	r.tokenStore = tokenstore.New(tokenstore.Config{})
	token, err := r.oidc.GenerateIDToken(user.UserInfo{ID: "bob", Username: "bob"}, "app", "")
	if err != nil {
		t.Fatalf("GenerateIDToken: %v", err)
	}
	revoke := func(clientID, secret string) int {
		form := url.Values{"token": {token}, "client_id": {clientID}, "client_secret": {secret}}
		req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		r.OidcRevoke(rec, req)
		return rec.Code
	}

	if code := revoke("other", "0ther"); code != http.StatusOK || r.tokenStore.IsRevoked(token) {
		t.Fatalf("another client's revocation = %d, revoked %v; want 200 and not revoked", code, r.tokenStore.IsRevoked(token))
	}
	if code := revoke("app", "s3cret"); code != http.StatusOK || !r.tokenStore.IsRevoked(token) {
		t.Errorf("the owner's revocation = %d, revoked %v; want 200 and revoked", code, r.tokenStore.IsRevoked(token))
	}
}
