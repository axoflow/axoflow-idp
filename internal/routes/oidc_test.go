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
	"slices"
	"strings"
	"testing"

	"github.com/axoflow/axoflow-idp/internal/codestore"
	"github.com/axoflow/axoflow-idp/internal/tokenstore"
	"github.com/axoflow/axoflow-idp/pkg/keychain"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
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

// splitLocation returns the query and the fragment parameters of the
// redirect, each decoded once.
func splitLocation(t *testing.T, rec *httptest.ResponseRecorder) (url.Values, url.Values) {
	t.Helper()
	base, fragment, _ := strings.Cut(rec.Header().Get("Location"), "#")
	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("parse Location %q: %v", base, err)
	}
	f, err := url.ParseQuery(fragment)
	if err != nil {
		t.Fatalf("parse fragment %q: %v", fragment, err)
	}
	return u.Query(), f
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
		"nonce":         {"n1"},
	})

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	q, f := splitLocation(t, rec)
	if len(q) != 0 {
		t.Errorf("query = %v, want the response in the fragment only", q)
	}
	if got := f.Get("state"); got != state {
		t.Errorf("state = %q, want %q", got, state)
	}
	if f.Get("id_token") == "" {
		t.Fatal("id_token must be present on success")
	}
	if _, claims := verifiedClaims(t, r, f.Get("id_token")); claims["nonce"] != "n1" {
		t.Errorf("id_token nonce = %v, want n1", claims["nonce"])
	}
}

// TestOidcAuth_ResponseMode delivers an implicit response, success or error,
// in the fragment and a code response in the query; response_mode cannot
// move a token into the query.
func TestOidcAuth_ResponseMode(t *testing.T) {
	state := "a b%c+d&e=f#g"
	request := func(responseType string, extra ...string) url.Values {
		q := url.Values{
			"scope": {"openid"}, "response_type": {responseType}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}, "state": {state},
		}
		for i := 0; i < len(extra); i += 2 {
			q.Set(extra[i], extra[i+1])
		}
		return q
	}
	tests := []struct {
		name         string
		q            url.Values
		wantFragment bool
		wantError    string // empty: success, carrying wantParam
		wantParam    string
	}{
		{"implicit", request("id_token", "nonce", "n1"), true, "", "id_token"},
		{"implicit with response_mode=query", request("id_token", "nonce", "n1", "response_mode", "query"), true, "", "id_token"},
		{"implicit without nonce", request("id_token"), true, "invalid_request", ""},
		{"implicit error", request("id_token", "nonce", "n1", "scope", "profile"), true, "invalid_scope", ""},
		{"code", request("code"), false, "", "code"},
		{"code error", request("code", "scope", "profile"), false, "invalid_scope", ""},
	}
	r, cookie := newOidcTestRoutes(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := authGet(t, r, cookie, tt.q)
			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body.String())
			}
			params, other := splitLocation(t, rec)
			if tt.wantFragment {
				params, other = other, params
			}
			if len(other) != 0 {
				t.Errorf("parameters %v in the wrong part of %q", other, rec.Header().Get("Location"))
			}
			if got := params.Get("state"); got != state {
				t.Errorf("state = %q, want %q", got, state)
			}
			if got := params.Get("error"); got != tt.wantError {
				t.Errorf("error = %q, want %q", got, tt.wantError)
			}
			for _, p := range []string{"id_token", "code"} {
				if got := params.Get(p) != ""; got != (p == tt.wantParam) {
					t.Errorf("%s present = %v, want %v", p, got, p == tt.wantParam)
				}
			}
		})
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
	r := newTestRoutes(t, false)
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
	r.oidc = o
	r.store = codestore.New()
	return r
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
	code := r.store.Create(codestore.Grant{User: user.UserInfo{ID: "bob"}, Nonce: "n1"}, "app", testRedirectURI)
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
	// both tokens are minted at redemption from the grant's nonce and the user's current record
	typ, claims := verifiedClaims(t, r, body.IDToken)
	if typ != "JWT" || claims["sub"] != "bob" || claims["name"] != "bob" || claims["nonce"] != "n1" || claims["aud"] != "app" {
		t.Errorf("id_token typ=%q sub=%v name=%v nonce=%v aud=%v, want JWT bob bob n1 app", typ, claims["sub"], claims["name"], claims["nonce"], claims["aud"])
	}
	typ, claims = verifiedClaims(t, r, body.AccessToken)
	if typ != "at+jwt" || claims["sub"] != "bob" || claims["aud"] != "app" || claims["client_id"] != "app" {
		t.Errorf("access_token typ=%q sub=%v aud=%v client_id=%v, want at+jwt bob app app", typ, claims["sub"], claims["aud"], claims["client_id"])
	}
	if body.ExpiresIn != 24*3600 {
		t.Errorf("expires_in = %d, want %d", body.ExpiresIn, 24*3600)
	}
	if body.TokenType != "Bearer" {
		t.Errorf("token_type = %q, want Bearer", body.TokenType)
	}
}

func TestOidcRevokeBadClientCredentials(t *testing.T) {
	r := newTokenTestRoutes(t)
	r.tokenStore = tokenstore.New(0)

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

// userChanges are the admin changes that land between issuance and use; nil
// groups means the user is gone.
var userChanges = []struct {
	name       string
	change     func(t *testing.T, u *user.User)
	wantGroups []any
}{
	{"unchanged", func(*testing.T, *user.User) {}, []any{"user"}},
	{"deleted", func(t *testing.T, u *user.User) {
		if err := u.AdminDelete("admin1", "bob"); err != nil {
			t.Fatalf("delete: %v", err)
		}
	}, nil},
	{"group removed", func(t *testing.T, u *user.User) {
		if err := u.AdminUpdateUserGroups("admin1", "bob", []string{}); err != nil {
			t.Fatalf("update groups: %v", err)
		}
	}, []any{}},
	// the new account has the username but another ID, so it is someone else
	{"deleted and recreated", func(t *testing.T, u *user.User) {
		if err := u.AdminDelete("admin1", "bob"); err != nil {
			t.Fatalf("delete: %v", err)
		}
		if err := u.Register("bob", "bobpass2", []string{"user"}, ""); err != nil {
			t.Fatalf("recreate: %v", err)
		}
	}, nil},
}

func groupsOf(claims map[string]any) []any {
	groups, _ := claims["groups"].([]any)
	if groups == nil {
		return []any{}
	}
	return groups
}

// TestOidcToken_LiveUser redeems a code issued before an admin change: the
// tokens carry the user's record at redemption, and a user gone by then gets
// no tokens.
func TestOidcToken_LiveUser(t *testing.T) {
	for _, tt := range userChanges {
		t.Run(tt.name, func(t *testing.T) {
			r, cookie := newPublicClientRoutes(t)
			code := issueCode(t, r, cookie, url.Values{
				"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI},
			})
			tt.change(t, r.user)

			rec := postToken(t, r, url.Values{
				"grant_type": {"authorization_code"}, "client_id": {"app"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirectURI}, "code": {code},
			})
			if tt.wantGroups == nil {
				assertRefusal(t, rec, "invalid_grant")
				return
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("token status = %d: %s", rec.Code, rec.Body.String())
			}
			body := tokenBody(t, rec)
			for _, name := range []string{"id_token", "access_token"} {
				_, claims := verifiedClaims(t, r, body[name].(string))
				if claims["sub"] != "bob" || !slices.Equal(groupsOf(claims), tt.wantGroups) {
					t.Errorf("%s sub=%v groups=%v, want bob %v", name, claims["sub"], claims["groups"], tt.wantGroups)
				}
			}
		})
	}
}

// TestUserinfo_LiveUser answers a token issued before an admin change with
// the user's current groups, and refuses it once the user is gone. The token
// comes from the public client's resource flow, whose aud is the resource.
func TestUserinfo_LiveUser(t *testing.T) {
	for _, tt := range userChanges {
		t.Run(tt.name, func(t *testing.T) {
			r, cookie := newPublicClientRoutes(t)
			r.tokenStore = tokenstore.New(r.oidc.IDTokenTTL())
			rec := postToken(t, r, tfTokenForm(issueCode(t, r, cookie, cliAuthQuery())))
			if rec.Code != http.StatusOK {
				t.Fatalf("token status = %d: %s", rec.Code, rec.Body.String())
			}
			access := tokenBody(t, rec)["access_token"].(string)
			tt.change(t, r.user)

			got := userinfoGet(t, r, access)
			if tt.wantGroups == nil {
				if got.Code != http.StatusUnauthorized {
					t.Errorf("userinfo = %d %s, want 401", got.Code, got.Body.String())
				}
				return
			}
			if got.Code != http.StatusOK {
				t.Fatalf("userinfo = %d: %s", got.Code, got.Body.String())
			}
			var info map[string]any
			if err := json.Unmarshal(got.Body.Bytes(), &info); err != nil {
				t.Fatalf("userinfo body: %v", err)
			}
			if info["sub"] != "bob" || info["name"] != "bob" || !slices.Equal(groupsOf(info), tt.wantGroups) {
				t.Errorf("userinfo = %v, want sub and name bob, groups %v", info, tt.wantGroups)
			}
		})
	}
}

// TestOidcAuth_ImplicitLoginLiveUser changes bob's record after the login
// form's password check and before the implicit ID token is signed: the token
// carries the record as it is after the login, and a user gone by then gets
// neither a token nor a session.
func TestOidcAuth_ImplicitLoginLiveUser(t *testing.T) {
	q := url.Values{
		"scope": {"openid"}, "response_type": {"id_token"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}, "nonce": {"n1"},
	}
	for _, tt := range userChanges {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newPublicClientRoutes(t)
			hookRan := false
			r.hooks.afterCreateSession = func() {
				hookRan = true
				tt.change(t, r.user)
			}

			rec := loginPost(t, r, q)
			if !hookRan {
				t.Fatal("the hook did not run")
			}
			query, fragment := splitLocation(t, rec)
			if tt.wantGroups == nil {
				if query.Has("id_token") || fragment.Has("id_token") {
					t.Errorf("a deleted user got an id_token: %d %q", rec.Code, rec.Header().Get("Location"))
				}
				if resolvingSession(r, rec) {
					t.Error("a deleted user got a resolving session")
				}
				return
			}
			if rec.Code != http.StatusFound || fragment.Get("id_token") == "" {
				t.Fatalf("login = %d %q, want 302 with an id_token in the fragment", rec.Code, rec.Header().Get("Location"))
			}
			_, claims := verifiedClaims(t, r, fragment.Get("id_token"))
			current, _ := r.user.Get("bob")
			if claims["sub"] != current.ID || claims["name"] != current.Username || claims["email"] != current.Email || !slices.Equal(groupsOf(claims), tt.wantGroups) {
				t.Errorf("id_token sub=%v name=%v email=%v groups=%v, want %s %s %q %v", claims["sub"], claims["name"], claims["email"], claims["groups"], current.ID, current.Username, current.Email, tt.wantGroups)
			}
		})
	}
}

// newSameKeyRoutes returns routes whose provider registers the confidential
// "app" with a resource, and a foreign provider that signs with the same key
// under another issuer.
func newSameKeyRoutes(t *testing.T) (*Routes, *oidc.Oidc) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "signing-key.json")
	provider := func(baseURL string) *oidc.Oidc {
		o, err := oidc.New(oidc.Config{
			BaseUrl:           baseURL,
			Clients:           []oidc.Client{{Id: "app", RedirectUri: testRedirectURI, ClientSecret: "s3cret", Resources: []string{cliResource}}},
			Keychain:          keychain.New(),
			SigningKeyPath:    keyPath,
			GenerateIfMissing: true,
		})
		if err != nil {
			t.Fatalf("oidc.New: %v", err)
		}
		return o
	}
	r := newTestRoutes(t, false)
	r.oidc = provider("https://idp.example.com")
	r.tokenStore = tokenstore.New(r.oidc.IDTokenTTL())
	return r, provider("https://other.example.com")
}

// TestUserinfo_TokenClaims refuses an access token this server's key signed
// but whose claims do not name this issuer, a registered client and an
// audience of that client.
func TestUserinfo_TokenClaims(t *testing.T) {
	r, foreign := newSameKeyRoutes(t)
	bob, _ := r.user.Get("bob")

	tests := []struct {
		name     string
		issuer   *oidc.Oidc
		user     user.UserInfo
		clientID string
		resource string
		want     int
	}{
		{"aud the client", r.oidc, bob, "app", "", http.StatusOK},
		{"aud a registered resource", r.oidc, bob, "app", cliResource, http.StatusOK},
		{"foreign issuer", foreign, bob, "app", "", http.StatusUnauthorized},
		{"unregistered client", r.oidc, bob, "nope", "", http.StatusUnauthorized},
		{"aud not the client's", r.oidc, bob, "app", "https://api.example/other", http.StatusUnauthorized},
		{"empty sub", r.oidc, user.UserInfo{}, "app", "", http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := tt.issuer.GenerateAccessToken(tt.user, tt.clientID, tt.resource)
			if err != nil {
				t.Fatalf("GenerateAccessToken: %v", err)
			}
			if got := userinfoGet(t, r, token); got.Code != tt.want {
				t.Errorf("userinfo = %d %s, want %d", got.Code, got.Body.String(), tt.want)
			}
		})
	}
}

func postRevoke(t *testing.T, r *Routes, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.OidcRevoke(rec, req)
	return rec
}

// TestOidcRevoke_Ownership lets a client revoke its own access tokens only:
// another client's token is the RFC 7009 unknown token, so the request
// succeeds and nothing is recorded.
func TestOidcRevoke_Ownership(t *testing.T) {
	appToken := func(t *testing.T, r *Routes, cookie *http.Cookie) string {
		code := issueCode(t, r, cookie, url.Values{
			"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI},
		})
		rec := postToken(t, r, url.Values{
			"grant_type": {"authorization_code"}, "client_id": {"app"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirectURI}, "code": {code},
		})
		if rec.Code != http.StatusOK {
			t.Fatalf("token status = %d: %s", rec.Code, rec.Body.String())
		}
		return tokenBody(t, rec)["access_token"].(string)
	}
	cliToken := func(t *testing.T, r *Routes, cookie *http.Cookie) string {
		rec := postToken(t, r, tfTokenForm(issueCode(t, r, cookie, cliAuthQuery())))
		if rec.Code != http.StatusOK {
			t.Fatalf("token status = %d: %s", rec.Code, rec.Body.String())
		}
		return tokenBody(t, rec)["access_token"].(string)
	}

	tests := []struct {
		name        string
		token       func(t *testing.T, r *Routes, cookie *http.Cookie) string
		client      url.Values
		wantStatus  int
		wantRevoked bool
	}{
		{"the owner", appToken, url.Values{"client_id": {"app"}, "client_secret": {"s3cret"}}, http.StatusOK, true},
		{"another confidential client", appToken, url.Values{"client_id": {"app2"}, "client_secret": {"s3cret2"}}, http.StatusOK, false},
		{"a public owner", cliToken, url.Values{"client_id": {"cli"}}, http.StatusUnauthorized, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cookie := newPublicClientRoutes(t)
			r.tokenStore = tokenstore.New(r.oidc.IDTokenTTL())
			access := tt.token(t, r, cookie)
			form := url.Values{"token": {access}}
			for k, v := range tt.client {
				form[k] = v
			}

			if rec := postRevoke(t, r, form); rec.Code != tt.wantStatus {
				t.Fatalf("revoke = %d %s, want %d", rec.Code, rec.Body.String(), tt.wantStatus)
			}
			_, claims := verifiedClaims(t, r, access)
			if got := r.tokenStore.IsRevoked(claims["jti"].(string)); got != tt.wantRevoked {
				t.Errorf("IsRevoked = %v, want %v", got, tt.wantRevoked)
			}
			wantUserinfo := http.StatusOK
			if tt.wantRevoked {
				wantUserinfo = http.StatusUnauthorized
			}
			if got := userinfoGet(t, r, access); got.Code != wantUserinfo {
				t.Errorf("userinfo after the revoke = %d, want %d", got.Code, wantUserinfo)
			}
		})
	}
}

// moveToQuery posts body to handler with the named parameters moved from the
// body to the URL query.
func moveToQuery(t *testing.T, handler http.HandlerFunc, path string, body url.Values, keys ...string) *httptest.ResponseRecorder {
	t.Helper()
	query := url.Values{}
	for _, k := range keys {
		query[k] = body[k]
		body.Del(k)
	}
	req := httptest.NewRequest(http.MethodPost, path+"?"+query.Encode(), strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// TestOidcToken_CredentialsInQuery takes the client's credentials, the code
// and the verifier from the request body only: in the URL they reach logs.
func TestOidcToken_CredentialsInQuery(t *testing.T) {
	appForm := func(t *testing.T, r *Routes, cookie *http.Cookie) url.Values {
		code := issueCode(t, r, cookie, url.Values{
			"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI},
		})
		return url.Values{
			"grant_type": {"authorization_code"}, "client_id": {"app"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirectURI}, "code": {code},
		}
	}
	cliForm := func(t *testing.T, r *Routes, cookie *http.Cookie) url.Values {
		return tfTokenForm(issueCode(t, r, cookie, cliAuthQuery()))
	}
	tests := []struct {
		name       string
		form       func(t *testing.T, r *Routes, cookie *http.Cookie) url.Values
		key        string
		wantStatus int
		wantError  string
	}{
		{"client_secret", appForm, "client_secret", http.StatusUnauthorized, "invalid_client"},
		{"client_id", appForm, "client_id", http.StatusUnauthorized, "invalid_client"},
		{"code", appForm, "code", http.StatusBadRequest, "invalid_grant"},
		{"code_verifier", cliForm, "code_verifier", http.StatusBadRequest, "invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, cookie := newPublicClientRoutes(t)
			rec := moveToQuery(t, r.OidcToken, "/token", tt.form(t, r, cookie), tt.key)
			if rec.Code != tt.wantStatus || tokenBody(t, rec)["error"] != tt.wantError {
				t.Errorf("token with %s in the query = %d %s, want %d %s", tt.key, rec.Code, rec.Body.String(), tt.wantStatus, tt.wantError)
			}
		})
	}
}

// TestOidcRevoke_CredentialsInQuery takes the client's credentials and the
// token from the request body only.
func TestOidcRevoke_CredentialsInQuery(t *testing.T) {
	tests := []struct {
		key        string
		wantStatus int
	}{
		{"client_secret", http.StatusUnauthorized},
		{"client_id", http.StatusUnauthorized},
		{"token", http.StatusBadRequest}, // the body lacks the token RFC 7009 §2.1 requires
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			r, cookie := newPublicClientRoutes(t)
			r.tokenStore = tokenstore.New(r.oidc.IDTokenTTL())
			code := issueCode(t, r, cookie, url.Values{
				"scope": {"openid"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI},
			})
			tok := postToken(t, r, url.Values{
				"grant_type": {"authorization_code"}, "client_id": {"app"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirectURI}, "code": {code},
			})
			access := tokenBody(t, tok)["access_token"].(string)

			rec := moveToQuery(t, r.OidcRevoke, "/revoke", url.Values{
				"token": {access}, "client_id": {"app"}, "client_secret": {"s3cret"},
			}, tt.key)
			if rec.Code != tt.wantStatus {
				t.Errorf("revoke with %s in the query = %d %s, want %d", tt.key, rec.Code, rec.Body.String(), tt.wantStatus)
			}
			_, claims := verifiedClaims(t, r, access)
			if r.tokenStore.IsRevoked(claims["jti"].(string)) {
				t.Errorf("revoke with %s in the query recorded the revocation", tt.key)
			}
		})
	}
}

// TestOidcRevoke_TokenParameter refuses an authenticated request without a
// token as malformed, since RFC 7009 §2.1 requires the parameter, and records
// nothing for a token another issuer signed with this server's key.
func TestOidcRevoke_TokenParameter(t *testing.T) {
	tests := []struct {
		name        string
		token       func(r *Routes, foreign *oidc.Oidc, bob user.UserInfo) (string, error)
		wantStatus  int
		wantRevoked bool
	}{
		{"absent", nil, http.StatusBadRequest, false},
		{"empty", func(*Routes, *oidc.Oidc, user.UserInfo) (string, error) { return "", nil }, http.StatusBadRequest, false},
		{"foreign issuer", func(_ *Routes, foreign *oidc.Oidc, bob user.UserInfo) (string, error) {
			return foreign.GenerateAccessToken(bob, "app", "")
		}, http.StatusOK, false},
		{"own", func(r *Routes, _ *oidc.Oidc, bob user.UserInfo) (string, error) {
			return r.oidc.GenerateAccessToken(bob, "app", "")
		}, http.StatusOK, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, foreign := newSameKeyRoutes(t)
			bob, _ := r.user.Get("bob")
			form := url.Values{"client_id": {"app"}, "client_secret": {"s3cret"}}
			token := ""
			if tt.token != nil {
				var err error
				if token, err = tt.token(r, foreign, bob); err != nil {
					t.Fatalf("token: %v", err)
				}
				form.Set("token", token)
			}

			rec := postRevoke(t, r, form)
			if rec.Code != tt.wantStatus {
				t.Fatalf("revoke = %d %s, want %d", rec.Code, rec.Body.String(), tt.wantStatus)
			}
			if tt.wantStatus == http.StatusBadRequest && tokenBody(t, rec)["error"] != "invalid_request" {
				t.Errorf("revoke body = %s, want invalid_request", rec.Body.String())
			}
			if token == "" {
				return
			}
			_, claims := verifiedClaims(t, r, token)
			if got := r.tokenStore.IsRevoked(claims["jti"].(string)); got != tt.wantRevoked {
				t.Errorf("IsRevoked = %v, want %v", got, tt.wantRevoked)
			}
		})
	}
}
