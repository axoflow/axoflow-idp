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
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/axoflow/axoflow-idp/internal/codestore"
	"github.com/axoflow/axoflow-idp/internal/tokenstore"
	"github.com/axoflow/axoflow-idp/pkg/keychain"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/go-jose/go-jose/v3"
)

const (
	pkceVerifier      = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	cliResource       = "https://api.example/v1"
	loopbackCallback  = "http://127.0.0.1/callback"
	localhostCallback = "http://localhost/callback"
)

func pkceChallenge() string {
	sum := sha256.Sum256([]byte(pkceVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// newPublicClientRoutes registers the CLI-shaped public client "cli", a
// second public client "cli2" sharing its callback and resource, and the
// confidential "app".
func newPublicClientRoutes(t *testing.T) (*Routes, *http.Cookie) {
	t.Helper()
	r := newTestRoutes(t, false)
	o, err := oidc.New(oidc.Config{
		BaseUrl: "https://idp.example.com",
		Clients: []oidc.Client{
			{Id: "cli", RedirectUris: []string{loopbackCallback, localhostCallback}, Public: true, Resources: []string{cliResource}},
			{Id: "cli2", RedirectUris: []string{loopbackCallback}, Public: true, Resources: []string{cliResource}, TokenTTL: "1h"},
			{Id: "app", RedirectUri: testRedirectURI, ClientSecret: "s3cret"},
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
	return r, &http.Cookie{Name: "session", Value: r.session.Create("bob")}
}

// cliAuthQuery is the authorization request a command-line client sends.
func cliAuthQuery() url.Values {
	return url.Values{
		"scope":                 {"openid profile email"},
		"response_type":         {"code"},
		"client_id":             {"cli"},
		"redirect_uri":          {loopbackCallback},
		"state":                 {"xyz"},
		"code_challenge":        {pkceChallenge()},
		"code_challenge_method": {"S256"},
		"resource":              {cliResource},
	}
}

func tfTokenForm(code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"cli"},
		"redirect_uri":  {loopbackCallback},
		"code":          {code},
		"code_verifier": {pkceVerifier},
	}
}

func authPost(t *testing.T, r *Routes, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oidc/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	r.OidcAuth(rec, req)
	return rec
}

func issueCode(t *testing.T, r *Routes, cookie *http.Cookie, q url.Values) string {
	t.Helper()
	rec := authGet(t, r, cookie, q)
	if rec.Code != http.StatusFound {
		t.Fatalf("auth status = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	lq := locationQuery(t, rec)
	if lq.Get("error") != "" || lq.Get("code") == "" {
		t.Fatalf("auth redirect query = %v, want a code", lq)
	}
	return lq.Get("code")
}

func tokenBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("token body: %v (%s)", err, rec.Body.String())
	}
	return body
}

// verifiedClaims checks the token's signature against the provider's keys and
// returns its typ header and claims.
func verifiedClaims(t *testing.T, r *Routes, token string) (string, map[string]any) {
	t.Helper()
	tok, err := jose.ParseSigned(token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	payload, err := tok.Verify(&jose.JSONWebKeySet{Keys: r.oidc.GetPublicKeys()})
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("token claims: %v", err)
	}
	typ, _ := tok.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	return typ, claims
}

// assertRefusal checks a token refusal: 400 and an envelope that carries the
// error code and nothing else, so no token can ride along.
func assertRefusal(t *testing.T, rec *httptest.ResponseRecorder, wantError string) {
	t.Helper()
	body := tokenBody(t, rec)
	if rec.Code != http.StatusBadRequest || body["error"] != wantError {
		t.Fatalf("refusal = %d %s, want 400 %s", rec.Code, rec.Body.String(), wantError)
	}
	if len(body) != 1 {
		t.Fatalf("a refusal must carry the error and nothing else: %s", rec.Body.String())
	}
}

// loginPost signs bob in through the form the authorization page renders for a
// signed-out browser: the credentials go to the same URL, query included.
func loginPost(t *testing.T, r *Routes, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {"bob"}, "password": {"bobpass1"}}
	req := httptest.NewRequest(http.MethodPost, "/oidc/auth?"+q.Encode(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.OidcAuth(rec, req)
	return rec
}

func TestPublicClient_PKCEFlow(t *testing.T) {
	r, cookie := newPublicClientRoutes(t)

	rec := authGet(t, r, cookie, cliAuthQuery())
	if rec.Code != http.StatusFound {
		t.Fatalf("auth status = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	q := locationQuery(t, rec)
	if q.Get("error") != "" || q.Get("code") == "" || q.Get("state") != "xyz" {
		t.Fatalf("auth redirect query = %v", q)
	}

	tok := postToken(t, r, tfTokenForm(q.Get("code")))
	if tok.Code != http.StatusOK {
		t.Fatalf("token status = %d: %s", tok.Code, tok.Body.String())
	}
	body := tokenBody(t, tok)
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", body["token_type"])
	}
	if body["expires_in"] != float64(86400) {
		t.Errorf("expires_in = %v, want 86400", body["expires_in"])
	}

	access, _ := body["access_token"].(string)
	typ, claims := verifiedClaims(t, r, access)
	if typ != "at+jwt" {
		t.Errorf("access_token typ = %q, want at+jwt", typ)
	}
	want := map[string]any{
		"aud":       cliResource,
		"client_id": "cli",
		"iss":       "https://idp.example.com",
		"sub":       "bob",
	}
	for k, v := range want {
		if claims[k] != v {
			t.Errorf("access_token %s = %v, want %v", k, claims[k], v)
		}
	}

	id, _ := body["id_token"].(string)
	typ, claims = verifiedClaims(t, r, id)
	if typ != "JWT" {
		t.Errorf("id_token typ = %q, want JWT", typ)
	}
	if claims["aud"] != "cli" {
		t.Errorf("id_token aud = %v, want cli", claims["aud"])
	}
}

// A client's tokenTTL reaches the wire: expires_in and both tokens' exp follow it.
func TestPublicClient_TokenTTL(t *testing.T) {
	r, cookie := newPublicClientRoutes(t)
	q := cliAuthQuery()
	q.Set("client_id", "cli2")
	form := tfTokenForm(issueCode(t, r, cookie, q))
	form.Set("client_id", "cli2")

	tok := postToken(t, r, form)
	if tok.Code != http.StatusOK {
		t.Fatalf("token status = %d: %s", tok.Code, tok.Body.String())
	}
	body := tokenBody(t, tok)
	if body["expires_in"] != float64(3600) {
		t.Errorf("expires_in = %v, want 3600 (the client's tokenTTL)", body["expires_in"])
	}
	for _, name := range []string{"access_token", "id_token"} {
		token, _ := body[name].(string)
		_, claims := verifiedClaims(t, r, token)
		if got := claims["exp"].(float64) - claims["iat"].(float64); got != 3600 {
			t.Errorf("%s exp-iat = %v, want 3600", name, got)
		}
	}
}

func TestPublicClient_TokenRefusals(t *testing.T) {
	tests := []struct {
		name string
		// redeemFirst redeems the code with the correct request before the refused one
		redeemFirst bool
		change      func(form url.Values)
		wantError   string
		// spent: the refusal consumed the code, so the correct request fails afterwards
		spent bool
	}{
		{"wrong verifier", false, func(form url.Values) {
			form.Set("code_verifier", strings.Repeat("x", 43))
		}, "invalid_grant", true},
		{"omitted verifier", false, func(form url.Values) {
			form.Del("code_verifier")
		}, "invalid_request", false},
		{"client_secret from a public client", false, func(form url.Values) {
			form.Set("client_secret", "s3cret")
		}, "invalid_request", false},
		{"unregistered loopback port", false, func(form url.Values) {
			form.Set("redirect_uri", "http://127.0.0.1:9999/callback")
		}, "invalid_grant", false},
		{"another public client with the same callback", false, func(form url.Values) {
			form.Set("client_id", "cli2")
		}, "invalid_grant", true},
		{"the client's other registered redirect", false, func(form url.Values) {
			form.Set("redirect_uri", localhostCallback)
		}, "invalid_grant", true},
		{"replay after a successful redemption", true, func(url.Values) {}, "invalid_grant", true},
	}

	r, cookie := newPublicClientRoutes(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := issueCode(t, r, cookie, cliAuthQuery())
			if tt.redeemFirst {
				if rec := postToken(t, r, tfTokenForm(code)); rec.Code != http.StatusOK {
					t.Fatalf("first redemption status = %d: %s", rec.Code, rec.Body.String())
				}
			}

			form := tfTokenForm(code)
			tt.change(form)
			assertRefusal(t, postToken(t, r, form), tt.wantError)

			again := postToken(t, r, tfTokenForm(code))
			if tt.spent {
				assertRefusal(t, again, "invalid_grant")
				return
			}
			if again.Code != http.StatusOK || tokenBody(t, again)["access_token"] == nil {
				t.Fatalf("the code must not be spent: retry = %d %s", again.Code, again.Body.String())
			}
		})
	}
}

// TestPublicClient_TokenResource covers a resource named at /token: it may repeat the
// granted one; another spends the code like the other binding failures; two values are refused before
// the code is looked up, so it stays redeemable.
func TestPublicClient_TokenResource(t *testing.T) {
	tests := []struct {
		name      string
		resources []string
		wantError string // empty: the tokens are issued
		spent     bool
	}{
		{"the granted resource repeated", []string{cliResource}, "", false},
		{"an empty value", []string{""}, "", false},
		{"another resource", []string{"https://api.example/other"}, "invalid_target", true},
		{"two resources", []string{cliResource, "https://api.example/other"}, "invalid_target", false},
	}
	r, cookie := newPublicClientRoutes(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := issueCode(t, r, cookie, cliAuthQuery())
			form := tfTokenForm(code)
			form["resource"] = tt.resources
			rec := postToken(t, r, form)
			if tt.wantError == "" {
				if rec.Code != http.StatusOK {
					t.Fatalf("token status = %d: %s", rec.Code, rec.Body.String())
				}
				_, claims := verifiedClaims(t, r, tokenBody(t, rec)["access_token"].(string))
				if claims["aud"] != cliResource {
					t.Errorf("aud = %v, want %q", claims["aud"], cliResource)
				}
				return
			}
			assertRefusal(t, rec, tt.wantError)
			retry := postToken(t, r, tfTokenForm(code))
			if tt.spent {
				assertRefusal(t, retry, "invalid_grant")
			} else if retry.Code != http.StatusOK {
				t.Errorf("code should still redeem, got %d: %s", retry.Code, retry.Body.String())
			}
		})
	}
}

// TestPublicClient_LoginPostFlow is the signed-out path a command-line
// user takes: the authorization URL renders the login form, the credentials
// are posted to that same URL, and the code redeems to the resource-bound
// access token.
func TestPublicClient_LoginPostFlow(t *testing.T) {
	r, _ := newPublicClientRoutes(t)

	if rec := authGet(t, r, nil, cliAuthQuery()); rec.Code != http.StatusOK {
		t.Fatalf("signed-out authorize status = %d, want 200 (the login form)", rec.Code)
	}

	rec := loginPost(t, r, cliAuthQuery())
	if rec.Code != http.StatusFound {
		t.Fatalf("login status = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(rec.Header().Get("Set-Cookie"), "session=") {
		t.Errorf("Set-Cookie = %q, want a session cookie", rec.Header().Get("Set-Cookie"))
	}
	q := locationQuery(t, rec)
	if q.Get("error") != "" || q.Get("code") == "" || q.Get("state") != "xyz" {
		t.Fatalf("login redirect query = %v", q)
	}

	tok := postToken(t, r, tfTokenForm(q.Get("code")))
	if tok.Code != http.StatusOK {
		t.Fatalf("token status = %d: %s", tok.Code, tok.Body.String())
	}
	access, _ := tokenBody(t, tok)["access_token"].(string)
	typ, claims := verifiedClaims(t, r, access)
	if typ != "at+jwt" || claims["aud"] != cliResource || claims["client_id"] != "cli" {
		t.Errorf("access token typ=%q aud=%v client_id=%v, want at+jwt %q cli", typ, claims["aud"], claims["client_id"], cliResource)
	}

	two := cliAuthQuery()
	two.Add("resource", "https://api.example/other")
	rec = loginPost(t, r, two)
	lq := locationQuery(t, rec)
	if rec.Code != http.StatusFound || lq.Get("error") != "invalid_target" || lq.Get("state") != "xyz" || lq.Get("code") != "" {
		t.Errorf("login with two resources = %d %v, want 302 error=invalid_target state=xyz", rec.Code, lq)
	}
}

func TestPublicClient_AuthorizeRefusals(t *testing.T) {
	r, cookie := newPublicClientRoutes(t)
	twoResources := cliAuthQuery()
	twoResources.Add("resource", "https://api.example/other")

	t.Run("unregistered loopback port is refused in place", func(t *testing.T) {
		q := cliAuthQuery()
		q.Set("redirect_uri", "http://127.0.0.1:9999/callback")
		rec := authGet(t, r, cookie, q)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("must not redirect to an unregistered uri, got Location %q", loc)
		}
	})

	tests := []struct {
		name string
		do   func(t *testing.T, r *Routes, cookie *http.Cookie, q url.Values) *httptest.ResponseRecorder
	}{
		{"two resources on GET", authGet},
		{"two resources on a direct POST", authPost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := tt.do(t, r, cookie, twoResources)
			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302: %s", rec.Code, rec.Body.String())
			}
			u, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			q := u.Query()
			u.RawQuery = ""
			if u.String() != loopbackCallback {
				t.Errorf("redirected to %q, want %q", u, loopbackCallback)
			}
			if q.Get("error") != "invalid_target" || q.Get("state") != "xyz" || q.Get("code") != "" {
				t.Errorf("redirect query = %v, want error=invalid_target and state=xyz", q)
			}
		})
	}
}

func userinfoGet(t *testing.T, r *Routes, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/oidc/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.OidcUserinfo(rec, req)
	return rec
}

// TestUserinfo_AccessTokenOnly covers the confidential client's two tokens at /oidc/userinfo: the access
// token answers, the ID token never does, and once the client revokes the access token neither does.
// Before the access token was split from the ID token, revoking "the token" covered userinfo by itself.
func TestUserinfo_AccessTokenOnly(t *testing.T) {
	r, cookie := newPublicClientRoutes(t)
	r.tokenStore = tokenstore.New(r.oidc.IDTokenTTL())
	q := url.Values{
		"scope": {"openid profile email"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}, "nonce": {"n1"},
	}
	code := issueCode(t, r, cookie, q)
	rec := postToken(t, r, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"app"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirectURI}, "code": {code},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("token status = %d: %s", rec.Code, rec.Body.String())
	}
	body := tokenBody(t, rec)
	id, _ := body["id_token"].(string)
	access, _ := body["access_token"].(string)

	if got := userinfoGet(t, r, access); got.Code != http.StatusOK {
		t.Fatalf("userinfo with the access token = %d: %s", got.Code, got.Body.String())
	} else {
		var info map[string]any
		if err := json.Unmarshal(got.Body.Bytes(), &info); err != nil {
			t.Fatalf("userinfo body: %v", err)
		}
		_, claims := verifiedClaims(t, r, access)
		if info["sub"] != claims["sub"] || info["sub"] == "" {
			t.Errorf("userinfo sub = %v, want the token's %v", info["sub"], claims["sub"])
		}
	}
	if got := userinfoGet(t, r, id); got.Code != http.StatusUnauthorized {
		t.Errorf("userinfo with the ID token = %d, want 401", got.Code)
	}
	// the parser accepts other spellings of the same token; they must share its revocation below
	for name, alias := range tokenAliases(t, access) {
		if got := userinfoGet(t, r, alias); got.Code != http.StatusOK {
			t.Fatalf("userinfo with the token as %s = %d before revocation, want 200", name, got.Code)
		}
	}

	revoke := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(url.Values{
		"token": {access}, "client_id": {"app"}, "client_secret": {"s3cret"},
	}.Encode()))
	revoke.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revoked := httptest.NewRecorder()
	r.OidcRevoke(revoked, revoke)
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke = %d: %s", revoked.Code, revoked.Body.String())
	}
	if got := userinfoGet(t, r, access); got.Code != http.StatusUnauthorized {
		t.Errorf("userinfo with the revoked access token = %d, want 401", got.Code)
	}
	if got := userinfoGet(t, r, id); got.Code != http.StatusUnauthorized {
		t.Errorf("userinfo with the ID token after revocation = %d, want 401", got.Code)
	}
	// the revocation holds for every spelling of the token, since it is recorded under the jti
	for name, alias := range tokenAliases(t, access) {
		if got := userinfoGet(t, r, alias); got.Code != http.StatusUnauthorized {
			t.Errorf("userinfo with the revoked token as %s = %d, want 401", name, got.Code)
		}
	}
}

// tokenAliases returns spellings of a compact JWS that parse and verify as the same token: an internal
// space, the flattened JSON serialization, and a signature whose unused padding bit is flipped.
func tokenAliases(t *testing.T, compact string) map[string]string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	signature := parts[2]
	last := strings.IndexByte(alphabet, signature[len(signature)-1])
	padBit := signature[:len(signature)-1] + string(alphabet[last^1])
	want, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("signature: %v", err)
	}
	if got, err := base64.RawURLEncoding.DecodeString(padBit); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("padding-bit alias does not decode to the same signature: %v", err)
	}
	return map[string]string{
		"internal space":        parts[0] + ". " + parts[1] + "." + parts[2],
		"flattened JSON":        `{"protected":"` + parts[0] + `","payload":"` + parts[1] + `","signature":"` + parts[2] + `"}`,
		"padding-bit signature": parts[0] + "." + parts[1] + "." + padBit,
	}
}

// TestConfidentialClient_CodeFlow covers a confidential web client's flow: a client secret,
// with or without an S256 challenge.
func TestConfidentialClient_CodeFlow(t *testing.T) {
	tests := []struct {
		name      string
		challenge bool
		verifier  string
		wantError string // empty: both tokens are issued
	}{
		{"without PKCE", false, "", ""},
		{"S256 with the correct verifier", true, pkceVerifier, ""},
		{"S256 with a wrong verifier", true, strings.Repeat("x", 43), "invalid_grant"},
		{"S256 with the verifier omitted", true, "", "invalid_grant"},
	}

	r, cookie := newPublicClientRoutes(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := url.Values{
				"scope": {"openid profile email"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}, "nonce": {"n1"},
			}
			if tt.challenge {
				q.Set("code_challenge", pkceChallenge())
				q.Set("code_challenge_method", "S256")
			}
			code := issueCode(t, r, cookie, q)
			form := func(verifier string) url.Values {
				f := url.Values{
					"grant_type": {"authorization_code"}, "client_id": {"app"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirectURI}, "code": {code},
				}
				if verifier != "" {
					f.Set("code_verifier", verifier)
				}
				return f
			}

			rec := postToken(t, r, form(tt.verifier))
			if tt.wantError != "" {
				assertRefusal(t, rec, tt.wantError)
				assertRefusal(t, postToken(t, r, form(pkceVerifier)), "invalid_grant")
				return
			}

			if rec.Code != http.StatusOK {
				t.Fatalf("token status = %d: %s", rec.Code, rec.Body.String())
			}
			body := tokenBody(t, rec)
			id, _ := body["id_token"].(string)
			access, _ := body["access_token"].(string)
			if id == "" || access == "" {
				t.Fatalf("both tokens expected: %v", body)
			}
			if typ, _ := verifiedClaims(t, r, id); typ != "JWT" {
				t.Errorf("id_token typ = %q, want JWT", typ)
			}
			typ, claims := verifiedClaims(t, r, access)
			if typ != "at+jwt" {
				t.Errorf("access_token typ = %q, want at+jwt", typ)
			}
			if claims["aud"] != "app" {
				t.Errorf("access_token aud = %v, want app", claims["aud"])
			}
		})
	}
}
