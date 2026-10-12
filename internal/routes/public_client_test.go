// Copyright © 2025 Axoflow
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
	"github.com/axoflow/axoflow-idp/pkg/keychain"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/go-jose/go-jose/v3"
)

const (
	pkceVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	mcpResource  = "https://console.example/mcp"
	cliCallback  = "http://127.0.0.1:51234/callback"
)

func pkceChallenge() string {
	sum := sha256.Sum256([]byte(pkceVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func newPublicClientRoutes(t *testing.T) (*Routes, *http.Cookie) {
	t.Helper()
	r := newTestRoutes(t, false)
	o, err := oidc.New(oidc.Config{
		BaseUrl: "https://idp.example.com",
		Clients: []oidc.Client{
			{Id: "mcpc", Name: "mcpc", RedirectUris: []string{"http://127.0.0.1/callback"}, Public: true, Resources: []string{mcpResource}},
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

func mcpAuthQuery() url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"mcpc"},
		"redirect_uri":          {cliCallback},
		"state":                 {"xyz"},
		"code_challenge":        {pkceChallenge()},
		"code_challenge_method": {"S256"},
		"resource":              {mcpResource},
	}
}

func tokenBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("token body: %v (%s)", err, rec.Body.String())
	}
	return body
}

func tokenType(t *testing.T, token string) string {
	t.Helper()
	tok, err := jose.ParseSigned(token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	typ, _ := tok.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	return typ
}

func TestPublicClient_PKCEFlow(t *testing.T) {
	r, cookie := newPublicClientRoutes(t)

	rec := authGet(t, r, cookie, mcpAuthQuery())
	if rec.Code != http.StatusFound {
		t.Fatalf("auth status = %d, want 302: %s", rec.Code, rec.Body.String())
	}
	q := locationQuery(t, rec)
	if q.Get("error") != "" || q.Get("code") == "" || q.Get("state") != "xyz" {
		t.Fatalf("auth redirect query = %v", q)
	}

	tok := postToken(t, r, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"mcpc"},
		"redirect_uri":  {cliCallback},
		"code":          {q.Get("code")},
		"code_verifier": {pkceVerifier},
	})
	if tok.Code != http.StatusOK {
		t.Fatalf("token status = %d: %s", tok.Code, tok.Body.String())
	}
	body := tokenBody(t, tok)
	if _, has := body["id_token"]; has {
		t.Error("no openid scope: no id_token must be issued")
	}
}

func TestPublicClient_TokenRefusals(t *testing.T) {
	tests := []struct {
		name      string
		change    func(form url.Values)
		wantError string
		// spent: the refusal consumed the code, so the correct request fails afterwards
		spent bool
	}{
		{"wrong verifier is invalid_grant and spends the code", func(form url.Values) {
			form.Set("code_verifier", strings.Repeat("x", 43))
		}, "invalid_grant", true},
	}

	r, cookie := newPublicClientRoutes(t)
	base := func(code string) url.Values {
		return url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"mcpc"},
			"redirect_uri":  {cliCallback},
			"code":          {code},
			"code_verifier": {pkceVerifier},
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := locationQuery(t, authGet(t, r, cookie, mcpAuthQuery()))
			code := q.Get("code")
			if code == "" {
				t.Fatalf("no code issued: %v", q)
			}
			form := base(code)
			tt.change(form)
			rec := postToken(t, r, form)
			if rec.Code != http.StatusBadRequest || tokenBody(t, rec)["error"] != tt.wantError {
				t.Fatalf("status/body = %d %s, want 400 %s", rec.Code, rec.Body.String(), tt.wantError)
			}
			if tt.spent {
				again := postToken(t, r, base(code))
				if again.Code != http.StatusBadRequest || tokenBody(t, again)["error"] != "invalid_grant" {
					t.Fatalf("the right verifier after a wrong one must find the code spent: %d %s", again.Code, again.Body.String())
				}
			}
		})
	}
}

func loginPost(t *testing.T, r *Routes, target string, handler http.HandlerFunc, password string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"username": {"bob"}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestPublicClient_LoginPageNamesTheClient(t *testing.T) {
	const banner = "Sign in to continue to <strong>mcpc</strong>"
	invalid := mcpAuthQuery()
	invalid.Set("redirect_uri", "http://evil.example/callback")

	tests := []struct {
		name       string
		do         func(t *testing.T, r *Routes) *httptest.ResponseRecorder
		wantStatus int
		wantBanner bool
	}{
		{"authorization request without a session", func(t *testing.T, r *Routes) *httptest.ResponseRecorder {
			return authGet(t, r, nil, mcpAuthQuery())
		}, http.StatusOK, true},
		{"wrong password on an invalid authorization request", func(t *testing.T, r *Routes) *httptest.ResponseRecorder {
			return loginPost(t, r, "/oidc/auth?"+invalid.Encode(), r.OidcAuth, "wrong")
		}, http.StatusUnauthorized, false},
	}

	r, _ := newPublicClientRoutes(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := tt.do(t, r)
			body := rec.Body.String()
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d:\n%s", rec.Code, tt.wantStatus, body)
			}
			if tt.wantStatus == http.StatusUnauthorized && !strings.Contains(body, "Invalid username or password") {
				t.Errorf("the retry page does not show the error:\n%s", body)
			}
			if tt.wantBanner && !strings.Contains(body, banner) {
				t.Errorf("the login page does not name the client:\n%s", body)
			}
			if !tt.wantBanner && strings.Contains(body, "continue to") {
				t.Errorf("the login page must not name a client:\n%s", body)
			}
		})
	}
}

func TestConfidentialClient_CodeFlow(t *testing.T) {
	r, cookie := newPublicClientRoutes(t)
	q := locationQuery(t, authGet(t, r, cookie, url.Values{
		"scope": {"openid profile email"}, "response_type": {"code"}, "client_id": {"app"}, "redirect_uri": {testRedirectURI}, "nonce": {"n1"},
	}))
	rec := postToken(t, r, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"app"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirectURI}, "code": {q.Get("code")},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("token status = %d: %s", rec.Code, rec.Body.String())
	}
	body := tokenBody(t, rec)
	id, _ := body["id_token"].(string)
	access, _ := body["access_token"].(string)
	if id == "" || access == "" {
		t.Fatalf("both tokens expected: %v", body)
	}
	if got := tokenType(t, id); got != "JWT" {
		t.Errorf("id_token typ = %q, want JWT", got)
	}
	if got := tokenType(t, access); got != "at+jwt" {
		t.Errorf("access_token typ = %q, want at+jwt", got)
	}
}
