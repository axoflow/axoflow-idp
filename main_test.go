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

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/axoflow/axoflow-idp/internal/codestore"
	"github.com/axoflow/axoflow-idp/internal/resettoken"
	"github.com/axoflow/axoflow-idp/internal/routes"
	"github.com/axoflow/axoflow-idp/internal/session"
	"github.com/axoflow/axoflow-idp/internal/tokenstore"
	"github.com/axoflow/axoflow-idp/pkg/keychain"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

// TestBaseUrlPrefixDerivation drives LoadConfig + Validate end to end: the
// trailing-slash trim, the derived prefix, and the rejection of baseUrl paths
// that would otherwise register mux patterns no request can ever match (the
// mux path-cleans and redirects incoming requests, the patterns stay verbatim)
// or that would panic HandleFunc at startup ("{" is wildcard syntax).
func TestBaseUrlPrefixDerivation(t *testing.T) {
	tests := []struct {
		baseUrl string
		prefix  string
		wantErr bool
	}{
		{baseUrl: "https://host", prefix: ""},
		{baseUrl: "https://host/", prefix: ""},
		{baseUrl: "https://host/idp", prefix: "/idp"},
		{baseUrl: "https://host/idp/", prefix: "/idp"},
		{baseUrl: "https://host/a/b", prefix: "/a/b"},
		{baseUrl: "https://host//idp", wantErr: true},
		{baseUrl: "https://host/idp/../admin", wantErr: true},
		{baseUrl: "https://host/./idp", wantErr: true},
		{baseUrl: "https://host/idp{x}", wantErr: true},
		{baseUrl: "https://host/my%20idp", wantErr: true},
		{baseUrl: "https://host/idp?x=1", wantErr: true},
		{baseUrl: "https://host/idp#frag", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.baseUrl, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"baseUrl":    tc.baseUrl,
				"clients":    []map[string]string{{"id": "c", "redirectUri": "https://rp/cb"}},
				"signingKey": map[string]any{"generateIfMissing": true},
			})
			if err != nil {
				t.Fatalf("marshal config: %v", err)
			}
			cfgPath := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			t.Setenv("CONFIG", cfgPath)

			cfg, err := LoadConfig()
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}

			err = cfg.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate() accepted %q, want an error", tc.baseUrl)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() rejected %q: %v", tc.baseUrl, err)
			}

			parsed, err := url.Parse(cfg.BaseUrl)
			if err != nil {
				t.Fatalf("parse validated baseUrl: %v", err)
			}
			if parsed.Path != tc.prefix {
				t.Errorf("derived prefix = %q, want %q", parsed.Path, tc.prefix)
			}
		})
	}
}

// newTestMux builds the real handler stack — OIDC provider, routes, mux — the
// same way main() does, so the registered patterns are the ones production
// serves.
func newTestMux(t *testing.T, baseUrl string) *http.ServeMux {
	t.Helper()

	o, err := oidc.New(oidc.Config{
		BaseUrl:           baseUrl,
		Clients:           []oidc.Client{{Id: "c", RedirectUri: "https://rp/cb"}},
		Keychain:          keychain.New(),
		SigningKeyPath:    filepath.Join(t.TempDir(), "signing-key.json"),
		GenerateIfMissing: true,
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}

	u, err := user.New(user.Config{UserAdminGroup: "admin"})
	if err != nil {
		t.Fatalf("user.New: %v", err)
	}

	parsed, err := url.Parse(baseUrl)
	if err != nil {
		t.Fatalf("parse baseUrl: %v", err)
	}

	r, err := routes.New(routes.Config{
		Oidc:        o,
		Session:     session.New(),
		User:        u,
		CodeStore:   codestore.New(),
		TokenStore:  tokenstore.New(tokenstore.Config{TTL: time.Hour}),
		ResetTokens: resettoken.New(time.Hour),
		BaseURL:     baseUrl,
		PathPrefix:  parsed.Path,
	})
	if err != nil {
		t.Fatalf("routes.New: %v", err)
	}

	return newMux(r, parsed.Path, u)
}

// TestMuxWiring exercises the pattern registration under a prefix and at the
// host root: the prefix subtree serves, everything outside it 404s, and the
// bare prefix redirects onto the subtree root (which is what makes the cookie
// path "/idp/" reachable for a browser that requests "/idp").
func TestMuxWiring(t *testing.T) {
	tests := []struct {
		name     string
		baseUrl  string
		method   string
		path     string
		wantCode int
		wantLoc  string
	}{
		{name: "prefix root serves", baseUrl: "https://host/idp", method: "GET", path: "/idp/", wantCode: http.StatusOK},
		// The status code of the mux's trailing-slash redirect is an
		// implementation detail (301 or 307 depending on the Go version), so
		// a wantLoc without a wantCode asserts "any redirect to wantLoc".
		{name: "bare prefix redirects onto the subtree", baseUrl: "https://host/idp", method: "GET", path: "/idp", wantLoc: "/idp/"},
		{name: "host root is not served", baseUrl: "https://host/idp", method: "GET", path: "/", wantCode: http.StatusNotFound},
		{name: "unprefixed route is not served", baseUrl: "https://host/idp", method: "GET", path: "/login", wantCode: http.StatusNotFound},
		{name: "unknown path under the prefix 404s", baseUrl: "https://host/idp", method: "GET", path: "/idp/nonexistent", wantCode: http.StatusNotFound},
		{name: "login serves under the prefix", baseUrl: "https://host/idp", method: "GET", path: "/idp/login", wantCode: http.StatusOK},
		{name: "protected route redirects inside the prefix", baseUrl: "https://host/idp", method: "GET", path: "/idp/password", wantCode: http.StatusFound, wantLoc: "/idp/login"},
		{name: "discovery serves under the prefix", baseUrl: "https://host/idp", method: "GET", path: "/idp/.well-known/openid-configuration", wantCode: http.StatusOK},
		{name: "root serves without a prefix", baseUrl: "https://host", method: "GET", path: "/", wantCode: http.StatusOK},
		{name: "unknown path 404s without a prefix", baseUrl: "https://host", method: "GET", path: "/nonexistent", wantCode: http.StatusNotFound},
	}

	// One mux per distinct baseUrl; signing-key generation is too slow to
	// repeat for every request.
	muxes := map[string]*http.ServeMux{}
	for _, tc := range tests {
		if muxes[tc.baseUrl] == nil {
			muxes[tc.baseUrl] = newTestMux(t, tc.baseUrl)
		}
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			muxes[tc.baseUrl].ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			switch {
			case tc.wantCode != 0 && rec.Code != tc.wantCode:
				t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.wantCode)
			case tc.wantCode == 0 && (rec.Code < 300 || rec.Code >= 400):
				t.Errorf("%s %s = %d, want a redirect", tc.method, tc.path, rec.Code)
			}
			if tc.wantLoc != "" {
				if loc := rec.Header().Get("Location"); loc != tc.wantLoc {
					t.Errorf("%s %s Location = %q, want %q", tc.method, tc.path, loc, tc.wantLoc)
				}
			}
		})
	}
}

// TestDiscoveryDocumentUnderPrefix checks that the URLs the discovery document
// advertises are the ones the mux actually serves.
func TestDiscoveryDocumentUnderPrefix(t *testing.T) {
	const baseUrl = "https://host/idp"
	mux := newTestMux(t, baseUrl)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/idp/.well-known/openid-configuration", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("discovery = %d, want 200", rec.Code)
	}

	var meta struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKsUri               string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("unmarshal discovery document: %v", err)
	}

	if meta.Issuer != baseUrl {
		t.Errorf("issuer = %q, want %q", meta.Issuer, baseUrl)
	}

	// Every advertised endpoint must resolve to a registered route.
	for name, endpoint := range map[string]string{
		"authorization_endpoint": meta.AuthorizationEndpoint,
		"token_endpoint":         meta.TokenEndpoint,
		"jwks_uri":               meta.JWKsUri,
	} {
		u, err := url.Parse(endpoint)
		if err != nil {
			t.Fatalf("parse %s %q: %v", name, endpoint, err)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, u.Path, nil))
		if rec.Code == http.StatusNotFound || rec.Code == http.StatusMovedPermanently {
			t.Errorf("%s %q is advertised but not served: got %d", name, endpoint, rec.Code)
		}
	}
}
