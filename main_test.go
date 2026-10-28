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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
				"clients":    []map[string]string{{"id": "c", "redirectUri": "https://rp/cb", "clientSecret": "s"}},
				"signingKey": map[string]any{"filePath": "signing-key.json", "generateIfMissing": true},
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

func TestValidateClientSecret(t *testing.T) {
	tests := []struct {
		name    string
		client  oidc.Client
		wantErr bool
	}{
		{name: "confidential client without a secret", client: oidc.Client{Id: "c", RedirectUri: "https://rp/cb"}, wantErr: true},
		{name: "public client with a secret", client: oidc.Client{Id: "c", RedirectUris: []string{"http://127.0.0.1/cb"}, Public: true, ClientSecret: "s"}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{BaseUrl: "https://host", Clients: []oidc.Client{tc.client}}
			cfg.SigningKey.FilePath = "signing-key.json"
			cfg.SigningKey.GenerateIfMissing = true
			if err := cfg.Validate(); (err != nil) != tc.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidateClientUrisAndResources covers every redirect URI, singular and
// list, and every resource indicator: one bad entry refuses the client.
func TestValidateClientUrisAndResources(t *testing.T) {
	const cb = "http://127.0.0.1/callback"
	tests := []struct {
		name         string
		redirectUri  string
		redirectUris []string
		resources    []string
		wantErr      bool
	}{
		{name: "redirectUris only", redirectUris: []string{cb}},
		{name: "neither redirectUri nor redirectUris", wantErr: true},
		{name: "invalid later list entry", redirectUris: []string{cb, "https://"}, wantErr: true},
		{name: "invalid singular beside a valid list", redirectUri: "https://rp/cb#x", redirectUris: []string{cb}, wantErr: true},
		{name: "non-http redirect scheme", redirectUris: []string{"myapp://callback"}, wantErr: true},
		{name: "relative resource", redirectUris: []string{cb}, resources: []string{"api/v1"}, wantErr: true},
		{name: "resource with an empty fragment", redirectUris: []string{cb}, resources: []string{"https://h/p#"}, wantErr: true},
		{name: "invalid later resource", redirectUris: []string{cb}, resources: []string{"https://h/p", "bad"}, wantErr: true},
		{name: "urn resource", redirectUris: []string{cb}, resources: []string{"urn:example:api"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := oidc.Client{Id: "cli", Public: true, RedirectUri: tc.redirectUri, RedirectUris: tc.redirectUris, Resources: tc.resources}
			cfg := config{BaseUrl: "https://host", Clients: []oidc.Client{client}}
			cfg.SigningKey.FilePath = "signing-key.json"
			cfg.SigningKey.GenerateIfMissing = true
			if err := cfg.Validate(); (err != nil) != tc.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidateClientTokenTTL: a tokenTTL is a duration from a minute to the default; the error names the
// client. A JSON number is refused by the decoder before validation.
func TestValidateClientTokenTTL(t *testing.T) {
	for _, tc := range []struct {
		ttl     string
		wantErr bool
	}{
		{ttl: ""}, {ttl: "1m"}, {ttl: "1h"}, {ttl: "24h"},
		{ttl: "25h", wantErr: true}, {ttl: "59s", wantErr: true}, {ttl: "500ms", wantErr: true}, {ttl: "0s", wantErr: true}, {ttl: "-1h", wantErr: true},
		{ttl: "3600", wantErr: true}, {ttl: "abc", wantErr: true},
	} {
		t.Run(tc.ttl, func(t *testing.T) {
			cfg := config{BaseUrl: "https://host", Clients: []oidc.Client{{Id: "cli", Public: true, RedirectUris: []string{"http://127.0.0.1/callback"}, TokenTTL: tc.ttl}}}
			cfg.SigningKey.FilePath = "signing-key.json"
			cfg.SigningKey.GenerateIfMissing = true
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "(cli)") {
				t.Errorf("error %q does not name the client", err)
			}
		})
	}

	raw, err := json.Marshal(map[string]any{
		"baseUrl":    "https://host",
		"clients":    []map[string]any{{"id": "cli", "public": true, "redirectUris": []string{"http://127.0.0.1/callback"}, "tokenTTL": 3600}},
		"signingKey": map[string]any{"filePath": "signing-key.json", "generateIfMissing": true},
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CONFIG", cfgPath)
	if _, err := LoadConfig(); err == nil {
		t.Error("LoadConfig accepted a JSON number for tokenTTL; it must be a duration string")
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
		Session:     session.New(session.Config{}),
		User:        u,
		CodeStore:   codestore.New(),
		TokenStore:  tokenstore.New(time.Hour),
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

// TestValidateRefusesIneffectiveSettings: each row is a setting that would start
// a server doing something other than what the configuration says.
func TestValidateRefusesIneffectiveSettings(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(c *config)
		wantErr string
	}{
		{name: "valid", modify: func(*config) {}},
		{name: "updateSeedPasswords with filePath and createIfMissing", modify: func(c *config) {
			c.Users = &user.Config{UpdateSeedPasswords: true, FilePath: "users.json", CreateIfMissing: true}
		}},
		{name: "updateSeedPasswords without createIfMissing", modify: func(c *config) {
			c.Users = &user.Config{UpdateSeedPasswords: true, FilePath: "users.json"}
		}, wantErr: "users.updateSeedPasswords requires users.filePath and users.createIfMissing"},
		{name: "updateSeedPasswords without filePath", modify: func(c *config) {
			c.Users = &user.Config{UpdateSeedPasswords: true, CreateIfMissing: true}
		}, wantErr: "users.updateSeedPasswords requires users.filePath and users.createIfMissing"},
		{name: "updateSeedPasswords with static", modify: func(c *config) {
			c.Users = &user.Config{UpdateSeedPasswords: true, FilePath: "users.json", CreateIfMissing: true, Static: true}
		}, wantErr: "users.updateSeedPasswords cannot be combined with users.static"},
		{name: "generateIfMissing without filePath", modify: func(c *config) {
			c.SigningKey.FilePath = ""
		}, wantErr: "signingKey.filePath is required"},
		{name: "no filePath without generateIfMissing", modify: func(c *config) {
			c.SigningKey.FilePath = ""
			c.SigningKey.GenerateIfMissing = false
		}, wantErr: "signingKey.filePath is required"},
		{name: "duplicate client id", modify: func(c *config) {
			c.Clients = append(c.Clients, c.Clients[0])
		}, wantErr: "client 1 (cli): duplicate id"},
		{name: "baseUrl without a host", modify: func(c *config) {
			c.BaseUrl = "https:///idp"
		}, wantErr: "baseUrl must have a host"},
		{name: "baseUrl with a port and no hostname", modify: func(c *config) {
			c.BaseUrl = "https://:443/idp"
		}, wantErr: "baseUrl must have a host"},
		{name: "baseUrl with a hostname and port", modify: func(c *config) {
			c.BaseUrl = "https://idp.example.test:8443/idp"
		}},
		{name: "baseUrl with an IPv6 host", modify: func(c *config) {
			c.BaseUrl = "https://[::1]/idp"
		}},
		{name: "baseUrl with userinfo", modify: func(c *config) {
			c.BaseUrl = "https://admin:secret@host"
		}, wantErr: "baseUrl must not contain userinfo"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{BaseUrl: "https://host", Clients: []oidc.Client{{Id: "cli", Public: true, RedirectUris: []string{"http://127.0.0.1/callback"}}}}
			cfg.SigningKey.FilePath = "signing-key.json"
			cfg.SigningKey.GenerateIfMissing = true
			tc.modify(&cfg)

			err := cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestSessionLimits: the session block takes Go duration strings; an omitted
// field takes its default, "0" disables the idle or absolute limit, and a
// value the server could not honor is refused.
func TestSessionLimits(t *testing.T) {
	const week = 168 * time.Hour
	tests := []struct {
		name    string
		session *sessionConfig
		want    sessionLimits
		wantErr bool
	}{
		{name: "omitted block", want: sessionLimits{cookie: week, Config: session.Config{AbsoluteTTL: week}}},
		{name: "empty block", session: &sessionConfig{}, want: sessionLimits{cookie: week, Config: session.Config{AbsoluteTTL: week}}},
		{name: "absolute follows the cookie", session: &sessionConfig{CookieTTL: "12h"}, want: sessionLimits{cookie: 12 * time.Hour, Config: session.Config{AbsoluteTTL: 12 * time.Hour}}},
		{name: "all set", session: &sessionConfig{CookieTTL: "168h", IdleTTL: "30m", AbsoluteTTL: "24h"}, want: sessionLimits{cookie: week, Config: session.Config{IdleTTL: 30 * time.Minute, AbsoluteTTL: 24 * time.Hour}}},
		{name: "zero disables idle and absolute", session: &sessionConfig{IdleTTL: "0", AbsoluteTTL: "0"}, want: sessionLimits{cookie: week}},
		{name: "days are not a Go duration", session: &sessionConfig{CookieTTL: "7d"}, wantErr: true},
		{name: "bare number", session: &sessionConfig{AbsoluteTTL: "3600"}, wantErr: true},
		{name: "negative idle", session: &sessionConfig{IdleTTL: "-1h"}, wantErr: true},
		{name: "negative absolute", session: &sessionConfig{AbsoluteTTL: "-1s"}, wantErr: true},
		{name: "negative cookie", session: &sessionConfig{CookieTTL: "-168h"}, wantErr: true},
		{name: "overflowing cookie", session: &sessionConfig{CookieTTL: "10000000h"}, wantErr: true},
		{name: "zero cookie", session: &sessionConfig{CookieTTL: "0"}, wantErr: true},
		{name: "cookie under a second", session: &sessionConfig{CookieTTL: "500ms"}, wantErr: true},
		{name: "cookie of one second", session: &sessionConfig{CookieTTL: "1s"}, want: sessionLimits{cookie: time.Second, Config: session.Config{AbsoluteTTL: time.Second}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{BaseUrl: "https://host", Clients: []oidc.Client{{Id: "cli", Public: true, RedirectUris: []string{"http://127.0.0.1/callback"}}}, Session: tc.session}
			cfg.SigningKey.FilePath = "signing-key.json"
			cfg.SigningKey.GenerateIfMissing = true
			if err := cfg.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			got, err := cfg.Session.limits()
			if err != nil || got != tc.want {
				t.Errorf("limits() = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}

	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"session":{"cookieTTL":604800}}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("CONFIG", cfgPath)
	if _, err := LoadConfig(); err == nil {
		t.Error("LoadConfig accepted a JSON number for cookieTTL; it must be a duration string")
	}
}

func TestLogSessionLimits(t *testing.T) {
	clients := []oidc.Client{{Id: "default"}, {Id: "short", TokenTTL: "1h"}}
	tokenTTL := func(id string) time.Duration {
		if id == "short" {
			return time.Hour
		}
		return oidc.DefaultTokenTTL
	}
	tests := []struct {
		name       string
		limits     sessionLimits
		wantLimits string
		wantWarned []string
	}{
		{"defaults", sessionLimits{cookie: 168 * time.Hour, Config: session.Config{AbsoluteTTL: 168 * time.Hour}},
			`"cookie":"168h0m0s","idle":"disabled","absolute":"168h0m0s"`, nil},
		{"absolute between the token lifetimes", sessionLimits{cookie: 168 * time.Hour, Config: session.Config{IdleTTL: 15 * time.Minute, AbsoluteTTL: 8 * time.Hour}},
			`"cookie":"168h0m0s","idle":"15m0s","absolute":"8h0m0s"`, []string{"default"}},
		{"absolute below both", sessionLimits{cookie: time.Hour, Config: session.Config{AbsoluteTTL: 30 * time.Minute}},
			`"absolute":"30m0s"`, []string{"default", "short"}},
		{"absolute disabled", sessionLimits{cookie: time.Minute},
			`"cookie":"1m0s","idle":"disabled","absolute":"disabled"`, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf strings.Builder
			logSessionLimits(slog.New(slog.NewJSONHandler(&buf, nil)), tc.limits, clients, tokenTTL)

			out := buf.String()
			if !strings.Contains(out, tc.wantLimits) {
				t.Errorf("log lacks %s:\n%s", tc.wantLimits, out)
			}
			var warned []string
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				var rec struct {
					Level, Msg string
					ClientID   string `json:"client_id"`
				}
				if err := json.Unmarshal([]byte(line), &rec); err != nil {
					t.Fatalf("log line %q: %v", line, err)
				}
				if rec.Level == "WARN" {
					if !strings.Contains(rec.Msg, "id_token outlives the session") {
						t.Errorf("warning %q", rec.Msg)
					}
					warned = append(warned, rec.ClientID)
				}
			}
			if strings.Join(warned, ",") != strings.Join(tc.wantWarned, ",") {
				t.Errorf("warned for %v, want %v", warned, tc.wantWarned)
			}
		})
	}
}

type countingCleaner struct{ calls chan struct{} }

func (c countingCleaner) CleanUp() { c.calls <- struct{}{} }

func TestSweeperCleansEveryStore(t *testing.T) {
	a, b := countingCleaner{make(chan struct{}, 8)}, countingCleaner{make(chan struct{}, 8)}
	stop := startSweeper(time.Millisecond, a, b)
	defer stop()

	for _, c := range []countingCleaner{a, b} {
		select {
		case <-c.calls:
		case <-time.After(5 * time.Second):
			t.Fatal("a store was not cleaned")
		}
	}
}
