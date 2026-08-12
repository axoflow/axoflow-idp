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

package oidc

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/axoflow/axoflow-idp/pkg/keychain"
	"github.com/axoflow/axoflow-idp/pkg/user"
	"github.com/go-jose/go-jose/v3"
)

func newTestOidc(t *testing.T, clients []Client) *Oidc {
	t.Helper()
	o, err := New(Config{
		BaseUrl:           "https://idp.example.com",
		Clients:           clients,
		Keychain:          keychain.New(),
		SigningKeyPath:    filepath.Join(t.TempDir(), "signing-key.json"),
		GenerateIfMissing: true,
	})
	if err != nil {
		t.Fatalf("oidc.New: %v", err)
	}
	return o
}

func TestValidateRedirect_ExactMatchOnly(t *testing.T) {
	o := newTestOidc(t, []Client{{
		Id:          "app",
		RedirectUri: "https://app.example.com/cb",
	}})

	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"exact match", "https://app.example.com/cb", false},
		{"domain-suffix bypass", "https://app.example.com.evil.com/cb", true},
		{"prefix-append bypass", "https://app.example.com/cb.evil.com", true},
		{"path-append (was allowed by prefix)", "https://app.example.com/cb/extra", true},
		{"trailing slash mismatch", "https://app.example.com/cb/", true},
		{"empty", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := o.ValidateRedirect("app", tt.uri)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateRedirect(%q) err = %v, wantErr = %v", tt.uri, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRedirect_UnknownClient(t *testing.T) {
	o := newTestOidc(t, []Client{{Id: "app", RedirectUri: "https://app.example.com/cb"}})
	if err := o.ValidateRedirect("nope", "https://app.example.com/cb"); err == nil {
		t.Fatal("unknown client should be rejected")
	}
}

func TestValidateRedirect_AllowList(t *testing.T) {
	o := newTestOidc(t, []Client{{
		Id:           "app",
		RedirectUri:  "https://app.example.com/cb",
		RedirectUris: []string{"https://app.example.com/cb2", "https://alt.example.com/cb"},
	}})

	allowed := []string{
		"https://app.example.com/cb",
		"https://app.example.com/cb2",
		"https://alt.example.com/cb",
	}
	for _, uri := range allowed {
		if err := o.ValidateRedirect("app", uri); err != nil {
			t.Errorf("registered uri %q should be allowed: %v", uri, err)
		}
	}
	if err := o.ValidateRedirect("app", "https://app.example.com/cb3"); err == nil {
		t.Error("unregistered uri should be rejected")
	}
}

func TestValidateAuthenticationRequest(t *testing.T) {
	o := newTestOidc(t, []Client{{Id: "app", RedirectUri: "https://app.example.com/cb"}})

	base := AuthenticationRequest{
		Scope:        "openid profile",
		ResponseType: "code",
		ClientID:     "app",
		RedirectUri:  "https://app.example.com/cb",
	}

	if err := o.ValidateAuthenticationRequest(base); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}

	bad := base
	bad.Scope = "profile"
	if err := o.ValidateAuthenticationRequest(bad); err == nil {
		t.Error("missing openid scope should be rejected")
	}

	bad = base
	bad.ResponseType = "token"
	if err := o.ValidateAuthenticationRequest(bad); err == nil {
		t.Error("unsupported response_type should be rejected")
	}

	bad = base
	bad.RedirectUri = "https://app.example.com.evil.com/cb"
	if err := o.ValidateAuthenticationRequest(bad); err == nil {
		t.Error("domain-suffix redirect_uri should be rejected")
	}
}

func TestValidateTokenRequest_ExactRedirect(t *testing.T) {
	o := newTestOidc(t, []Client{{
		Id:           "app",
		RedirectUri:  "https://app.example.com/cb",
		ClientSecret: "secret",
	}})

	base := TokenRequest{
		GrantType:    "authorization_code",
		ClientID:     "app",
		ClientSecret: "secret",
		RedirectUri:  "https://app.example.com/cb",
		Code:         "abc",
	}

	if err := o.ValidateTokenRequest(base); err != nil {
		t.Fatalf("valid token request rejected: %v", err)
	}

	bad := base
	bad.RedirectUri = "https://app.example.com/cb.evil.com"
	if err := o.ValidateTokenRequest(bad); err == nil {
		t.Error("prefix-bypass redirect_uri should be rejected at token")
	}

	bad = base
	bad.ClientSecret = "sekret" // same length as "secret": a length-only compare must still reject
	if err := o.ValidateTokenRequest(bad); err == nil {
		t.Error("bad client secret should be rejected")
	}
}

func newSignedOidc(t *testing.T, cfg Config) *Oidc {
	t.Helper()
	cfg.Keychain = keychain.New()
	cfg.SigningKeyPath = filepath.Join(t.TempDir(), "signing-key.json")
	cfg.GenerateIfMissing = true
	if cfg.BaseUrl == "" {
		cfg.BaseUrl = "https://idp.example.com"
	}
	o, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return o
}

func decodeIDToken(t *testing.T, o *Oidc, idToken string) IDTokenPayload {
	t.Helper()
	tok, err := jose.ParseSigned(idToken)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	payload, err := tok.Verify(o.keychain.GetAll()[0].Public().Key)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	var claims IDTokenPayload
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func TestGenerateIDTokenClaims(t *testing.T) {
	o := newSignedOidc(t, Config{})
	o.idTokenTTL = time.Hour
	u := user.UserInfo{ID: "u1", Username: "alice", Email: "a@example.com", Groups: []string{"admins"}}

	idToken, err := o.GenerateIDToken(u, "app", "nonce-123")
	if err != nil {
		t.Fatalf("GenerateIDToken: %v", err)
	}
	claims := decodeIDToken(t, o, idToken)

	if got := claims.Expiration - claims.IssuedAt; got < 3598 || got > 3600 {
		t.Errorf("exp-iat = %ds, want ~3600 (the configured 1h TTL)", got)
	}
	if claims.Issuer != "https://idp.example.com" {
		t.Errorf("iss = %q, want %q", claims.Issuer, "https://idp.example.com")
	}
	if claims.Audience != "app" {
		t.Errorf("aud = %q, want %q", claims.Audience, "app")
	}
	if claims.Subject != "u1" || claims.Name != "alice" || claims.Email != "a@example.com" {
		t.Errorf("unexpected identity claims: %+v", claims)
	}
	if !slices.Equal(claims.Groups, []string{"admins"}) {
		t.Errorf("groups = %v, want [admins]", claims.Groups)
	}
	if claims.Nonce != "nonce-123" {
		t.Errorf("nonce = %q, want %q", claims.Nonce, "nonce-123")
	}
}

func TestValidateAuthenticationRequestScope(t *testing.T) {
	o := newTestOidc(t, []Client{{
		Id:           "app",
		RedirectUri:  "https://app.example.com/cb",
		ClientSecret: "s3cret",
	}})
	base := func(scope string) AuthenticationRequest {
		return AuthenticationRequest{
			Scope:        scope,
			ResponseType: "code",
			ClientID:     "app",
			RedirectUri:  "https://app.example.com/cb",
		}
	}
	tests := []struct {
		name    string
		scope   string
		wantErr bool
	}{
		{"openid not first", "profile openid", false},
		{"substring notopenid", "notopenid", true},
		{"substring openidx", "openidx", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := o.ValidateAuthenticationRequest(base(tt.scope))
			if (err != nil) != tt.wantErr {
				t.Errorf("scope %q: err = %v, wantErr %v", tt.scope, err, tt.wantErr)
			}
		})
	}
}

func TestValidateRevocationRequest(t *testing.T) {
	o := newTestOidc(t, []Client{{
		Id:           "app",
		RedirectUri:  "https://app.example.com/cb",
		ClientSecret: "s3cret",
	}})
	tests := []struct {
		name string
		req  RevocationRequest
		want error
	}{
		{"credentials are checked before the token", RevocationRequest{Token: "", ClientID: "app", ClientSecret: "s3cret"}, ErrInvalidRequest},
		{"equal-length wrong secret", RevocationRequest{Token: "t", ClientID: "app", ClientSecret: "s3crXt"}, ErrInvalidClient},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := o.ValidateRevocationRequest(tt.req); !errors.Is(err, tt.want) {
				t.Errorf("ValidateRevocationRequest(%+v) error = %v, want %v", tt.req, err, tt.want)
			}
		})
	}
}

func TestFirstClient_RedirectUrisOnly(t *testing.T) {
	o := newTestOidc(t, []Client{{
		Name:         "App",
		RedirectUris: []string{"https://app.example.com/cb"},
	}})

	info := o.FirstClient()
	if info == nil {
		t.Fatal("a client registered only via redirectUris should still yield client info")
	}
	if info.URL != "https://app.example.com" {
		t.Errorf("URL = %q, want %q", info.URL, "https://app.example.com")
	}
}
