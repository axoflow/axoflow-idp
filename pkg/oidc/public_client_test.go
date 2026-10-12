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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/axoflow/axoflow-idp/pkg/user"
	"github.com/go-jose/go-jose/v3"
)

const (
	testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	mcpResource  = "https://console.example/mcp"
)

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func publicClients() []Client {
	return []Client{
		{Id: "cli", Name: "Console CLI", RedirectUris: []string{"http://127.0.0.1/callback", "http://localhost/callback"}, Public: true, Resources: []string{mcpResource, "urn:example:mcp"}},
		{Id: "app", RedirectUri: "https://app.example.com/cb", ClientSecret: "s3cret"},
	}
}

func TestAllowsRedirect_LoopbackAnyPort(t *testing.T) {
	t.Parallel()
	cli := publicClients()[0]
	tests := []struct {
		uri  string
		want bool
	}{
		{"http://127.0.0.1:8765/callback", true},
		{"http://127.0.0.1:8765/other", false},        // path must match exactly
		{"http://127.0.0.1:8765/callback?x=1", false}, // no query
		{"http://evil.example/callback", false},       // only the registered loopback host
	}
	for _, tt := range tests {
		if got := cli.allowsRedirect(tt.uri); got != tt.want {
			t.Errorf("allowsRedirect(%q) = %v, want %v", tt.uri, got, tt.want)
		}
	}
}

func TestVerifyCodeExchange(t *testing.T) {
	t.Parallel()
	challenge := challengeOf(testVerifier)
	tests := []struct {
		name                string
		challenge, verifier string
		wantErr             error
	}{
		{"challenge answered", challenge, testVerifier, nil},
		{"challenge unanswered", challenge, "", ErrInvalidGrant},
		{"wrong verifier", challenge, strings.Repeat("b", 43), ErrInvalidGrant},
	}
	for _, tt := range tests {
		if err := VerifyCodeExchange(tt.challenge, tt.verifier); !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.wantErr)
		}
	}
}

func TestValidateAuthenticationRequest_PublicClientAndResource(t *testing.T) {
	o := newTestOidc(t, publicClients())
	base := AuthenticationRequest{
		ResponseType:        "code",
		ClientID:            "cli",
		RedirectUri:         "http://127.0.0.1:8765/callback",
		CodeChallenge:       challengeOf(testVerifier),
		CodeChallengeMethod: CodeChallengeMethodS256,
		Resource:            mcpResource,
	}
	if err := o.ValidateAuthenticationRequest(base); err != nil {
		t.Fatalf("a public client with S256 PKCE, a resource and no scope must be accepted: %v", err)
	}

	tests := []struct {
		name    string
		change  func(*AuthenticationRequest)
		wantErr string
	}{
		{"public client without PKCE", func(r *AuthenticationRequest) { r.CodeChallenge, r.CodeChallengeMethod = "", "" }, "invalid_request"},
		{"plain challenge method", func(r *AuthenticationRequest) { r.CodeChallengeMethod = "plain" }, "invalid_request"},
		{"resource not registered for the client", func(r *AuthenticationRequest) { r.Resource = "https://other.example/api" }, "invalid_target"},
		{"resource from a client without a list", func(r *AuthenticationRequest) {
			r.ClientID, r.RedirectUri = "app", "https://app.example.com/cb"
		}, "invalid_target"},
		{"public client implicit flow", func(r *AuthenticationRequest) { r.ResponseType, r.Scope = "id_token", "openid" }, "unsupported_response_type"},
		{"confidential client may skip PKCE", func(r *AuthenticationRequest) {
			r.ClientID, r.RedirectUri, r.CodeChallenge, r.CodeChallengeMethod, r.Resource = "app", "https://app.example.com/cb", "", "", ""
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := base
			tt.change(&req)
			err := o.ValidateAuthenticationRequest(req)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("unexpected error %v", err)
			case tt.wantErr != "" && (err == nil || err.Error() != tt.wantErr):
				t.Errorf("err = %v, want %s", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTokenRequest_PublicClient(t *testing.T) {
	o := newTestOidc(t, publicClients())
	base := TokenRequest{GrantType: "authorization_code", ClientID: "cli", RedirectUri: "http://localhost:9999/callback", Code: "c", CodeVerifier: testVerifier}
	if err := o.ValidateTokenRequest(base); err != nil {
		t.Fatalf("a public client with a verifier and no secret must pass: %v", err)
	}
	tests := []struct {
		name    string
		change  func(*TokenRequest)
		wantErr error
	}{
		{"confidential client still needs its secret", func(r *TokenRequest) {
			r.ClientID, r.RedirectUri, r.CodeVerifier = "app", "https://app.example.com/cb", ""
		}, ErrInvalidClient},
	}
	for _, tt := range tests {
		req := base
		tt.change(&req)
		if err := o.ValidateTokenRequest(req); !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.wantErr)
		}
	}
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

func decodeAccessToken(t *testing.T, o *Oidc, token string) AccessTokenPayload {
	t.Helper()
	tok, err := jose.ParseSigned(token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	payload, err := tok.Verify(o.keychain.GetAll()[0].Public().Key)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	var claims AccessTokenPayload
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func TestGenerateAccessTokenClaims(t *testing.T) {
	o := newSignedOidc(t, Config{Clients: publicClients()})
	u := user.UserInfo{ID: "u1", Username: "alice", Email: "a@example.com", Groups: []string{"admins"}}

	token, err := o.GenerateAccessToken(u, "cli", mcpResource)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if got := tokenType(t, token); got != "at+jwt" {
		t.Errorf("typ = %q, want at+jwt (RFC 9068 section 2.1)", got)
	}
	claims := decodeAccessToken(t, o, token)
	if claims.Audience != mcpResource {
		t.Errorf("aud = %q, want the requested resource %q", claims.Audience, mcpResource)
	}

	plain, err := o.GenerateAccessToken(u, "cli", "")
	if err != nil {
		t.Fatalf("GenerateAccessToken without resource: %v", err)
	}
	plainClaims := decodeAccessToken(t, o, plain)
	if plainClaims.Audience != "cli" {
		t.Errorf("aud without a resource = %q, want the client id", plainClaims.Audience)
	}
}

func TestOpenIDProviderMetadata_AdvertisesPublicClientSupport(t *testing.T) {
	o := newTestOidc(t, publicClients())
	meta := o.GetOpenIDProviderMetadata()
	if !slices.Equal(meta.CodeChallengeMethodsSupported, []string{"S256"}) {
		t.Errorf("code_challenge_methods_supported = %v", meta.CodeChallengeMethodsSupported)
	}
	if !slices.Contains(meta.TokenEndpointAuthMethodsSupported, "none") || !slices.Contains(meta.TokenEndpointAuthMethodsSupported, "client_secret_post") {
		t.Errorf("token_endpoint_auth_methods_supported = %v", meta.TokenEndpointAuthMethodsSupported)
	}
}
