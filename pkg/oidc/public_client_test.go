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
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/axoflow/axoflow-idp/pkg/user"
	"github.com/go-jose/go-jose/v3"
)

const (
	testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	cliResource  = "https://api.example/v1"
	// registered on purpose, so the syntax check cannot hide behind the allow-list
	malformedResource = "not a uri#frag"
)

func challengeOf(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func publicClients() []Client {
	return []Client{
		{
			Id:           "cli",
			Name:         "Example CLI",
			RedirectUris: []string{"http://127.0.0.1/callback", "http://localhost/callback"},
			Public:       true,
			Resources:    []string{cliResource, "urn:example:api", malformedResource},
		},
		{Id: "app", RedirectUri: "https://app.example.com/cb", ClientSecret: "s3cret"},
	}
}

func TestVerifyPKCE(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		verifier string
		want     bool
	}{
		{"43 characters", testVerifier, true},
		{"64 characters, the openssl rand 48 shape", "q3ZJ8f-Lx2_TbN0vWmR7yKcD1aE5gH9iJ4kP6sU8wXzYoQnB-_tV3rL0mC2dF7hG", true},
		{"128 characters", strings.Repeat("A1._~-zZ", 16), true},
		{"42 characters", testVerifier[:42], false},
		{"129 characters", strings.Repeat("a", 129), false},
		{"plus sign", testVerifier[:42] + "+", false},
		{"slash", testVerifier[:42] + "/", false},
		{"padding", testVerifier[:42] + "=", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the challenge is derived from the same verifier, so only the syntax can refuse it
			if got := VerifyPKCE(challengeOf(tt.verifier), tt.verifier); got != tt.want {
				t.Errorf("VerifyPKCE(len %d) = %v, want %v", len(tt.verifier), got, tt.want)
			}
		})
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
		{"wrong verifier", challenge, strings.Repeat("b", 43), ErrInvalidGrant},
		{"challenge without verifier", challenge, "", ErrInvalidGrant},
		{"verifier without challenge", "", testVerifier, ErrInvalidGrant},
		{"neither", "", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyCodeExchange(tt.challenge, tt.verifier); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAuthenticationRequest_PublicClientAndResource(t *testing.T) {
	o := newTestOidc(t, publicClients())
	challenge := challengeOf(testVerifier)
	base := AuthenticationRequest{
		Scope:               "openid",
		ResponseType:        "code",
		ClientID:            "cli",
		RedirectUri:         "http://127.0.0.1/callback",
		CodeChallenge:       challenge,
		CodeChallengeMethod: CodeChallengeMethodS256,
		Resources:           []string{cliResource},
	}

	tests := []struct {
		name    string
		change  func(*AuthenticationRequest)
		wantErr string
	}{
		{"public client with S256 PKCE and a registered resource", func(*AuthenticationRequest) {}, ""},
		{"public client without PKCE", func(r *AuthenticationRequest) { r.CodeChallenge, r.CodeChallengeMethod = "", "" }, "invalid_request"},
		{"plain challenge method", func(r *AuthenticationRequest) { r.CodeChallengeMethod = "plain" }, "invalid_request"},
		{"method without challenge", func(r *AuthenticationRequest) { r.CodeChallenge = "" }, "invalid_request"},
		{"challenge without method", func(r *AuthenticationRequest) { r.CodeChallengeMethod = "" }, "invalid_request"},
		{"42-character challenge", func(r *AuthenticationRequest) { r.CodeChallenge = challenge[:42] }, "invalid_request"},
		{"challenge with a plus sign", func(r *AuthenticationRequest) { r.CodeChallenge = challenge[:42] + "+" }, "invalid_request"},
		{"resource not registered for the client", func(r *AuthenticationRequest) { r.Resources = []string{"https://other.example/api"} }, "invalid_target"},
		{"resource with a registered prefix", func(r *AuthenticationRequest) { r.Resources = []string{cliResource + "/extra"} }, "invalid_target"},
		{"empty resource value counts as omitted (RFC 6749 §3.1)", func(r *AuthenticationRequest) { r.Resources = []string{""} }, ""},
		{"resource from a client without a list", func(r *AuthenticationRequest) {
			r.ClientID, r.RedirectUri = "app", "https://app.example.com/cb"
		}, "invalid_target"},
		{"registered but malformed resource", func(r *AuthenticationRequest) { r.Resources = []string{malformedResource} }, "invalid_target"},
		{"two registered resources", func(r *AuthenticationRequest) { r.Resources = []string{cliResource, "urn:example:api"} }, "invalid_target"},
		{"public client implicit flow", func(r *AuthenticationRequest) { r.ResponseType = "id_token" }, "unsupported_response_type"},
		{"code flow without openid", func(r *AuthenticationRequest) { r.Scope = "profile" }, "invalid_scope"},
		{"confidential client may skip PKCE", func(r *AuthenticationRequest) {
			r.ClientID, r.RedirectUri, r.CodeChallenge, r.CodeChallengeMethod, r.Resources = "app", "https://app.example.com/cb", "", "", nil
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
	base := TokenRequest{GrantType: "authorization_code", ClientID: "cli", RedirectUri: "http://localhost/callback", Code: "c", CodeVerifier: testVerifier}
	tests := []struct {
		name    string
		change  func(*TokenRequest)
		wantErr error
	}{
		{"public client with a verifier and no secret", func(*TokenRequest) {}, nil},
		{"public client sending a client_secret", func(r *TokenRequest) { r.ClientSecret = "s3cret" }, ErrInvalidRequest},
		{"public client without code_verifier", func(r *TokenRequest) { r.CodeVerifier = "" }, ErrInvalidRequest},
		{"confidential client still needs its secret", func(r *TokenRequest) {
			r.ClientID, r.RedirectUri, r.CodeVerifier = "app", "https://app.example.com/cb", ""
		}, ErrInvalidClient},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := base
			tt.change(&req)
			if err := o.ValidateTokenRequest(req); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTokenRequest_Resources(t *testing.T) {
	o := newTestOidc(t, publicClients())
	base := TokenRequest{GrantType: "authorization_code", ClientID: "cli", RedirectUri: "http://localhost/callback", Code: "c", CodeVerifier: testVerifier}
	tests := []struct {
		name      string
		resources []string
		wantErr   error
	}{
		{"no resource", nil, nil},
		{"one resource", []string{cliResource}, nil},
		{"an empty value counts as omitted (RFC 6749 §3.1)", []string{""}, nil},
		{"an empty value beside one resource", []string{"", cliResource}, nil},
		{"two resources", []string{cliResource, "https://api.example/other"}, ErrInvalidTarget},
		{"the same resource twice", []string{cliResource, cliResource}, ErrInvalidTarget},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := base
			req.Resources = tt.resources
			if err := o.ValidateTokenRequest(req); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyTokenResource(t *testing.T) {
	tests := []struct {
		name      string
		resources []string
		granted   string
		wantErr   error
	}{
		{"absent, grant for the client", nil, "", nil},
		{"absent, grant for a resource", nil, cliResource, nil},
		{"the granted resource", []string{cliResource}, cliResource, nil},
		{"empty value, grant for a resource", []string{""}, cliResource, nil},
		{"another resource", []string{"https://api.example/other"}, cliResource, ErrInvalidTarget},
		{"a resource when the grant is for the client", []string{cliResource}, "", ErrInvalidTarget},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := TokenRequest{Resources: tt.resources}
			if err := VerifyTokenResource(req, tt.granted); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRevocationRequest_PublicClientCannotRevoke(t *testing.T) {
	o := newTestOidc(t, publicClients())
	tests := []struct {
		name string
		req  RevocationRequest
		want error
	}{
		{"public client without a secret", RevocationRequest{Token: "t", ClientID: "cli"}, ErrInvalidClient},
		{"public client with a secret", RevocationRequest{Token: "t", ClientID: "cli", ClientSecret: "s3cret"}, ErrInvalidClient},
		{"confidential client with its secret", RevocationRequest{Token: "t", ClientID: "app", ClientSecret: "s3cret"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := o.ValidateRevocationRequest(tt.req); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
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

// accessTokenClaims verifies token and returns its claims under their wire names.
func accessTokenClaims(t *testing.T, o *Oidc, token string) map[string]any {
	t.Helper()
	tok, err := jose.ParseSigned(token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	payload, err := tok.Verify(o.keychain.GetAll()[0].Public().Key)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

// TestGetUserinfoFromToken_AccessTokenOnly pins that userinfo is served from the at+jwt access token and
// that the ID token of the same response is refused: revoking the access token must not leave a second
// credential for the endpoint.
func TestGetUserinfoFromToken_AccessTokenOnly(t *testing.T) {
	o := newTestOidc(t, publicClients())
	u := user.UserInfo{ID: "u1", Username: "alice", Email: "a@example.com", Groups: []string{"admins"}}
	access, err := o.GenerateAccessToken(u, "cli", cliResource)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	id, err := o.GenerateIDToken(u, "cli", "n1")
	if err != nil {
		t.Fatalf("GenerateIDToken: %v", err)
	}

	info, err := o.GetUserinfoFromToken(access)
	if err != nil {
		t.Fatalf("userinfo from the access token: %v", err)
	}
	want := &UserinfoResponse{Subject: "u1", Name: "alice", Email: "a@example.com", Groups: []string{"admins"}}
	if !reflect.DeepEqual(info, want) {
		t.Errorf("userinfo = %+v, want %+v", info, want)
	}
	if _, err := o.GetUserinfoFromToken(id); err == nil {
		t.Error("the ID token was accepted as a userinfo bearer")
	}
}

// TestGetUserinfoFromToken_Claims refuses, in the validator itself, a token
// without a subject and one whose audience is a resource of another client.
func TestGetUserinfoFromToken_Claims(t *testing.T) {
	o := newTestOidc(t, publicClients())
	alice := user.UserInfo{ID: "u1", Username: "alice"}
	tests := []struct {
		name     string
		user     user.UserInfo
		clientID string
		resource string
		wantOK   bool
	}{
		{"the client's own resource", alice, "cli", cliResource, true},
		{"empty sub", user.UserInfo{Username: "alice"}, "cli", cliResource, false},
		{"another client's resource", alice, "app", cliResource, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := o.GenerateAccessToken(tt.user, tt.clientID, tt.resource)
			if err != nil {
				t.Fatalf("GenerateAccessToken: %v", err)
			}
			if _, err := o.GetUserinfoFromToken(token); (err == nil) != tt.wantOK {
				t.Errorf("GetUserinfoFromToken error = %v, want accepted %v", err, tt.wantOK)
			}
		})
	}
}

// TestAccessTokenID pins the revocation identity: the jti of a verified access token, also when expired;
// nothing for an ID token, a foreign signature or garbage.
func TestAccessTokenID(t *testing.T) {
	o := newTestOidc(t, publicClients())
	u := user.UserInfo{ID: "u1", Username: "alice"}
	access, err := o.GenerateAccessToken(u, "cli", cliResource)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	id, err := o.AccessTokenID(access)
	if err != nil || id == "" {
		t.Fatalf("AccessTokenID = %q, %v", id, err)
	}
	if got := accessTokenClaims(t, o, access)["jti"]; got != id {
		t.Errorf("AccessTokenID = %q, jti claim %v", id, got)
	}

	o.idTokenTTL = -time.Hour
	expired, err := o.GenerateAccessToken(u, "cli", cliResource)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	if _, err := o.AccessTokenID(expired); err != nil {
		t.Errorf("an expired access token has no id: %v (it must stay revocable)", err)
	}
	o.idTokenTTL = time.Hour

	idToken, err := o.GenerateIDToken(u, "cli", "n1")
	if err != nil {
		t.Fatalf("GenerateIDToken: %v", err)
	}
	other := newTestOidc(t, publicClients())
	foreign, err := other.GenerateAccessToken(u, "cli", cliResource)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	// a token this provider signed as an access token but without a usable jti has no identity either:
	// nothing may be recorded under an empty key, and such a token is not served
	for name, payload := range map[string]string{
		"missing jti": `{"iss":"https://idp.example.com","sub":"u1","aud":"cli","exp":4102444800,"iat":1,"client_id":"cli"}`,
		"empty jti":   `{"iss":"https://idp.example.com","sub":"u1","aud":"cli","exp":4102444800,"iat":1,"jti":"","client_id":"cli"}`,
		"null jti":    `{"iss":"https://idp.example.com","sub":"u1","aud":"cli","exp":4102444800,"iat":1,"jti":null,"client_id":"cli"}`,
	} {
		jws, err := o.accessSigner.Sign([]byte(payload))
		if err != nil {
			t.Fatalf("sign %s: %v", name, err)
		}
		token, err := jws.CompactSerialize()
		if err != nil {
			t.Fatalf("serialize %s: %v", name, err)
		}
		if id, err := o.AccessTokenID(token); err == nil {
			t.Errorf("%s has an id %q", name, id)
		}
		if _, err := o.GetUserinfoFromToken(token); err == nil {
			t.Errorf("%s is served at userinfo", name)
		}
	}
	for name, token := range map[string]string{"ID token": idToken, "foreign signature": foreign, "garbage": "not.a.token"} {
		if id, err := o.AccessTokenID(token); err == nil {
			t.Errorf("%s has an id %q", name, id)
		}
	}
}

func TestGenerateAccessTokenClaims(t *testing.T) {
	o := newTestOidc(t, publicClients())
	u := user.UserInfo{ID: "u1", Username: "alice", Email: "a@example.com", Groups: []string{"admins"}}

	before := time.Now().Unix()
	token, err := o.GenerateAccessToken(u, "cli", cliResource)
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	after := time.Now().Unix()
	if got := tokenType(t, token); got != "at+jwt" {
		t.Errorf("typ = %q, want at+jwt (RFC 9068 §2.1)", got)
	}
	claims := accessTokenClaims(t, o, token)
	want := map[string]any{
		"iss":       "https://idp.example.com",
		"sub":       "u1",
		"aud":       cliResource, // a single string: the consumer verifies exactly one audience
		"client_id": "cli",
		"name":      "alice",
		"email":     "a@example.com",
		"groups":    []any{"admins"},
	}
	for name, w := range want {
		if got := claims[name]; !reflect.DeepEqual(got, w) {
			t.Errorf("%s = %#v, want %#v", name, got, w)
		}
	}
	if jti, _ := claims["jti"].(string); jti == "" {
		t.Errorf("jti = %#v, want a non-empty string", claims["jti"])
	}
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	if int64(iat) < before || int64(iat) > after {
		t.Errorf("iat = %v, want within [%d, %d] (the clock at generation)", iat, before, after)
	}
	if got := exp - iat; got < 86398 || got > 86400 {
		t.Errorf("exp-iat = %vs, want ~86400 (the 24h token TTL)", got)
	}

	plain, err := o.GenerateAccessToken(u, "cli", "")
	if err != nil {
		t.Fatalf("GenerateAccessToken without resource: %v", err)
	}
	if got := accessTokenClaims(t, o, plain)["aud"]; got != "cli" {
		t.Errorf("aud without a resource = %#v, want the client id", got)
	}
}

// TestClientTokenTTL covers the effective lifetime: a client's tokenTTL, the default without one or for
// an unknown client, and both tokens of a client sharing it.
func TestClientTokenTTL(t *testing.T) {
	o := newTestOidc(t, []Client{
		{Id: "short", RedirectUri: "http://127.0.0.1/callback", Public: true, TokenTTL: "1h"},
		{Id: "app", RedirectUri: "https://app.example.com/cb", ClientSecret: "s3cret"},
	})
	for clientID, want := range map[string]time.Duration{"short": time.Hour, "app": DefaultTokenTTL, "nobody": DefaultTokenTTL} {
		if got := o.ClientTokenTTL(clientID); got != want {
			t.Errorf("ClientTokenTTL(%q) = %v, want %v", clientID, got, want)
		}
	}

	u := user.UserInfo{ID: "u1", Username: "alice"}
	for clientID, want := range map[string]float64{"short": 3600, "app": 86400} {
		id, err := o.GenerateIDToken(u, clientID, "")
		if err != nil {
			t.Fatalf("GenerateIDToken(%s): %v", clientID, err)
		}
		access, err := o.GenerateAccessToken(u, clientID, "")
		if err != nil {
			t.Fatalf("GenerateAccessToken(%s): %v", clientID, err)
		}
		for name, token := range map[string]string{"id_token": id, "access_token": access} {
			claims := accessTokenClaims(t, o, token)
			if got := claims["exp"].(float64) - claims["iat"].(float64); got != want {
				t.Errorf("%s of %s: exp-iat = %v, want %v", name, clientID, got, want)
			}
		}
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
	raw, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal metadata: %v", err)
	}
	// omitted on purpose: the default, authorization_code and implicit, is what the server serves (OIDC Discovery §3)
	if strings.Contains(string(raw), "grant_types_supported") {
		t.Errorf("grant_types_supported must stay omitted: %s", raw)
	}
}

func TestValidResourceIndicator(t *testing.T) {
	t.Parallel()
	tests := []struct {
		s    string
		want bool
	}{
		{"https://h/p", true},
		{"urn:example:api", true},
		{"api/v1", false},
		{"https://h/p#", false},
		{"https://h/p#x", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := ValidResourceIndicator(tt.s); got != tt.want {
			t.Errorf("ValidResourceIndicator(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestParseTokenTTL(t *testing.T) {
	for _, tc := range []struct {
		s       string
		want    time.Duration
		wantErr bool
	}{
		{s: "1m", want: time.Minute}, {s: "1h", want: time.Hour}, {s: "24h", want: 24 * time.Hour},
		{s: "59s", wantErr: true}, {s: "500ms", wantErr: true}, {s: "0s", wantErr: true}, {s: "-1h", wantErr: true},
		{s: "24h1s", wantErr: true}, {s: "3600", wantErr: true},
	} {
		got, err := ParseTokenTTL(tc.s)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseTokenTTL(%q) = %v, %v; want %v, wantErr %v", tc.s, got, err, tc.want, tc.wantErr)
		}
	}
}
