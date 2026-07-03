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
	"path/filepath"
	"testing"

	"github.com/axoflow/axoflow-idp/pkg/keychain"
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
	bad.ClientSecret = "wrong"
	if err := o.ValidateTokenRequest(bad); err == nil {
		t.Error("bad client secret should be rejected")
	}
}

func TestValidateTokenRequest(t *testing.T) {
	o := newTestOidc(t, []Client{{
		Id:           "app",
		RedirectUri:  "https://app.example.com/cb",
		ClientSecret: "s3cret",
	}})
	tests := []struct {
		name    string
		req     TokenRequest
		wantErr bool
	}{
		{"valid", TokenRequest{GrantType: "authorization_code", ClientID: "app", ClientSecret: "s3cret", RedirectUri: "https://app.example.com/cb", Code: "x"}, false},
		{"unsupported grant", TokenRequest{GrantType: "refresh_token", ClientID: "app", ClientSecret: "s3cret", RedirectUri: "https://app.example.com/cb"}, true},
		{"unknown client", TokenRequest{GrantType: "authorization_code", ClientID: "nope", ClientSecret: "s3cret", RedirectUri: "https://app.example.com/cb"}, true},
		{"wrong secret", TokenRequest{GrantType: "authorization_code", ClientID: "app", ClientSecret: "totally-wrong", RedirectUri: "https://app.example.com/cb"}, true},
		{"equal-length wrong secret", TokenRequest{GrantType: "authorization_code", ClientID: "app", ClientSecret: "s3crXt", RedirectUri: "https://app.example.com/cb"}, true},
		{"wrong redirect", TokenRequest{GrantType: "authorization_code", ClientID: "app", ClientSecret: "s3cret", RedirectUri: "https://evil.example.com/cb"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := o.ValidateTokenRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTokenRequest(%+v) error = %v, wantErr %v", tt.req, err, tt.wantErr)
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
		name    string
		req     RevocationRequest
		wantErr bool
	}{
		{"valid", RevocationRequest{Token: "t", ClientID: "app", ClientSecret: "s3cret"}, false},
		{"empty token", RevocationRequest{Token: "", ClientID: "app", ClientSecret: "s3cret"}, true},
		{"unknown client", RevocationRequest{Token: "t", ClientID: "nope", ClientSecret: "s3cret"}, true},
		{"wrong secret", RevocationRequest{Token: "t", ClientID: "app", ClientSecret: "nope"}, true},
		{"equal-length wrong secret", RevocationRequest{Token: "t", ClientID: "app", ClientSecret: "s3crXt"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := o.ValidateRevocationRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRevocationRequest(%+v) error = %v, wantErr %v", tt.req, err, tt.wantErr)
			}
		})
	}
}
