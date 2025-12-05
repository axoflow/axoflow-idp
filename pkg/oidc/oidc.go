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
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/axoflow/axoflow-idp/pkg/keychain"
	"github.com/axoflow/axoflow-idp/pkg/user"
	"github.com/go-jose/go-jose/v3"
)

const (
	SigningKeyKid = "oidc-signing-key"
)

type Client struct {
	Id           string `json:"id"`
	Name         string `json:"name"`
	RedirectUri  string `json:"redirectUri"`
	ClientSecret string `json:"clientSecret"`
}

type Oidc struct {
	baseUrl  string
	clients  []Client
	keychain *keychain.Keychain
	signer   jose.Signer
}

type Config struct {
	BaseUrl           string
	Clients           []Client
	Keychain          *keychain.Keychain
	SigningKeyPath    string
	GenerateIfMissing bool
}

func New(cfg Config) (*Oidc, error) {
	var signingKey *jose.JSONWebKey

	if cfg.SigningKeyPath != "" {
		data, err := os.ReadFile(cfg.SigningKeyPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if cfg.GenerateIfMissing {
					key, err := generateSigningKey(cfg.Keychain, cfg.SigningKeyPath)
					if err != nil {
						return nil, fmt.Errorf("failed to generate signing key: %w", err)
					}
					signingKey = key
				} else {
					return nil, fmt.Errorf("signing key file not found and GenerateIfMissing is false: %w", err)
				}
			} else {
				return nil, fmt.Errorf("failed to read signing key: %w", err)
			}
		} else {
			var key jose.JSONWebKey
			if err := json.Unmarshal(data, &key); err != nil {
				return nil, fmt.Errorf("failed to unmarshal signing key: %w", err)
			}
			signingKey = &key
			slog.Info("loaded signing key", "path", cfg.SigningKeyPath)
		}
	} else {
		if cfg.GenerateIfMissing {
			key, err := generateSigningKey(cfg.Keychain, "signing-key.json")
			if err != nil {
				return nil, fmt.Errorf("failed to generate signing key: %w", err)
			}
			signingKey = key
		}
	}

	if signingKey == nil {
		return nil, errors.New("no signing key available")
	}

	cfg.Keychain.Add(*signingKey)

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       signingKey,
	}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", SigningKeyKid))
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	return &Oidc{
		baseUrl:  cfg.BaseUrl,
		clients:  cfg.Clients,
		keychain: cfg.Keychain,
		signer:   signer,
	}, nil
}

func generateSigningKey(keychain *keychain.Keychain, signingKeyPath string) (*jose.JSONWebKey, error) {
	key, err := keychain.Create(SigningKeyKid)
	if err != nil {
		return nil, fmt.Errorf("failed to create key in keychain: %w", err)
	}

	keyJSON, err := key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	slog.Info("generated new signing key", "key", string(keyJSON))

	if err := os.WriteFile(signingKeyPath, keyJSON, 0600); err != nil {
		return nil, fmt.Errorf("failed to save signing key to %s: %w", signingKeyPath, err)
	}
	slog.Info("saved signing key", "path", signingKeyPath)

	return &key, nil
}

type AuthenticationRequest struct {
	Scope        string
	ResponseType string
	ClientID     string
	RedirectUri  string
	Nonce        string
	State        string
}

type IDTokenPayload struct {
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   string   `json:"aud"`
	Expiration int64    `json:"exp"`
	IssuedAt   int64    `json:"iat"`
	Nonce      string   `json:"nonce"`
	Name       string   `json:"name"`
	Groups     []string `json:"groups"`
	Email      string   `json:"email"`
}

type authMethod string

const (
	AuthMethodClientSecretPost authMethod = "client_secret_post"
)

type OpenIDProviderMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	JWKsUri                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenURL                          string   `json:"token_endpoint"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
}

func (o *Oidc) GetOpenIDProviderMetadata() OpenIDProviderMetadata {
	return OpenIDProviderMetadata{
		Issuer:                o.baseUrl,
		AuthorizationEndpoint: o.baseUrl + "/oidc/auth",
		JWKsUri:               o.baseUrl + "/oidc/jwks",
		UserinfoEndpoint:      o.baseUrl + "/oidc/userinfo",
		TokenURL:              o.baseUrl + "/token",
		ResponseTypesSupported: []string{
			"id_token",
			"code",
		},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
		SubjectTypesSupported: []string{
			"public",
		},
		IdTokenSigningAlgValuesSupported: []string{
			string(jose.RS256),
		},
		TokenEndpointAuthMethodsSupported: []string{
			string(AuthMethodClientSecretPost),
		},
		EndSessionEndpoint: o.baseUrl + "/logout",
		RevocationEndpoint: o.baseUrl + "/revoke",
	}
}

func (o *Oidc) getClient(clientId string) (Client, bool) {
	idx := slices.IndexFunc(o.clients, func(c Client) bool {
		return c.Id == clientId
	})

	if idx == -1 {
		return Client{}, false
	}

	return o.clients[idx], true
}

func (o *Oidc) GetPublicKeys() []jose.JSONWebKey {
	jwks := o.keychain.GetAll()
	publicKeys := make([]jose.JSONWebKey, len(jwks))
	for i, jwk := range jwks {
		publicKeys[i] = jwk.Public()
	}
	return publicKeys
}

func (o *Oidc) ValidateAuthenticationRequest(req AuthenticationRequest) error {
	if !strings.Contains(req.Scope, "openid") {
		return errors.New("invalid_scope")
	}

	if req.ResponseType != "id_token" && req.ResponseType != "code" {
		return errors.New("unsupported_response_type")
	}

	client, ok := o.getClient(req.ClientID)
	if !ok {
		return errors.New("access_denied")
	}

	if !strings.HasPrefix(req.RedirectUri, client.RedirectUri) {
		return errors.New("invalid_redirect_uri")
	}

	return nil
}

func (o *Oidc) GenerateIDToken(user user.UserInfo, clientID string, nonce string) (string, error) {
	payload, err := json.Marshal(IDTokenPayload{
		Issuer:     o.baseUrl,
		Subject:    user.ID.String(),
		Audience:   clientID,
		Expiration: time.Now().Add(time.Hour * 24).Unix(),
		IssuedAt:   time.Now().Unix(),
		Nonce:      nonce,
		Name:       user.Username,
		Groups:     user.Groups,
		Email:      user.Email,
	})
	if err != nil {
		return "", err
	}

	jws, err := o.signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return jws.CompactSerialize()
}

type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	RedirectUri  string
	Code         string
}

type RevocationRequest struct {
	Token        string
	ClientID     string
	ClientSecret string
}

type UserinfoResponse struct {
	Subject string   `json:"sub"`
	Name    string   `json:"name,omitempty"`
	Email   string   `json:"email,omitempty"`
	Groups  []string `json:"groups,omitempty"`
}

func (o *Oidc) ValidateTokenRequest(req TokenRequest) error {
	if req.GrantType != "authorization_code" {
		return errors.New("unsupported grant type")
	}

	client, ok := o.getClient(req.ClientID)
	if !ok {
		return errors.New("access_denied")
	}

	if client.ClientSecret != req.ClientSecret {
		return errors.New("bad client secret")
	}

	if client.RedirectUri != req.RedirectUri {
		return errors.New("invalid_redirect_uri")
	}

	return nil
}

func (o *Oidc) ValidateRevocationRequest(req RevocationRequest) error {
	if req.Token == "" {
		return errors.New("token is required")
	}

	client, ok := o.getClient(req.ClientID)
	if !ok {
		return errors.New("invalid client")
	}

	if client.ClientSecret != req.ClientSecret {
		return errors.New("invalid client credentials")
	}

	return nil
}

func (o *Oidc) GetUserinfoFromToken(tokenString string) (*UserinfoResponse, error) {
	token, err := jose.ParseSigned(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	payload, err := token.Verify(o.keychain.GetAll()[0].Public().Key)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	var claims IDTokenPayload
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	if time.Now().Unix() > claims.Expiration {
		return nil, errors.New("token expired")
	}

	return &UserinfoResponse{
		Subject: claims.Subject,
		Name:    claims.Name,
		Email:   claims.Email,
		Groups:  claims.Groups,
	}, nil
}
