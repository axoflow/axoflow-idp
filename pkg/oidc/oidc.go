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
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
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

	defaultIDTokenTTL = 24 * time.Hour
)

type Client struct {
	Id           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectUri  string   `json:"redirectUri"`
	RedirectUris []string `json:"redirectUris,omitempty"`
	ClientSecret string   `json:"clientSecret"`
}

// registeredRedirectUris returns every redirect URI registered for the client:
// the singular redirectUri (if set) plus any in the redirectUris list.
func (c Client) registeredRedirectUris() []string {
	uris := make([]string, 0, len(c.RedirectUris)+1)
	if c.RedirectUri != "" {
		uris = append(uris, c.RedirectUri)
	}
	return append(uris, c.RedirectUris...)
}

// allowsRedirect reports whether uri exactly matches one of the client's
// registered redirect URIs. Matching is an exact string comparison per
// RFC 6749 §3.1.2.3 / RFC 9700 §4.1.1 — no prefix or pattern matching.
func (c Client) allowsRedirect(uri string) bool {
	return slices.Contains(c.registeredRedirectUris(), uri)
}

type Oidc struct {
	baseUrl    string
	clients    []Client
	keychain   *keychain.Keychain
	signer     jose.Signer
	idTokenTTL time.Duration
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
		baseUrl:    cfg.BaseUrl,
		clients:    cfg.Clients,
		keychain:   cfg.Keychain,
		signer:     signer,
		idTokenTTL: defaultIDTokenTTL,
	}, nil
}

func (o *Oidc) IDTokenTTL() time.Duration {
	return o.idTokenTTL
}

func generateSigningKey(keychain *keychain.Keychain, signingKeyPath string) (*jose.JSONWebKey, error) {
	slog.Info("generating new signing key")
	key, err := keychain.Create(SigningKeyKid)
	if err != nil {
		return nil, fmt.Errorf("failed to create key in keychain: %w", err)
	}

	keyJSON, err := key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}
	slog.Info("generated new signing key", "kid", key.KeyID)

	if err := os.WriteFile(signingKeyPath, keyJSON, 0600); err != nil {
		return nil, fmt.Errorf("failed to save signing key to %s: %w", signingKeyPath, err)
	}
	slog.Info("saved signing key", "path", signingKeyPath)

	return &key, nil
}

type ClientInfo struct {
	Name string
	URL  string
}

func (o *Oidc) FirstClient() *ClientInfo {
	if len(o.clients) == 0 {
		return nil
	}
	uris := o.clients[0].registeredRedirectUris()
	if len(uris) == 0 {
		return nil
	}
	u, err := url.Parse(uris[0])
	if err != nil || u.Host == "" {
		return nil
	}
	return &ClientInfo{
		Name: o.clients[0].Name,
		URL:  u.Scheme + "://" + u.Host,
	}
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
	Nonce      string   `json:"nonce,omitempty"`
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

// ValidateRedirect validates the client and its redirect_uri. It must be
// checked before redirecting anything back to redirect_uri, so that an
// unregistered URI is rejected in place rather than turned into an open
// redirect (RFC 6749 §4.1.2.1).
func (o *Oidc) ValidateRedirect(clientID, redirectUri string) error {
	client, ok := o.getClient(clientID)
	if !ok {
		return errors.New("access_denied")
	}

	if !client.allowsRedirect(redirectUri) {
		return errors.New("invalid_redirect_uri")
	}

	return nil
}

func (o *Oidc) ValidateAuthenticationRequest(req AuthenticationRequest) error {
	if !slices.Contains(strings.Fields(req.Scope), "openid") {
		return errors.New("invalid_scope")
	}

	if req.ResponseType != "id_token" && req.ResponseType != "code" {
		return errors.New("unsupported_response_type")
	}

	return o.ValidateRedirect(req.ClientID, req.RedirectUri)
}

func (o *Oidc) GenerateIDToken(user user.UserInfo, clientID string, nonce string) (string, error) {
	payload, err := json.Marshal(IDTokenPayload{
		Issuer:     o.baseUrl,
		Subject:    user.ID,
		Audience:   clientID,
		Expiration: time.Now().Add(o.idTokenTTL).Unix(),
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

// Token-endpoint error codes per RFC 6749 §5.2; the string is the code sent to the client.
var (
	ErrInvalidRequest       = errors.New("invalid_request")
	ErrInvalidClient        = errors.New("invalid_client")
	ErrInvalidGrant         = errors.New("invalid_grant")
	ErrUnsupportedGrantType = errors.New("unsupported_grant_type")
)

func (o *Oidc) ValidateTokenRequest(req TokenRequest) error {
	if req.GrantType != "authorization_code" {
		return ErrUnsupportedGrantType
	}

	client, ok := o.getClient(req.ClientID)
	if !ok {
		return ErrInvalidClient
	}

	if subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(req.ClientSecret)) != 1 {
		return ErrInvalidClient
	}

	if !client.allowsRedirect(req.RedirectUri) {
		return ErrInvalidGrant
	}

	return nil
}

// ValidateRevocationRequest authenticates the client before inspecting the
// token: RFC 7009 §2.1 makes a failed client authentication a 401, while an
// invalid token is still a 200.
func (o *Oidc) ValidateRevocationRequest(req RevocationRequest) error {
	client, ok := o.getClient(req.ClientID)
	if !ok {
		return ErrInvalidClient
	}

	if subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(req.ClientSecret)) != 1 {
		return ErrInvalidClient
	}

	if req.Token == "" {
		return ErrInvalidRequest
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
