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
	"crypto/rand"
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
	// Public clients (RFC 8252) send no secret and must use PKCE.
	Public bool `json:"public,omitempty"`
	// Resources are the RFC 8707 resource indicators allowed; none means no resource may be sent.
	Resources []string `json:"resources,omitempty"`
	// TokenTTL is the lifetime of this client's access tokens as a Go duration such as "720h";
	// empty means the default. ID tokens keep the default: a long-lived access token for an
	// automation account should not come with a long-lived identity assertion.
	TokenTTL string `json:"tokenTTL,omitempty"`
}

// tokenTTL parses TokenTTL; zero means the default applies.
func (c Client) tokenTTL() (time.Duration, error) {
	if c.TokenTTL == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(c.TokenTTL)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("client %s: tokenTTL must be a positive Go duration such as \"720h\", got %q", c.Id, c.TokenTTL)
	}
	return d, nil
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

// allowsRedirect matches exactly (RFC 6749 §3.1.2.3, RFC 9700 §4.1.1).
// A registered loopback redirect matches on any port (RFC 8252 §7.3).
func (c Client) allowsRedirect(uri string) bool {
	registered := c.registeredRedirectUris()
	if slices.Contains(registered, uri) {
		return true
	}
	return slices.ContainsFunc(registered, func(r string) bool { return loopbackRedirectMatches(r, uri) })
}

// Only the port may differ; even an empty "?" or "#" fails the match.
func loopbackRedirectMatches(registered, uri string) bool {
	if strings.ContainsAny(registered, "?#") || strings.ContainsAny(uri, "?#") {
		return false
	}
	r, err := url.Parse(registered)
	if err != nil || r.Scheme != "http" || !isLoopbackHost(r.Hostname()) || r.User != nil {
		return false
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" || u.User != nil {
		return false
	}
	return u.Hostname() == r.Hostname() && u.EscapedPath() == r.EscapedPath()
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// ClientName returns the client's display name, its id when unnamed, "" when unknown.
func (o *Oidc) ClientName(clientID string) string {
	client, ok := o.getClient(clientID)
	if !ok {
		return ""
	}
	if client.Name == "" {
		return client.Id
	}
	return client.Name
}

type Oidc struct {
	baseUrl      string
	clients      []Client
	keychain     *keychain.Keychain
	signer       jose.Signer
	accessSigner jose.Signer
	idTokenTTL   time.Duration
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

	for _, c := range cfg.Clients {
		if _, err := c.tokenTTL(); err != nil {
			return nil, err
		}
	}

	cfg.Keychain.Add(*signingKey)

	key := jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}
	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", SigningKeyKid))
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}
	// RFC 9068 section 2.1: access tokens carry typ "at+jwt", so they cannot pass as ID tokens
	accessSigner, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", SigningKeyKid))
	if err != nil {
		return nil, fmt.Errorf("failed to create access token signer: %w", err)
	}

	return &Oidc{
		baseUrl:      cfg.BaseUrl,
		clients:      cfg.Clients,
		keychain:     cfg.Keychain,
		signer:       signer,
		accessSigner: accessSigner,
		idTokenTTL:   defaultIDTokenTTL,
	}, nil
}

func (o *Oidc) IDTokenTTL() time.Duration {
	return o.idTokenTTL
}

// AccessTokenTTL is the lifetime of the access tokens issued to clientID: its tokenTTL when
// set, the ID token lifetime otherwise.
func (o *Oidc) AccessTokenTTL(clientID string) time.Duration {
	if c, ok := o.getClient(clientID); ok {
		if d, err := c.tokenTTL(); err == nil && d > 0 {
			return d
		}
	}
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
	// CodeChallenge and CodeChallengeMethod are PKCE (RFC 7636); only S256 is accepted.
	CodeChallenge       string
	CodeChallengeMethod string
	// Resource (RFC 8707) becomes the access token's audience.
	Resource string
}

// WantsIDToken reports whether the openid scope was requested.
func (r AuthenticationRequest) WantsIDToken() bool {
	return slices.Contains(strings.Fields(r.Scope), "openid")
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

// AccessTokenPayload is the RFC 9068 access token, with the ID token's identity claims.
type AccessTokenPayload struct {
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   string   `json:"aud"`
	Expiration int64    `json:"exp"`
	IssuedAt   int64    `json:"iat"`
	JWTID      string   `json:"jti"`
	ClientID   string   `json:"client_id"`
	Name       string   `json:"name"`
	Groups     []string `json:"groups"`
	Email      string   `json:"email"`
}

type authMethod string

const (
	AuthMethodClientSecretPost authMethod = "client_secret_post"
	AuthMethodNone             authMethod = "none"

	CodeChallengeMethodS256 = "S256"
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
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
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
			string(AuthMethodNone),
		},
		GrantTypesSupported:           []string{"authorization_code"},
		CodeChallengeMethodsSupported: []string{CodeChallengeMethodS256},
		EndSessionEndpoint:            o.baseUrl + "/logout",
		RevocationEndpoint:            o.baseUrl + "/revoke",
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

// ValidateAuthenticationRequest accepts PKCE S256 only (RFC 7636 §4.6); openid is optional for plain OAuth.
func (o *Oidc) ValidateAuthenticationRequest(req AuthenticationRequest) error {
	client, ok := o.getClient(req.ClientID)
	if !ok {
		return errors.New("access_denied")
	}

	if req.ResponseType != "id_token" && req.ResponseType != "code" {
		return errors.New("unsupported_response_type")
	}
	// a public client proves PKCE at the token endpoint, so only the code flow works
	if client.Public && req.ResponseType != "code" {
		return errors.New("unsupported_response_type")
	}
	if req.ResponseType == "id_token" && !req.WantsIDToken() {
		return errors.New("invalid_scope")
	}

	if req.CodeChallenge != "" || req.CodeChallengeMethod != "" {
		if req.CodeChallengeMethod != CodeChallengeMethodS256 || !validCodeChallenge(req.CodeChallenge) {
			return errors.New("invalid_request")
		}
	} else if client.Public {
		return errors.New("invalid_request")
	}

	if req.Resource != "" {
		u, err := url.Parse(req.Resource)
		if err != nil || !u.IsAbs() || strings.Contains(req.Resource, "#") {
			return errors.New("invalid_target")
		}
		if !slices.Contains(client.Resources, req.Resource) {
			return errors.New("invalid_target")
		}
	}

	return o.ValidateRedirect(req.ClientID, req.RedirectUri)
}

func (o *Oidc) GenerateIDToken(user user.UserInfo, clientID string, nonce string) (string, error) {
	return sign(o.signer, IDTokenPayload{
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
}

func sign(signer jose.Signer, claims any) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return jws.CompactSerialize()
}

// GenerateAccessToken signs an access token for resource, or for clientID when resource is "".
func (o *Oidc) GenerateAccessToken(user user.UserInfo, clientID string, resource string) (string, error) {
	audience := resource
	if audience == "" {
		audience = clientID
	}
	return sign(o.accessSigner, AccessTokenPayload{
		Issuer:     o.baseUrl,
		Subject:    user.ID,
		Audience:   audience,
		Expiration: time.Now().Add(o.AccessTokenTTL(clientID)).Unix(),
		IssuedAt:   time.Now().Unix(),
		JWTID:      rand.Text(),
		ClientID:   clientID,
		Name:       user.Username,
		Groups:     user.Groups,
		Email:      user.Email,
	})
}

type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	RedirectUri  string
	Code         string
	CodeVerifier string
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

// ValidateTokenRequest authenticates the client; a public client has no secret, so it must send a code_verifier.
func (o *Oidc) ValidateTokenRequest(req TokenRequest) error {
	if req.GrantType != "authorization_code" {
		return ErrUnsupportedGrantType
	}

	client, ok := o.getClient(req.ClientID)
	if !ok {
		return ErrInvalidClient
	}

	if client.Public {
		if req.ClientSecret != "" || req.CodeVerifier == "" {
			return ErrInvalidRequest
		}
	} else if subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(req.ClientSecret)) != 1 {
		return ErrInvalidClient
	}

	if !client.allowsRedirect(req.RedirectUri) {
		return ErrInvalidGrant
	}

	return nil
}

// VerifyCodeExchange requires a verifier exactly when the code was issued with a challenge (RFC 7636 §4.6).
func VerifyCodeExchange(codeChallenge, codeVerifier string) error {
	switch {
	case codeChallenge == "" && codeVerifier == "":
		return nil
	case codeChallenge == "" || codeVerifier == "":
		return ErrInvalidGrant
	case !VerifyPKCE(codeChallenge, codeVerifier):
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
