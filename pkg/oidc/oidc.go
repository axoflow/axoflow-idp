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

	// DefaultTokenTTL is the lifetime of both tokens unless the client sets a shorter tokenTTL. The
	// revocation list keeps an entry this long, so no client may exceed it.
	DefaultTokenTTL = 24 * time.Hour
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
	// TokenTTL is the lifetime of this client's ID and access tokens as a Go duration string such as "1h";
	// empty means DefaultTokenTTL. A string, not a time.Duration: a JSON number would decode as nanoseconds.
	TokenTTL string `json:"tokenTTL,omitempty"`
}

// ParseTokenTTL parses a client's tokenTTL: a positive Go duration of at most DefaultTokenTTL.
func ParseTokenTTL(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 || d > DefaultTokenTTL {
		return 0, fmt.Errorf("%s is not within (0, %s]", d, DefaultTokenTTL)
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

// allowsRedirect reports whether uri exactly matches one of the client's
// registered redirect URIs. Matching is an exact string comparison per
// RFC 6749 §3.1.2.3 / RFC 9700 §4.1.1 — no prefix or pattern matching.
func (c Client) allowsRedirect(uri string) bool {
	return slices.Contains(c.registeredRedirectUris(), uri)
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

	cfg.Keychain.Add(*signingKey)

	key := jose.SigningKey{Algorithm: jose.RS256, Key: signingKey}
	signer, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", SigningKeyKid))
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}
	// RFC 9068 §2.1: access tokens carry typ "at+jwt", so a validator that enforces the profile can tell them from ID tokens.
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
		idTokenTTL:   DefaultTokenTTL,
	}, nil
}

// IDTokenTTL is the provider's default token lifetime, the longest any client gets.
func (o *Oidc) IDTokenTTL() time.Duration {
	return o.idTokenTTL
}

// ClientTokenTTL is the lifetime of the tokens issued to clientID: its tokenTTL when set, the provider
// default otherwise, also for an unknown client. Validation refused an unparsable tokenTTL at start.
func (o *Oidc) ClientTokenTTL(clientID string) time.Duration {
	if c, ok := o.getClient(clientID); ok && c.TokenTTL != "" {
		if d, err := ParseTokenTTL(c.TokenTTL); err == nil {
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
	// Resources holds every RFC 8707 resource parameter sent; at most one is accepted.
	Resources []string
}

// Resource returns the single requested resource, which becomes the access token's audience, or "".
func (r AuthenticationRequest) Resource() string {
	if len(r.Resources) != 1 {
		return ""
	}
	return r.Resources[0]
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

// ValidateAuthenticationRequest accepts PKCE S256 only (RFC 7636 §4.6) and at most one registered resource.
func (o *Oidc) ValidateAuthenticationRequest(req AuthenticationRequest) error {
	if !slices.Contains(strings.Fields(req.Scope), "openid") {
		return errors.New("invalid_scope")
	}

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

	if req.CodeChallenge != "" || req.CodeChallengeMethod != "" {
		if req.CodeChallengeMethod != CodeChallengeMethodS256 || !validCodeChallenge(req.CodeChallenge) {
			return errors.New("invalid_request")
		}
	} else if client.Public {
		return errors.New("invalid_request")
	}

	// a token is bound to one audience, so this server accepts at most one resource
	if len(req.Resources) > 1 {
		return ErrInvalidTarget
	}
	if resource := req.Resource(); resource != "" {
		if !ValidResourceIndicator(resource) || !slices.Contains(client.Resources, resource) {
			return ErrInvalidTarget
		}
	}

	return o.ValidateRedirect(req.ClientID, req.RedirectUri)
}

// ValidResourceIndicator reports whether s has a scheme and no fragment, which is what RFC 8707 §2 asks of a
// resource indicator; the exact match against the registered list is the gate, not this syntax check.
func ValidResourceIndicator(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.IsAbs() && !strings.Contains(s, "#")
}

func (o *Oidc) GenerateIDToken(user user.UserInfo, clientID string, nonce string) (string, error) {
	now := time.Now()
	return sign(o.signer, IDTokenPayload{
		Issuer:     o.baseUrl,
		Subject:    user.ID,
		Audience:   clientID,
		Expiration: now.Add(o.ClientTokenTTL(clientID)).Unix(),
		IssuedAt:   now.Unix(),
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
	now := time.Now()
	return sign(o.accessSigner, AccessTokenPayload{
		Issuer:     o.baseUrl,
		Subject:    user.ID,
		Audience:   audience,
		Expiration: now.Add(o.ClientTokenTTL(clientID)).Unix(),
		IssuedAt:   now.Unix(),
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
	// Resources are the RFC 8707 resource values of the request; an empty value counts as omitted.
	Resources []string
}

// Resource returns the one non-empty resource of the request, or "" when none was sent.
func (r TokenRequest) Resource() string {
	resource := ""
	for _, candidate := range r.Resources {
		if candidate != "" {
			resource = candidate
		}
	}
	return resource
}

func (r TokenRequest) resourceCount() int {
	count := 0
	for _, candidate := range r.Resources {
		if candidate != "" {
			count++
		}
	}
	return count
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
	// ErrInvalidTarget is RFC 8707 §2's code for a resource the request may not have.
	ErrInvalidTarget = errors.New("invalid_target")
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

	// this server accepts at most one non-empty resource per token request (a grant carries one); the match
	// against the grant needs the code
	if req.resourceCount() > 1 {
		return ErrInvalidTarget
	}

	return nil
}

// VerifyTokenResource checks a resource named at /token against the one the code was issued for:
// it must be that resource, or absent (a local policy within RFC 8707 §2.2). Issuance never changes at redemption.
func VerifyTokenResource(req TokenRequest, granted string) error {
	if resource := req.Resource(); resource != "" && resource != granted {
		return ErrInvalidTarget
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

	// a public client has no credential to revoke with; its tokens expire instead
	if client.Public {
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

// AccessTokenID returns the jti of a token this provider signed as an access token (typ at+jwt), expired
// or not. It is the identity a revocation is recorded under: the token's bytes have more than one valid
// spelling (whitespace, JSON serialization, unused padding bits), the id has one.
func (o *Oidc) AccessTokenID(tokenString string) (string, error) {
	token, err := jose.ParseSigned(tokenString)
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}
	if len(token.Signatures) != 1 || token.Signatures[0].Header.ExtraHeaders[jose.HeaderType] != "at+jwt" {
		return "", errors.New("not an access token")
	}
	payload, err := token.Verify(o.keychain.GetAll()[0].Public().Key)
	if err != nil {
		return "", fmt.Errorf("failed to verify token: %w", err)
	}
	var claims AccessTokenPayload
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	if claims.JWTID == "" {
		return "", errors.New("access token without jti")
	}
	return claims.JWTID, nil
}

// GetUserinfoFromToken serves /oidc/userinfo from an access token. Only a token with the typ at+jwt
// header is accepted: the ID token of the same response is a separate credential, and a revocation of the
// access token must not leave it usable here.
func (o *Oidc) GetUserinfoFromToken(tokenString string) (*UserinfoResponse, error) {
	token, err := jose.ParseSigned(tokenString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	if len(token.Signatures) != 1 || token.Signatures[0].Header.ExtraHeaders[jose.HeaderType] != "at+jwt" {
		return nil, errors.New("not an access token")
	}

	payload, err := token.Verify(o.keychain.GetAll()[0].Public().Key)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	var claims AccessTokenPayload
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	if claims.JWTID == "" {
		return nil, errors.New("access token without jti") // no identity to revoke it under
	}

	// RFC 7519 §4.1.4: a token is not accepted on or after exp. main.go keeps a revocation for the token lifetime
	// from the revoke, so this is also what keeps a revoked token from outliving its record.
	if time.Now().Unix() >= claims.Expiration {
		return nil, errors.New("token expired")
	}

	return &UserinfoResponse{
		Subject: claims.Subject,
		Name:    claims.Name,
		Email:   claims.Email,
		Groups:  claims.Groups,
	}, nil
}
