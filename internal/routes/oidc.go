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

package routes

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
	"github.com/go-jose/go-jose/v3"
)

// writeTokenError emits an RFC 6749 §5.2 JSON error; err must be an oidc.Err* sentinel.
func writeTokenError(res http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, oidc.ErrInvalidClient) {
		status = http.StatusUnauthorized
	}

	res.Header().Set("Content-Type", "application/json")
	res.WriteHeader(status)
	if encErr := json.NewEncoder(res).Encode(struct {
		Error string `json:"error"`
	}{Error: err.Error()}); encErr != nil {
		slog.Error("failed to write token error response", "error", encErr)
	}
}

func (r *Routes) WellKnownOpenIdConfiguration(res http.ResponseWriter, _ *http.Request) {
	json, err := json.Marshal(r.oidc.GetOpenIDProviderMetadata())
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	if _, err := res.Write(json); err != nil {
		slog.Error("failed to write well-known response", "error", err)
	}
}

func authRequest(getter interface{ Get(string) string }) oidc.AuthenticationRequest {
	return oidc.AuthenticationRequest{
		Scope:        getter.Get("scope"),
		ResponseType: getter.Get("response_type"),
		ClientID:     getter.Get("client_id"),
		RedirectUri:  getter.Get("redirect_uri"),
		Nonce:        getter.Get("nonce"),
		State:        getter.Get("state"),
	}
}

// authRedirect sends a 302 back to redirectUri with params merged into its
// query string, all properly percent-encoded. It must only be called with a
// redirect_uri that has already passed ValidateRedirect.
func authRedirect(res http.ResponseWriter, req *http.Request, redirectUri string, params url.Values) {
	u, err := url.Parse(redirectUri)
	if err != nil {
		http.Error(res, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := u.Query()
	for key, values := range params {
		for _, v := range values {
			q.Set(key, v)
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(res, req, u.String(), http.StatusFound)
}

// authError redirects an authorization error back to the client, echoing the
// request's state when present (RFC 6749 §4.1.2.1).
func authError(res http.ResponseWriter, req *http.Request, authReq oidc.AuthenticationRequest, errCode string) {
	params := url.Values{"error": {errCode}}
	if authReq.State != "" {
		params.Set("state", authReq.State)
	}
	authRedirect(res, req, authReq.RedirectUri, params)
}

func (r *Routes) OidcAuth(res http.ResponseWriter, req *http.Request) {
	var user *user.UserInfo
	var authReq oidc.AuthenticationRequest
	switch req.Method {
	case http.MethodGet:
		authReq = authRequest(req.URL.Query())
	case http.MethodPost:
		if err := req.ParseForm(); err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Form.Has("username") {
			// GET -> login form
			if user = r.login(res, req); user == nil {
				return // failure, handled in r.login
			}
			authReq = authRequest(req.URL.Query())
		} else {
			// POST based auth flow
			authReq = authRequest(req.Form)
		}
	default:
		res.Header().Set("Allow", "GET, POST")
		http.Error(res, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate the client and redirect_uri before redirecting anything back to
	// it; an unregistered URI is rejected in place rather than turned into an
	// open redirect (RFC 6749 §4.1.2.1).
	if err := r.oidc.ValidateRedirect(authReq.ClientID, authReq.RedirectUri); err != nil {
		r.renderError(res, req, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}

	if err := r.oidc.ValidateAuthenticationRequest(authReq); err != nil {
		authError(res, req, authReq, err.Error())
		return
	}

	if user == nil {
		var err error
		user, err = r.getUserFromSession(req)
		if err != nil {
			// The OIDC request is dropped; the relying party restarts it once
			// the first account exists.
			if r.needsBootstrap() {
				http.Redirect(res, req, r.url("/register"), http.StatusFound)
				return
			}
			if err := r.template.ExecuteTemplate(res, "login.html", nil); err != nil {
				slog.Error("failed to render login template", "error", err)
			}
			return
		}
	}

	idToken, err := r.oidc.GenerateIDToken(*user, authReq.ClientID, authReq.Nonce)
	if err != nil {
		authError(res, req, authReq, "server_error")
		return
	}

	if authReq.ResponseType == "id_token" {
		params := url.Values{"id_token": {idToken}}
		if authReq.State != "" {
			params.Set("state", authReq.State)
		}
		authRedirect(res, req, authReq.RedirectUri, params)
		return
	}

	code := r.store.Create(idToken)
	params := url.Values{"code": {code}}
	if authReq.State != "" {
		params.Set("state", authReq.State)
	}
	authRedirect(res, req, authReq.RedirectUri, params)
}

func (r *Routes) OidcJwks(res http.ResponseWriter, _ *http.Request) {
	keys := r.oidc.GetPublicKeys()
	jwks := struct {
		Keys []jose.JSONWebKey `json:"keys"`
	}{Keys: keys}

	json, err := json.Marshal(jwks)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	if _, err := res.Write(json); err != nil {
		slog.Error("failed to write jwks response", "error", err)
	}
}

func (r *Routes) OidcToken(res http.ResponseWriter, req *http.Request) {
	var tokenRequest oidc.TokenRequest
	switch req.Method {
	case http.MethodPost:
		if err := req.ParseForm(); err != nil {
			writeTokenError(res, oidc.ErrInvalidRequest)
			return
		}

		tokenRequest = oidc.TokenRequest{
			GrantType:    req.Form.Get("grant_type"),
			ClientID:     req.Form.Get("client_id"),
			ClientSecret: req.Form.Get("client_secret"),
			RedirectUri:  req.Form.Get("redirect_uri"),
			Code:         req.Form.Get("code"),
		}
	default:
		res.Header().Add("allow", http.MethodPost)
		http.Error(res, "unsupported method (must be POST)", http.StatusMethodNotAllowed)
		return
	}

	if err := r.oidc.ValidateTokenRequest(tokenRequest); err != nil {
		writeTokenError(res, err)
		return
	}

	id_token, err := r.store.Pop(tokenRequest.Code)
	if err != nil {
		writeTokenError(res, oidc.ErrInvalidGrant)
		return
	}

	body := struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}{
		IDToken:     id_token,
		AccessToken: id_token,
		ExpiresIn:   int(r.oidc.IDTokenTTL().Seconds()),
		TokenType:   "Bearer",
	}

	body_json, err := json.Marshal(body)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	res.Header().Set("Cache-Control", "no-store")
	res.Header().Set("Pragma", "no-cache")
	if _, err := res.Write(body_json); err != nil {
		slog.Error("failed to write token response", "error", err)
	}
}

func (r *Routes) OidcRevoke(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := req.ParseForm(); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	revocationRequest := oidc.RevocationRequest{
		Token:        req.Form.Get("token"),
		ClientID:     req.Form.Get("client_id"),
		ClientSecret: req.Form.Get("client_secret"),
	}

	if err := r.oidc.ValidateRevocationRequest(revocationRequest); err != nil {
		// Per RFC 7009 an invalid/unknown token still returns 200 OK, but a
		// failed client authentication is a 401 invalid_client.
		if errors.Is(err, oidc.ErrInvalidClient) {
			writeTokenError(res, err)
			return
		}
		res.WriteHeader(http.StatusOK)
		return
	}

	r.tokenStore.Revoke(revocationRequest.Token)

	res.WriteHeader(http.StatusOK)
}

func (r *Routes) OidcUserinfo(res http.ResponseWriter, req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(res, "missing authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		http.Error(res, "invalid authorization header format", http.StatusUnauthorized)
		return
	}

	token := parts[1]

	if r.tokenStore.IsRevoked(token) {
		http.Error(res, "token has been revoked", http.StatusUnauthorized)
		return
	}

	userinfo, err := r.oidc.GetUserinfoFromToken(token)
	if err != nil {
		http.Error(res, "invalid token", http.StatusUnauthorized)
		return
	}

	userinfoJSON, err := json.Marshal(userinfo)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	if _, err := res.Write(userinfoJSON); err != nil {
		slog.Error("failed to write userinfo response", "error", err)
	}
}
