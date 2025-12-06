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
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
	"github.com/go-jose/go-jose/v3"
)

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
		http.Redirect(res, req, fmt.Sprintf("%s?error=invalid_request&error_description=method not allowed", authReq.RedirectUri), http.StatusFound)
		return
	}

	fmt.Printf("%#v\n", authReq)

	err := r.oidc.ValidateAuthenticationRequest(authReq)
	if err != nil {
		http.Redirect(res, req, fmt.Sprintf("%s?error=%s", authReq.RedirectUri, err.Error()), http.StatusFound)
		return
	}

	if user == nil {
		user, err = r.getUserFromSession(req)
		if err != nil {
			if err := r.template.ExecuteTemplate(res, "login.html", nil); err != nil {
				slog.Error("failed to render login template", "error", err)
			}
			return
		}
	}

	idToken, err := r.oidc.GenerateIDToken(*user, authReq.ClientID, authReq.Nonce)
	if err != nil {
		http.Redirect(res, req, fmt.Sprintf("%s?error=server_error", authReq.RedirectUri), http.StatusFound)
		return
	}

	if authReq.ResponseType == "id_token" {
		http.Redirect(res, req, fmt.Sprintf("%s?id_token=%s", authReq.RedirectUri, idToken), http.StatusFound)
		return
	}

	code := r.store.Create(idToken)
	http.Redirect(res, req, fmt.Sprintf("%s?code=%s&state=%s", authReq.RedirectUri, code, authReq.State), http.StatusFound)
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
			http.Error(res, err.Error(), http.StatusBadRequest)
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

	fmt.Printf("%#v\n", tokenRequest)

	if err := r.oidc.ValidateTokenRequest(tokenRequest); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	id_token, err := r.store.Pop(tokenRequest.Code)
	if err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	body := struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}{
		IDToken:     id_token,
		AccessToken: "not-used", // TODO ?
		ExpiresIn:   24 * 3600,  // TODO dynamic
		TokenType:   "Bearer",
		//"scope": "photo offline_access",
		//"refresh_token": "vUOknvjU8_Oal1a7j0F5XXD3"
	}

	body_json, err := json.Marshal(body)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
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
		slog.Error("failed to validate revocation request", "error", err)
		// Per RFC 7009, we should return 200 OK even if the token is invalid
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
