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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/axoflow/axoflow-idp/internal/codestore"
	"github.com/axoflow/axoflow-idp/internal/resettoken"
	"github.com/axoflow/axoflow-idp/internal/routes"
	"github.com/axoflow/axoflow-idp/internal/session"
	"github.com/axoflow/axoflow-idp/internal/tokenstore"
	"github.com/axoflow/axoflow-idp/pkg/keychain"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

// passwordResetLinkTTL is how long an admin-generated password-reset link
// stays valid. Kept short to limit the window of a leaked link.
const passwordResetLinkTTL = time.Hour

type config struct {
	BaseUrl    string             `json:"baseUrl"`
	Clients    []oidc.Client      `json:"clients"`
	Users      *user.Config       `json:"users,omitempty"`
	Token      *tokenstore.Config `json:"token,omitempty"`
	SigningKey struct {
		FilePath          string `json:"filePath,omitempty"`
		GenerateIfMissing bool   `json:"generateIfMissing,omitempty"`
	} `json:"signingKey"`
}

func LoadConfig() (cfg config, err error) {
	configPath := os.Getenv("CONFIG")
	if configPath == "" {
		configPath = "config.json"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	cfg.BaseUrl = strings.TrimRight(cfg.BaseUrl, "/")

	if cfg.Users == nil {
		cfg.Users = &user.Config{}
	}

	if cfg.Token == nil {
		cfg.Token = &tokenstore.Config{
			TTL: 24 * time.Hour,
		}
	}

	return
}

func (c *config) Validate() error {
	if c.BaseUrl == "" {
		return errors.New("baseUrl is required")
	}

	parsedUrl, err := url.Parse(c.BaseUrl)
	if err != nil {
		return fmt.Errorf("baseUrl is invalid: %w", err)
	}

	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return errors.New("baseUrl must start with http:// or https://")
	}

	if parsedUrl.RawQuery != "" || parsedUrl.Fragment != "" {
		return errors.New("baseUrl must not contain a query or fragment")
	}

	// The path becomes a ServeMux pattern prefix and is echoed into every
	// redirect, cookie and link. An unclean path ("//idp", "/idp/../x") would
	// register patterns the path-cleaning mux can never match — the server
	// would start and then 404 every request — and "{" or "}" is ServeMux
	// wildcard syntax that panics at registration. A percent-encoded path
	// would decode here and re-emit unencoded in headers. Reject them all.
	if p := parsedUrl.Path; p != "" {
		if p != parsedUrl.EscapedPath() || p != path.Clean(p) || strings.ContainsAny(p, "{}") {
			return errors.New("baseUrl path must be a clean, unescaped path such as /idp")
		}
	}

	if len(c.Clients) == 0 {
		return errors.New("at least one client is required")
	}

	for i, client := range c.Clients {
		if client.Id == "" {
			return fmt.Errorf("client %d: id is required", i)
		}
		if client.RedirectUri == "" {
			return fmt.Errorf("client %d (%s): redirectUri is required", i, client.Id)
		}
		if !strings.HasPrefix(client.RedirectUri, "http://") && !strings.HasPrefix(client.RedirectUri, "https://") {
			return fmt.Errorf("client %d (%s): redirectUri must start with http:// or https://", i, client.Id)
		}
	}

	if !c.SigningKey.GenerateIfMissing && c.SigningKey.FilePath == "" {
		return errors.New("signingKey.filePath is required when generateIfMissing is false")
	}

	if c.Users != nil && c.Users.AllowBootstrap {
		if c.Users.Static {
			return errors.New("users.allowBootstrap cannot be combined with users.static (read-only database)")
		}
		if c.Users.FilePath == "" {
			return errors.New("users.allowBootstrap requires users.filePath: without a persistent database the bootstrap window would reopen on every restart")
		}
	}

	return nil
}

// newMux registers every route under pathPrefix, so the same binary can be
// served from the host root or from a prefix such as /idp. A reverse proxy in
// front of it must pass the prefix through rather than strip it.
func newMux(r *routes.Routes, pathPrefix string, u *user.User) *http.ServeMux {
	mux := http.NewServeMux()
	handle := func(pattern string, handler http.HandlerFunc) {
		mux.HandleFunc(pathPrefix+pattern, handler)
	}

	rootPath := pathPrefix + "/"
	handle("/", func(res http.ResponseWriter, req *http.Request) {
		if req.URL.Path != rootPath {
			http.NotFound(res, req)
			return
		}
		r.Index(res, req)
	})
	handle("/.well-known/openid-configuration", r.WellKnownOpenIdConfiguration)
	handle("/login", r.Login)
	handle("/logout", r.Logout)
	handle("/oidc/auth", r.OidcAuth)
	handle("/oidc/jwks", r.OidcJwks)
	handle("/oidc/userinfo", r.OidcUserinfo)
	handle("/token", r.OidcToken)
	handle("/revoke", r.OidcRevoke)

	// In static mode the user database is read-only, so no route that mutates
	// it is registered (registration, password changes/resets, group updates,
	// deletion). Only read endpoints remain.
	if u.Static {
		slog.Info("user database is static (read-only); user-mutating routes are disabled")
	}

	if (u.SelfRegistration || u.AllowBootstrap) && !u.Static {
		if u.SelfRegistration {
			slog.Info("self-registration is enabled")
		} else {
			slog.Info("bootstrap registration is enabled while the user database is empty")
		}
		handle("/register", r.Register)
	}

	if !u.Static {
		handle("/password", r.ChangePassword)
		handle("/set-password", r.SetPassword)
	}

	if u.UserAdminGroup != "" {
		handle("/admin", r.AdminPanel)
		handle("/admin/users/api", r.AdminUsersAPI)
		if !u.Static {
			handle("/admin/register", r.AdminRegister)
			handle("/admin/users/delete", r.AdminDeleteUser)
			handle("/admin/users/reset-password", r.AdminResetPassword)
			handle("/admin/users/update-groups", r.AdminUpdateUserGroups)
			handle("/admin/users/reset-link", r.AdminCreateResetLink)
		}
	} else {
		slog.Warn("user admin group is not set; admin routes are disabled")
	}

	return mux
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := LoadConfig()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		slog.Error("invalid config", "error", err)
		os.Exit(1)
	}

	oidcConfig := oidc.Config{
		BaseUrl:           cfg.BaseUrl,
		Clients:           cfg.Clients,
		Keychain:          keychain.New(),
		SigningKeyPath:    cfg.SigningKey.FilePath,
		GenerateIfMissing: cfg.SigningKey.GenerateIfMissing,
	}
	o, err := oidc.New(oidcConfig)
	if err != nil {
		slog.Error("failed to create OIDC provider", "error", err)
		os.Exit(1)
	}

	u, err := user.New(*cfg.Users)
	if err != nil {
		slog.Error("failed to create user manager", "error", err)
		os.Exit(1)
	}

	// Validate() has already parsed baseUrl, so this cannot fail.
	parsedBaseUrl, _ := url.Parse(cfg.BaseUrl)
	pathPrefix := parsedBaseUrl.Path

	r, err := routes.New(routes.Config{
		Oidc:          o,
		Session:       session.New(),
		User:          u,
		CodeStore:     codestore.New(),
		TokenStore:    tokenstore.New(*cfg.Token),
		ResetTokens:   resettoken.New(passwordResetLinkTTL),
		BaseURL:       cfg.BaseUrl,
		PathPrefix:    pathPrefix,
		SecureCookies: strings.HasPrefix(cfg.BaseUrl, "https://"),
	})
	if err != nil {
		slog.Error("failed to create routes", "error", err)
		os.Exit(1)
	}

	mux := newMux(r, pathPrefix, u)

	slog.Info("listening", "addr", "http://localhost:8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
