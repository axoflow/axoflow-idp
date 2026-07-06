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

package app

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/axoflow/axoflow-idp/internal/codestore"
	"github.com/axoflow/axoflow-idp/internal/refreshstore"
	"github.com/axoflow/axoflow-idp/internal/resettoken"
	"github.com/axoflow/axoflow-idp/internal/routes"
	"github.com/axoflow/axoflow-idp/internal/session"
	"github.com/axoflow/axoflow-idp/internal/tokenstore"
	"github.com/axoflow/axoflow-idp/pkg/keychain"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

const (
	listenAddr      = ":8080"
	cleanupInterval = time.Hour
)

// Run builds the provider's dependencies from cfg, starts the background
// cleanup sweeper, and serves HTTP until it fails. cfg must come from
// LoadConfig (which applies defaults) and have passed Validate.
func Run(cfg Config) error {
	o, err := oidc.New(oidc.Config{
		BaseUrl:           cfg.BaseUrl,
		Clients:           cfg.Clients,
		Keychain:          keychain.New(),
		SigningKeyPath:    cfg.SigningKey.FilePath,
		GenerateIfMissing: cfg.SigningKey.GenerateIfMissing,
		IDTokenTTL:        cfg.IDTokenTTL,
		RefreshEnabled:    cfg.Refresh != nil,
	})
	if err != nil {
		return fmt.Errorf("create OIDC provider: %w", err)
	}

	u, err := user.New(*cfg.Users)
	if err != nil {
		return fmt.Errorf("create user manager: %w", err)
	}

	var refreshStore *refreshstore.Store
	if cfg.Refresh != nil {
		refreshStore = refreshstore.New(*cfg.Refresh)
		slog.Info("refresh tokens are enabled")
	}

	tokenStore := tokenstore.New(*cfg.Token)
	sessionStore := session.New(session.Config{
		IdleTTL:     cfg.Session.IdleTTL,
		AbsoluteTTL: cfg.Session.AbsoluteTTL,
	})

	r, err := routes.New(routes.Config{
		Oidc:             o,
		Session:          sessionStore,
		User:             u,
		CodeStore:        codestore.New(),
		TokenStore:       tokenStore,
		RefreshStore:     refreshStore,
		ResetTokens:      resettoken.New(passwordResetLinkTTL),
		BaseURL:          cfg.BaseUrl,
		SecureCookies:    strings.HasPrefix(cfg.BaseUrl, "https://"),
		SessionCookieTTL: cfg.Session.CookieTTL,
	})
	if err != nil {
		return fmt.Errorf("create routes: %w", err)
	}

	logEffectiveLifetimes(cfg, refreshStore)
	startCleanupSweeper(sessionStore, tokenStore, refreshStore)

	mux := http.NewServeMux()
	registerRoutes(mux, r, u)

	slog.Info("listening", "addr", "http://localhost"+listenAddr)
	return http.ListenAndServe(listenAddr, mux)
}

// registerRoutes wires every HTTP handler onto mux. Routes that mutate the user
// database are omitted in static (read-only) mode; admin routes require an
// admin group.
func registerRoutes(mux *http.ServeMux, r *routes.Routes, u *user.User) {
	mux.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(res, req)
			return
		}
		r.Index(res, req)
	})
	mux.HandleFunc("/.well-known/openid-configuration", r.WellKnownOpenIdConfiguration)
	mux.HandleFunc("/login", r.Login)
	mux.HandleFunc("/logout", r.Logout)
	mux.HandleFunc("/oidc/auth", r.OidcAuth)
	mux.HandleFunc("/oidc/jwks", r.OidcJwks)
	mux.HandleFunc("/oidc/userinfo", r.OidcUserinfo)
	mux.HandleFunc("/token", r.OidcToken)
	mux.HandleFunc("/revoke", r.OidcRevoke)

	if u.Static {
		slog.Info("user database is static (read-only); user-mutating routes are disabled")
	}

	if u.SelfRegistration && !u.Static {
		slog.Info("self-registration is enabled")
		mux.HandleFunc("/register", r.Register)
	}

	if !u.Static {
		mux.HandleFunc("/password", r.ChangePassword)
		mux.HandleFunc("/set-password", r.SetPassword)
	}

	if u.UserAdminGroup == "" {
		slog.Warn("user admin group is not set; admin routes are disabled")
		return
	}

	mux.HandleFunc("/admin", r.AdminPanel)
	mux.HandleFunc("/admin/users/api", r.AdminUsersAPI)
	if !u.Static {
		mux.HandleFunc("/admin/register", r.AdminRegister)
		mux.HandleFunc("/admin/users/delete", r.AdminDeleteUser)
		mux.HandleFunc("/admin/users/reset-password", r.AdminResetPassword)
		mux.HandleFunc("/admin/users/update-groups", r.AdminUpdateUserGroups)
		mux.HandleFunc("/admin/users/reset-link", r.AdminCreateResetLink)
	}
}

// startCleanupSweeper periodically prunes the in-memory stores. Session and
// revoked-token pruning always apply; refresh pruning only when enabled.
func startCleanupSweeper(sessions *session.Session, tokens *tokenstore.TokenStore, refresh *refreshstore.Store) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			sessions.CleanUp()
			tokens.CleanUp()
			if refresh != nil {
				refresh.CleanUp()
			}
		}
	}()
}
