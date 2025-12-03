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
	"strings"

	"github.com/axoflow/axoflow-idp/internal/codestore"
	"github.com/axoflow/axoflow-idp/internal/routes"
	"github.com/axoflow/axoflow-idp/internal/session"
	"github.com/axoflow/axoflow-idp/pkg/keychain"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

type config struct {
	BaseUrl    string        `json:"baseUrl"`
	Clients    []oidc.Client `json:"clients"`
	Users      *user.Config  `json:"users,omitempty"`
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

	if cfg.Users == nil {
		cfg.Users = &user.Config{}
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

	return nil
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

	r := routes.New(routes.Config{
		Oidc:      o,
		Session:   session.New(),
		User:      u,
		CodeStore: codestore.New(),
	})
	http.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(res, req)
			return
		}
		r.Index(res, req)
	})
	http.HandleFunc("/.well-known/openid-configuration", r.WellKnownOpenIdConfiguration)
	http.HandleFunc("/login", r.Login)
	http.HandleFunc("/logout", r.Logout)
	http.HandleFunc("/oidc/auth", r.OidcAuth)
	http.HandleFunc("/oidc/jwks", r.OidcJwks)
	http.HandleFunc("/token", r.OidcToken)

	if u.SelfRegistration {
		slog.Info("self-registration is enabled")
		http.HandleFunc("/register", r.Register)
	}

	if u.UserAdminGroup != "" {
		http.HandleFunc("/admin", r.AdminPanel)
		http.HandleFunc("/admin/register", r.AdminRegister)
		http.HandleFunc("/admin/users/delete", r.AdminDeleteUser)
		http.HandleFunc("/admin/users/reset-password", r.AdminResetPassword)
		http.HandleFunc("/admin/users/update-groups", r.AdminUpdateUserGroups)
		http.HandleFunc("/admin/users/api", r.AdminUsersAPI)
	} else {
		slog.Warn("user admin group is not set; admin routes are disabled")
	}

	slog.Info("listening", "addr", "http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
