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

// Package app wires the identity provider's configuration, dependencies, and
// HTTP routes together and runs the server. main() is a thin shell over it.
package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/axoflow/axoflow-idp/internal/refreshstore"
	"github.com/axoflow/axoflow-idp/internal/tokenstore"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

// passwordResetLinkTTL is how long an admin-generated password-reset link
// stays valid. Kept short to limit the window of a leaked link.
const passwordResetLinkTTL = time.Hour

// id_token lifetime defaults. When refresh tokens are enabled the id_token is
// kept short so revocation takes effect quickly; otherwise it stays long-lived
// for backward compatibility.
const (
	defaultIDTokenTTL = 24 * time.Hour
	refreshIDTokenTTL = 15 * time.Minute
)

const defaultSessionCookieTTL = 7 * 24 * time.Hour

type SessionConfig struct {
	CookieTTL   time.Duration `json:"cookieTTL,omitempty"`
	IdleTTL     time.Duration `json:"idleTTL,omitempty"`
	AbsoluteTTL time.Duration `json:"absoluteTTL,omitempty"`
}

type Config struct {
	BaseUrl    string               `json:"baseUrl"`
	Clients    []oidc.Client        `json:"clients"`
	Users      *user.Config         `json:"users,omitempty"`
	Token      *tokenstore.Config   `json:"token,omitempty"`
	Refresh    *refreshstore.Config `json:"refresh,omitempty"`
	Session    *SessionConfig       `json:"session,omitempty"`
	IDTokenTTL time.Duration        `json:"idTokenTTL,omitempty"`
	SigningKey struct {
		FilePath          string `json:"filePath,omitempty"`
		GenerateIfMissing bool   `json:"generateIfMissing,omitempty"`
	} `json:"signingKey"`
}

// LoadConfig reads the JSON config from $CONFIG (default config.json) and
// applies defaults.
func LoadConfig() (cfg Config, err error) {
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

	cfg.applyDefaults()
	return
}

func (cfg *Config) applyDefaults() {
	if cfg.Users == nil {
		cfg.Users = &user.Config{}
	}

	if cfg.Token == nil {
		cfg.Token = &tokenstore.Config{TTL: 24 * time.Hour}
	}

	if cfg.IDTokenTTL == 0 {
		if cfg.Refresh != nil {
			cfg.IDTokenTTL = refreshIDTokenTTL
		} else {
			cfg.IDTokenTTL = defaultIDTokenTTL
		}
	}

	if cfg.Session == nil {
		cfg.Session = &SessionConfig{}
	}
	if cfg.Session.CookieTTL == 0 {
		cfg.Session.CookieTTL = defaultSessionCookieTTL
	}
	if cfg.Session.AbsoluteTTL == 0 {
		cfg.Session.AbsoluteTTL = cfg.Session.CookieTTL
	}
}

func (cfg *Config) Validate() error {
	if cfg.BaseUrl == "" {
		return errors.New("baseUrl is required")
	}

	parsedUrl, err := url.Parse(cfg.BaseUrl)
	if err != nil {
		return fmt.Errorf("baseUrl is invalid: %w", err)
	}

	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return errors.New("baseUrl must start with http:// or https://")
	}

	if len(cfg.Clients) == 0 {
		return errors.New("at least one client is required")
	}

	for i, client := range cfg.Clients {
		if client.Id == "" {
			return fmt.Errorf("client %d: id is required", i)
		}
		if client.RedirectUri == "" {
			return fmt.Errorf("client %d (%s): redirectUri is required", i, client.Id)
		}
		if !strings.HasPrefix(client.RedirectUri, "http://") && !strings.HasPrefix(client.RedirectUri, "https://") {
			return fmt.Errorf("client %d (%s): redirectUri must start with http:// or https://", i, client.Id)
		}
		if client.AllowOfflineAccess && client.ClientSecret == "" {
			return fmt.Errorf("client %d (%s): clientSecret is required when allowOfflineAccess is true", i, client.Id)
		}
	}

	if cfg.Session != nil && (cfg.Session.CookieTTL < 0 || cfg.Session.IdleTTL < 0 || cfg.Session.AbsoluteTTL < 0) {
		return errors.New("session TTLs must not be negative")
	}

	if !cfg.SigningKey.GenerateIfMissing && cfg.SigningKey.FilePath == "" {
		return errors.New("signingKey.filePath is required when generateIfMissing is false")
	}

	return nil
}
