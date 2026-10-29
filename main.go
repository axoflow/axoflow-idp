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

// defaultCookieTTL is how long the browser keeps the session cookie unless
// session.cookieTTL says otherwise.
const defaultCookieTTL = 7 * 24 * time.Hour

// sweepInterval is how often the in-memory stores drop what has expired.
const sweepInterval = time.Hour

// sessionConfig bounds a sign-in. Each field is a Go duration string such as
// "168h" ("7d" is not one), parsed like a client's tokenTTL.
type sessionConfig struct {
	// CookieTTL is the session cookie's Max-Age; default 168h.
	CookieTTL string `json:"cookieTTL,omitempty"`
	// IdleTTL ends a session unused for this long; default and "0": never.
	IdleTTL string `json:"idleTTL,omitempty"`
	// AbsoluteTTL ends a session this long after sign-in; default the
	// cookieTTL, so a session does not outlive its cookie; "0": never.
	AbsoluteTTL string `json:"absoluteTTL,omitempty"`
}

// sessionLimits is a sessionConfig parsed, with the defaults applied.
type sessionLimits struct {
	cookie time.Duration
	session.Config
}

func (c *sessionConfig) limits() (sessionLimits, error) {
	if c == nil {
		c = &sessionConfig{}
	}
	parse := func(name, value string, def time.Duration) (time.Duration, error) {
		if value == "" {
			return def, nil
		}
		d, err := time.ParseDuration(value)
		if err != nil || d < 0 {
			return 0, fmt.Errorf("session.%s %q must be a non-negative duration such as \"168h\"", name, value)
		}
		return d, nil
	}

	var l sessionLimits
	var err error
	if l.cookie, err = parse("cookieTTL", c.CookieTTL, defaultCookieTTL); err != nil {
		return l, err
	}
	// Max-Age counts whole seconds, and a Max-Age of zero would make the
	// cookie last only until the browser closes.
	if l.cookie < time.Second {
		return l, fmt.Errorf("session.cookieTTL %q must be at least 1s", c.CookieTTL)
	}
	// The browser keeps the cookie for whole seconds only; count it the same
	// way before it becomes the default absoluteTTL and is logged.
	l.cookie = l.cookie.Truncate(time.Second)
	if l.IdleTTL, err = parse("idleTTL", c.IdleTTL, 0); err != nil {
		return l, err
	}
	if l.AbsoluteTTL, err = parse("absoluteTTL", c.AbsoluteTTL, l.cookie); err != nil {
		return l, err
	}
	return l, nil
}

type config struct {
	BaseUrl    string         `json:"baseUrl"`
	Clients    []oidc.Client  `json:"clients"`
	Users      *user.Config   `json:"users,omitempty"`
	Session    *sessionConfig `json:"session,omitempty"`
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

	// The issuer is compared verbatim by relying parties, and a credential in
	// it would be published in discovery. Hostname, not Host: "https://:443"
	// has a Host of ":443" and names no server.
	if parsedUrl.Hostname() == "" {
		return errors.New("baseUrl must have a host")
	}
	if parsedUrl.User != nil {
		return errors.New("baseUrl must not contain userinfo")
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

	seenIDs := map[string]struct{}{}
	for i, client := range c.Clients {
		if client.Id == "" {
			return fmt.Errorf("client %d: id is required", i)
		}
		if _, dup := seenIDs[client.Id]; dup {
			return fmt.Errorf("client %d (%s): duplicate id", i, client.Id)
		}
		seenIDs[client.Id] = struct{}{}
		uris := append([]string{}, client.RedirectUris...)
		if client.RedirectUri != "" {
			uris = append(uris, client.RedirectUri)
		}
		if len(uris) == 0 {
			return fmt.Errorf("client %d (%s): redirectUri or redirectUris is required", i, client.Id)
		}
		// requests are still matched by exact string; this refuses a URI no browser could be sent to
		for _, uri := range uris {
			u, err := url.Parse(uri)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.Contains(uri, "#") {
				return fmt.Errorf("client %d (%s): redirect URI %q must be an http or https URL with a host and no fragment", i, client.Id, uri)
			}
		}
		for _, resource := range client.Resources {
			if !oidc.ValidResourceIndicator(resource) {
				return fmt.Errorf("client %d (%s): resource %q must be an absolute URI without a fragment", i, client.Id, resource)
			}
		}
		if client.Public && client.ClientSecret != "" {
			return fmt.Errorf("client %d (%s): a public client has no clientSecret", i, client.Id)
		}
		if !client.Public && client.ClientSecret == "" {
			return fmt.Errorf("client %d (%s): clientSecret is required unless the client is public", i, client.Id)
		}
		if client.TokenTTL != "" {
			if _, err := oidc.ParseTokenTTL(client.TokenTTL); err != nil {
				return fmt.Errorf("client %d (%s): tokenTTL %q must be a duration between %dm and %dh", i, client.Id, client.TokenTTL, int(oidc.MinTokenTTL.Minutes()), int(oidc.DefaultTokenTTL.Hours()))
			}
		}
	}

	if _, err := c.Session.limits(); err != nil {
		return err
	}

	// Without a path a generated key is never read back, so every start would
	// generate a new one: tokens signed with the previous key no longer
	// validate against the restarted provider (a verifier still holding the
	// old key is not affected).
	if c.SigningKey.FilePath == "" {
		return errors.New("signingKey.filePath is required")
	}

	if c.Users != nil && c.Users.AllowBootstrap {
		if c.Users.Static {
			return errors.New("users.allowBootstrap cannot be combined with users.static (read-only database)")
		}
		if c.Users.FilePath == "" {
			return errors.New("users.allowBootstrap requires users.filePath: without a persistent database the bootstrap window would reopen on every restart")
		}
	}

	// The seed is applied to a writable file database only; anything else
	// would ignore the option and leave a rotated-out password valid.
	if c.Users != nil && c.Users.UpdateSeedPasswords {
		if c.Users.Static {
			return errors.New("users.updateSeedPasswords cannot be combined with users.static (read-only database)")
		}
		if c.Users.FilePath == "" || !c.Users.CreateIfMissing {
			return errors.New("users.updateSeedPasswords requires users.filePath and users.createIfMissing: without them the configured seed passwords are never applied")
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
			r.NotFound(res, req)
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

// logSessionLimits logs the effective session limits, and warns for each
// client whose tokens outlive the absolute limit: shortening the session does
// not shorten them.
func logSessionLimits(log *slog.Logger, l sessionLimits, clients []oidc.Client, tokenTTL func(clientID string) time.Duration) {
	limit := func(d time.Duration) string {
		if d == 0 {
			return "disabled"
		}
		return d.String()
	}
	log.Info("session limits", "cookie", l.cookie.String(), "idle", limit(l.IdleTTL), "absolute", limit(l.AbsoluteTTL))

	if l.AbsoluteTTL == 0 {
		return
	}
	for _, c := range clients {
		if ttl := tokenTTL(c.Id); ttl > l.AbsoluteTTL {
			log.Warn("id_token outlives the session; as a bearer JWT it stays valid at relying parties until it expires",
				"client_id", c.Id, "token_ttl", ttl.String(), "session_absolute", l.AbsoluteTTL.String())
		}
	}
}

// cleaner is an in-memory store that can drop its expired entries.
type cleaner interface{ CleanUp() }

// storeCleaners is the list of stores main sweeps.
func storeCleaners(sessions *session.Session, codes *codestore.CodeStore, tokens *tokenstore.TokenStore, resets *resettoken.Store) []cleaner {
	return []cleaner{sessions, codes, tokens, resets}
}

// startSweeper calls CleanUp on every store each interval until stop is
// called: an entry nobody presents again is otherwise held until a restart.
// stop returns once the sweeper has, so no CleanUp runs after it.
func startSweeper(interval time.Duration, stores ...cleaner) (stop func()) {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-ticker.C:
				for _, s := range stores {
					s.CleanUp()
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		ticker.Stop()
		close(done)
		<-stopped
	}
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

	// Validate() has already parsed the session block, so this cannot fail.
	limits, _ := cfg.Session.limits()
	logSessionLimits(slog.Default(), limits, cfg.Clients, o.ClientTokenTTL)

	sessions := session.New(limits.Config)
	codes := codestore.New()
	tokens := tokenstore.New(o.IDTokenTTL())
	resetTokens := resettoken.New(passwordResetLinkTTL)
	r, err := routes.New(routes.Config{
		Oidc:          o,
		Session:       sessions,
		User:          u,
		CodeStore:     codes,
		TokenStore:    tokens,
		ResetTokens:   resetTokens,
		BaseURL:       cfg.BaseUrl,
		PathPrefix:    pathPrefix,
		SecureCookies: strings.HasPrefix(cfg.BaseUrl, "https://"),
		CookieTTL:     limits.cookie,
	})
	if err != nil {
		slog.Error("failed to create routes", "error", err)
		os.Exit(1)
	}
	stopSweeper := startSweeper(sweepInterval, storeCleaners(sessions, codes, tokens, resetTokens)...)
	defer stopSweeper()

	mux := newMux(r, pathPrefix, u)

	slog.Info("listening", "addr", "http://localhost:8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
