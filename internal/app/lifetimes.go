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
	"log/slog"
	"time"

	"github.com/axoflow/axoflow-idp/internal/refreshstore"
)

type lifetimeCheck struct {
	Level slog.Level
	Msg   string
	Attrs []any
}

func lifetimeChecks(sessionTTL, idTokenTTL, refreshAbsoluteTTL time.Duration, refreshEnabled bool) []lifetimeCheck {
	var checks []lifetimeCheck
	if idTokenTTL > sessionTTL {
		checks = append(checks, lifetimeCheck{
			Level: slog.LevelWarn,
			Msg:   "id_token outlives the session; as a bearer JWT it stays valid at relying parties until it expires",
			Attrs: []any{"id_token_ttl", idTokenTTL, "session_ttl", sessionTTL},
		})
	}
	if refreshEnabled && refreshAbsoluteTTL > sessionTTL {
		checks = append(checks, lifetimeCheck{
			Level: slog.LevelInfo,
			Msg:   "refresh tokens outlive the session by design (offline_access)",
			Attrs: []any{"refresh_absolute_ttl", refreshAbsoluteTTL, "session_ttl", sessionTTL},
		})
	}
	return checks
}

func logEffectiveLifetimes(cfg Config, refresh *refreshstore.Store) {
	sessionTTL := cfg.Session.CookieTTL
	if cfg.Session.AbsoluteTTL > 0 && cfg.Session.AbsoluteTTL < sessionTTL {
		sessionTTL = cfg.Session.AbsoluteTTL
	}

	attrs := []any{
		"session_cookie", cfg.Session.CookieTTL,
		"session_absolute", cfg.Session.AbsoluteTTL,
		"session_idle", cfg.Session.IdleTTL,
		"id_token", cfg.IDTokenTTL,
	}
	var refreshAbsolute time.Duration
	if refresh != nil {
		refreshAbsolute = refresh.AbsoluteTTL()
		attrs = append(attrs, "refresh_idle", refresh.IdleTTL(), "refresh_absolute", refreshAbsolute)
	}
	slog.Info("effective lifetimes", attrs...)

	for _, c := range lifetimeChecks(sessionTTL, cfg.IDTokenTTL, refreshAbsolute, refresh != nil) {
		if c.Level == slog.LevelWarn {
			slog.Warn(c.Msg, c.Attrs...)
		} else {
			slog.Info(c.Msg, c.Attrs...)
		}
	}
}
