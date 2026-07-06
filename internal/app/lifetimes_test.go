// Copyright © 2026 Axoflow
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
	"testing"
	"time"
)

func hasLevel(checks []lifetimeCheck, level slog.Level) bool {
	for _, c := range checks {
		if c.Level == level {
			return true
		}
	}
	return false
}

func TestLifetimeChecks(t *testing.T) {
	const day = 24 * time.Hour
	tests := []struct {
		name           string
		sessionTTL     time.Duration
		idTokenTTL     time.Duration
		refreshAbsTTL  time.Duration
		refreshEnabled bool
		wantWarn       bool
		wantInfo       bool
	}{
		{"refresh off, id_token under session", 7 * day, day, 0, false, false, false},
		{"refresh off, id_token outlives session", 12 * time.Hour, day, 0, false, true, false},
		{"refresh on defaults: 15m token, 30d refresh, 7d session", 7 * day, 15 * time.Minute, 30 * day, true, false, true},
		{"refresh on, short session: token and refresh both outlive", 5 * time.Minute, 15 * time.Minute, 30 * day, true, true, true},
		{"refresh equal to session emits nothing", 7 * day, day, 7 * day, true, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := lifetimeChecks(tt.sessionTTL, tt.idTokenTTL, tt.refreshAbsTTL, tt.refreshEnabled)
			if hasLevel(got, slog.LevelWarn) != tt.wantWarn {
				t.Errorf("warn = %v, want %v (checks: %+v)", !tt.wantWarn, tt.wantWarn, got)
			}
			if hasLevel(got, slog.LevelInfo) != tt.wantInfo {
				t.Errorf("info = %v, want %v (checks: %+v)", !tt.wantInfo, tt.wantInfo, got)
			}
		})
	}
}
