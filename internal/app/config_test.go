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
	"testing"
	"time"

	"github.com/axoflow/axoflow-idp/pkg/oidc"
)

func baseValidConfig() Config {
	c := Config{
		BaseUrl: "https://idp.example.com",
		Clients: []oidc.Client{{Id: "app", RedirectUri: "https://app.example.com/cb", ClientSecret: "s3cret"}},
	}
	c.SigningKey.GenerateIfMissing = true
	return c
}

func TestValidateOfflineAccessRequiresSecret(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"offline access with a secret is ok", func(c *Config) { c.Clients[0].AllowOfflineAccess = true }, false},
		{"offline access without a secret is rejected", func(c *Config) {
			c.Clients[0].AllowOfflineAccess = true
			c.Clients[0].ClientSecret = ""
		}, true},
		{"no offline access, empty secret is ok", func(c *Config) { c.Clients[0].ClientSecret = "" }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseValidConfig()
			tt.mutate(&c)
			if err := c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRejectsNegativeSessionTTL(t *testing.T) {
	tests := []struct {
		name    string
		session *SessionConfig
		wantErr bool
	}{
		{"nil session ok", nil, false},
		{"positive ok", &SessionConfig{CookieTTL: time.Hour, IdleTTL: time.Minute, AbsoluteTTL: time.Hour}, false},
		{"negative cookie rejected", &SessionConfig{CookieTTL: -time.Hour}, true},
		{"negative idle rejected", &SessionConfig{IdleTTL: -time.Minute}, true},
		{"negative absolute rejected", &SessionConfig{AbsoluteTTL: -time.Hour}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseValidConfig()
			c.Session = tt.session
			if err := c.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
