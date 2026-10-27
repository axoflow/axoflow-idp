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

package tokenstore

import (
	"testing"
	"time"
)

func TestRevokeDropsRevocationsOlderThanTheTokenLifetime(t *testing.T) {
	s := New(time.Minute)
	s.revokedTokens["stale"] = time.Now().Add(-2 * time.Minute)
	s.revokedTokens["fresh"] = time.Now()

	s.Revoke("new")

	if s.IsRevoked("stale") {
		t.Error("a revocation older than the token lifetime survived Revoke")
	}
	for _, token := range []string{"fresh", "new"} {
		if !s.IsRevoked(token) {
			t.Errorf("%q is not revoked", token)
		}
	}
}

func TestRevokeKeepsEveryRevocationWithoutALifetime(t *testing.T) {
	s := New(0)
	s.revokedTokens["old"] = time.Now().Add(-24 * time.Hour)

	s.Revoke("new")

	if !s.IsRevoked("old") {
		t.Error("a zero lifetime must keep every revocation")
	}
}
