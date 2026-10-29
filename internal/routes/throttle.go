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

package routes

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"
)

// loginFailed logs that a failed sign-in put username in cooldown. A username
// is as long as the request body allows, so the log gets its first 64 bytes
// and a 12-hex-character digest prefix. The prefix helps correlate log lines;
// at 48 bits it does not identify a username.
func (r *Routes) loginFailed(username string, cooldown time.Duration) {
	sum := sha256.Sum256([]byte(username))
	slog.Warn("username in cooldown", "username", truncate(username, 64),
		"username_sha256", hex.EncodeToString(sum[:6]), "cooldown", cooldown.String())
}

// setRetryAfter tells a client refused for wait when to try again, in whole
// seconds rounded up.
func setRetryAfter(res http.ResponseWriter, wait time.Duration) {
	res.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
}

// truncate cuts s to at most n bytes, at a rune boundary, and marks the cut.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "..."
}

// clientSecretFailed counts an invalid_client at /token or /revoke when it
// is a confidential client's wrong secret, and logs the count at most once a
// minute. The client is not refused for it: a guesser could lock a relying
// party out. An unknown client ID is not counted, so the keys stay the
// registered clients.
func (r *Routes) clientSecretFailed(clientID string) {
	if !r.confidential[clientID] {
		return
	}
	if n, report := r.secretFailures.Add(clientID); report {
		slog.Warn("client authentication failed: wrong client_secret", "client_id", clientID, "failures", n)
	}
}
