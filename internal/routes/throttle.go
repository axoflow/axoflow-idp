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

import "log/slog"

// loginFailed counts a failed sign-in of username, and logs when it puts the
// username in cooldown.
func (r *Routes) loginFailed(username string) {
	if cooldown := r.logins.Fail(username); cooldown > 0 {
		slog.Warn("repeated failed sign-ins; username in cooldown", "username", username, "cooldown", cooldown.String())
	}
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
