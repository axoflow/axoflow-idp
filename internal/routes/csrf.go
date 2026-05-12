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

package routes

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
)

func generateCSRFKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic("failed to generate CSRF key: " + err.Error())
	}
	return key
}

// csrfToken returns a stateless CSRF token bound to the given session ID.
func (r *Routes) csrfToken(sessionID string) string {
	mac := hmac.New(sha256.New, r.csrfKey)
	mac.Write([]byte(sessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// validateCSRF checks the csrf_token form value against the expected token
// for the current session. Must be called after ParseForm.
func (r *Routes) validateCSRF(req *http.Request, sessionID string) bool {
	token := req.FormValue("csrf_token")
	if token == "" {
		return false
	}
	expected := r.csrfToken(sessionID)
	return hmac.Equal([]byte(token), []byte(expected))
}
