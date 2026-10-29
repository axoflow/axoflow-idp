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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
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
// for the current session. Must be called after ParseForm. The token is read
// from the body only: in the URL it would reach access logs and the history.
func (r *Routes) validateCSRF(req *http.Request, sessionID string) bool {
	token := req.PostForm.Get("csrf_token")
	if token == "" {
		return false
	}
	expected := r.csrfToken(sessionID)
	return hmac.Equal([]byte(token), []byte(expected))
}

// newSignInOrigin returns the check that refuses a credential-submitting
// POST a page of another origin made the browser send: such a page could
// otherwise sign the victim in to the attacker's account (login CSRF), where
// whatever they enter is the attacker's to read. A request without
// Sec-Fetch-Site and Origin, from a non-browser client, passes. The origin of
// baseURL is trusted: behind a proxy that rewrites Host, a browser that sends
// Origin but not Sec-Fetch-Site names it, and it never matches the Host.
func newSignInOrigin(baseURL string) (*http.CrossOriginProtection, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	// a browser's Origin has a lowercase host and no default port
	host := strings.ToLower(u.Host)
	if port := u.Port(); (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		host = strings.TrimSuffix(host, ":"+port)
	}
	c := http.NewCrossOriginProtection()
	if err := c.AddTrustedOrigin(u.Scheme + "://" + host); err != nil {
		return nil, err
	}
	return c, nil
}

// refuseCrossOriginSignIn renders a 403 and reports true when req comes from
// another origin. A Sec-Fetch-Site the browser sent decides on its own:
// CrossOriginProtection would let a trusted Origin overrule a cross-site one.
func (r *Routes) refuseCrossOriginSignIn(res http.ResponseWriter, req *http.Request) bool {
	site := req.Header.Get("Sec-Fetch-Site")
	if (site != "" && site != "same-origin" && site != "none") || r.signInOrigin.Check(req) != nil {
		r.renderError(res, req, http.StatusForbidden, "Invalid Request", "The form was sent from another site. Open the sign-in page and try again.")
		return true
	}
	return false
}
