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

import "net/http"

// SecurityHeaders sets the headers every response of next carries: no page
// of the IdP is meant to be framed, where a login or admin form could be
// clickjacked, and no response may be sniffed as another content type.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		h := res.Header()
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(res, req)
	})
}

// NoStore keeps every response of next, its errors included, out of browser
// and proxy caches: it shows an account, a secret such as a reset link, or a
// form for one. It is set before next writes anything.
func NoStore(next http.HandlerFunc) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		res.Header().Set("Cache-Control", "no-store")
		next(res, req)
	}
}
