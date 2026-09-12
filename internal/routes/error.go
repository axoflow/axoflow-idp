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
	"log/slog"
	"net/http"
)

// renderError renders the styled error page for browser-facing failures, so a
// visitor gets a proper page instead of bare plain text. Requests from the
// admin panel's fetch-based modal forms still get plain text (the message is
// shown inline in the modal). Protocol endpoints (/token, /revoke, userinfo)
// keep answering machine clients with plain http.Error and never come here.
func (r *Routes) renderError(res http.ResponseWriter, req *http.Request, status int, title, message string) {
	if wantsInlineError(req) {
		http.Error(res, message, status)
		return
	}

	res.WriteHeader(status)
	if err := r.template.ExecuteTemplate(res, "error.html", struct {
		Status  int
		Title   string
		Message string
	}{Status: status, Title: title, Message: message}); err != nil {
		slog.Error("failed to render error template", "error", err)
	}
}

// NotFound is the styled 404 page; the mux routes unknown paths here.
func (r *Routes) NotFound(res http.ResponseWriter, req *http.Request) {
	r.renderError(res, req, http.StatusNotFound, "Page Not Found", "The page you are looking for does not exist.")
}
