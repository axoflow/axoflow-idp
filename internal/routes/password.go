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
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/axoflow/axoflow-idp/pkg/user"
)

// ChangePassword lets a logged-in user change their own password after
// re-entering their current one. On success all of the user's other sessions
// are invalidated and a fresh session is issued for the current browser.
func (r *Routes) ChangePassword(res http.ResponseWriter, req *http.Request) {
	u, err := r.getUserFromSession(req)
	if err != nil {
		http.Redirect(res, req, "/login", http.StatusFound)
		return
	}

	sessionCookie, _ := req.Cookie("session")

	switch req.Method {
	case http.MethodGet:
		r.renderChangePassword(res, sessionCookie.Value, "")
		return

	case http.MethodPost:
		if err := req.ParseForm(); err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		if !r.validateCSRF(req, sessionCookie.Value) {
			http.Error(res, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		currentPassword := req.Form.Get("current_password")
		newPassword := req.Form.Get("new_password")
		if newPassword == "" {
			res.WriteHeader(http.StatusBadRequest)
			r.renderChangePassword(res, sessionCookie.Value, "New password is required")
			return
		}

		if err := r.user.ChangePassword(u.ID, currentPassword, newPassword); err != nil {
			res.WriteHeader(http.StatusBadRequest)
			r.renderChangePassword(res, sessionCookie.Value, err.Error())
			return
		}

		if err := r.user.SaveUsers(); err != nil {
			slog.Error("failed to save users after password change", "user_id", u.ID, "error", err)
			res.WriteHeader(http.StatusInternalServerError)
			r.renderChangePassword(res, sessionCookie.Value, "Could not save your new password, please try again")
			return
		}

		// Invalidate every session for this user (including the current one),
		// then issue a fresh session so this browser stays logged in.
		r.session.DeleteUserSessions(u.ID)
		r.setSessionCookie(res, r.session.Create(u.ID))

		slog.Info("user changed password", "user_id", u.ID, "username", u.Username)
		http.Redirect(res, req, "/?flash=password", http.StatusSeeOther)
		return

	default:
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func (r *Routes) renderChangePassword(res http.ResponseWriter, sessionID, message string) {
	if err := r.template.ExecuteTemplate(res, "password.html", struct {
		Message   string
		CSRFToken string
	}{
		Message:   message,
		CSRFToken: r.csrfToken(sessionID),
	}); err != nil {
		slog.Error("failed to render password template", "error", err)
	}
}

// AdminCreateResetLink mints a single-use password-reset link for another user
// and renders the admin panel with the link shown once for the admin to copy.
// The admin never sees or sets the user's password; the user picks it via the
// link. The link is the secret and is therefore never written to the logs.
func (r *Routes) AdminCreateResetLink(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	admin, err := r.getUserFromSession(req)
	if err != nil {
		http.Error(res, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !r.user.IsAdmin(admin) {
		http.Error(res, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	sessionCookie, _ := req.Cookie("session")
	if err := req.ParseForm(); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}
	if !r.validateCSRF(req, sessionCookie.Value) {
		http.Error(res, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	userID := req.Form.Get("user_id")
	if userID == "" {
		http.Error(res, "Invalid user ID", http.StatusBadRequest)
		return
	}
	if userID == admin.ID {
		http.Error(res, "Cannot create a reset link for yourself; use Change Password instead", http.StatusBadRequest)
		return
	}

	target, ok := r.user.Get(userID)
	if !ok {
		http.Error(res, "Target user not found", http.StatusBadRequest)
		return
	}

	token, err := r.resetTokens.Create(userID)
	if err != nil {
		slog.Error("failed to generate password reset token", "target_user_id", userID, "error", err)
		http.Error(res, "Could not create reset link", http.StatusInternalServerError)
		return
	}

	slog.Info("admin created password reset link", "admin", admin.Username, "target_user_id", userID)

	r.renderAdminPanel(res, req, admin, r.resetLinkURL(token), target.Username)
}

// resetLinkURL builds the absolute password-reset URL from the configured base
// URL (never the request Host header, which is client-controlled).
func (r *Routes) resetLinkURL(token string) string {
	return strings.TrimRight(r.baseURL, "/") + "/set-password?token=" + url.QueryEscape(token)
}

// SetPassword handles the password-reset link: it shows a form gated by a
// single-use token and sets the user's password without requiring the old one.
// No session is created. There is no session-bound CSRF token here; the
// unguessable single-use token in the form is itself the CSRF defense.
func (r *Routes) SetPassword(res http.ResponseWriter, req *http.Request) {
	// The single-use token lives in the URL; keep it out of the Referer header
	// sent to any third party (e.g. web-font CDNs referenced by the layout).
	res.Header().Set("Referrer-Policy", "no-referrer")

	switch req.Method {
	case http.MethodGet:
		token := req.URL.Query().Get("token")
		if token == "" {
			r.renderSetPasswordInvalid(res)
			return
		}
		r.renderSetPasswordForm(res, token, "")
		return

	case http.MethodPost:
		if err := req.ParseForm(); err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}

		token := req.Form.Get("token")
		newPassword := req.Form.Get("new_password")
		if token == "" {
			r.renderSetPasswordInvalid(res)
			return
		}

		// Do not consume the token on a client-side validation failure, so the
		// user can retry with the same link.
		if newPassword == "" {
			res.WriteHeader(http.StatusBadRequest)
			r.renderSetPasswordForm(res, token, "New password is required")
			return
		}

		// Validate the token without consuming it yet, so that if persisting
		// the new password fails the link remains usable for a retry.
		userID, ok := r.resetTokens.Peek(token)
		if !ok {
			r.renderSetPasswordInvalid(res)
			return
		}

		if err := r.user.SetPassword(userID, newPassword); err != nil {
			// A weak password is a client-side mistake: keep the token usable and
			// re-render the form with the reason, like the empty-password branch.
			if errors.Is(err, user.ErrWeakPassword) {
				res.WriteHeader(http.StatusBadRequest)
				r.renderSetPasswordForm(res, token, err.Error())
				return
			}
			slog.Warn("set password via reset link failed", "target_user_id", userID, "error", err)
			r.renderSetPasswordInvalid(res)
			return
		}

		if err := r.user.SaveUsers(); err != nil {
			slog.Error("failed to save users after set-password via reset link", "target_user_id", userID, "error", err)
			res.WriteHeader(http.StatusInternalServerError)
			r.renderSetPasswordForm(res, token, "Could not save your new password, please try again")
			return
		}

		// Only now burn the token, and sign out any existing sessions. The token
		// was already saved durably above, so a retryable link is no longer
		// needed. If Consume reports the token already gone, a concurrent
		// request for the same link won the race (e.g. a double submit): the
		// password is set either way, so log the anomaly rather than fail.
		if _, ok := r.resetTokens.Consume(token); !ok {
			slog.Warn("reset token already consumed by a concurrent request", "target_user_id", userID)
		}
		r.session.DeleteUserSessions(userID)

		slog.Info("password set via reset link", "target_user_id", userID)
		http.Redirect(res, req, "/login?flash=password_reset", http.StatusSeeOther)
		return

	default:
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func (r *Routes) renderSetPasswordForm(res http.ResponseWriter, token, message string) {
	if err := r.template.ExecuteTemplate(res, "set_password.html", struct {
		Token   string
		Message string
		Invalid bool
	}{
		Token:   token,
		Message: message,
	}); err != nil {
		slog.Error("failed to render set_password template", "error", err)
	}
}

func (r *Routes) renderSetPasswordInvalid(res http.ResponseWriter) {
	res.WriteHeader(http.StatusBadRequest)
	if err := r.template.ExecuteTemplate(res, "set_password.html", struct {
		Token   string
		Message string
		Invalid bool
	}{
		Invalid: true,
	}); err != nil {
		slog.Error("failed to render set_password template", "error", err)
	}
}
