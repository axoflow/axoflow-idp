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
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/axoflow/axoflow-idp/pkg/user"
)

func (r *Routes) AdminPanel(res http.ResponseWriter, req *http.Request) {
	admin, err := r.getUserFromSession(req)
	if err != nil {
		http.Redirect(res, req, r.url("/login"), http.StatusFound)
		return
	}

	if !r.user.IsAdmin(admin) {
		r.renderError(res, req, http.StatusForbidden, "Access Denied", "Admin access is required for this page.")
		return
	}

	r.renderAdminPanel(res, req, admin, "", "", "")
}

// renderAdminPanel renders the admin panel. resetLink, when non-empty, surfaces
// a freshly minted password-reset link for resetLinkUser so the admin can copy
// it (the link is the secret, so it is shown once and never logged).
// errorMsg, when non-empty, is shown as an error banner and the response is a
// 400, so failed admin operations land back on the panel instead of a bare
// plain-text error page.
func (r *Routes) renderAdminPanel(res http.ResponseWriter, req *http.Request, admin *user.UserInfo, resetLink, resetLinkUser, errorMsg string) {
	users, err := r.user.AdminList(admin.ID)
	if err != nil {
		slog.Error("failed to list users for admin panel", "admin", admin.Username, "error", err)
		http.Error(res, "Failed to load user list", http.StatusInternalServerError)
		return
	}

	if errorMsg != "" {
		res.WriteHeader(http.StatusBadRequest)
	}

	sessionCookie, _ := req.Cookie("session")
	if err := r.template.ExecuteTemplate(res, "admin.html", struct {
		Username      string
		AdminID       string
		Users         any
		CSRFToken     string
		KnownGroups   []string
		AdminGroup    string
		Static        bool
		ResetLink     string
		ResetLinkUser string
		Message       string
	}{
		Username:      admin.Username,
		AdminID:       admin.ID,
		Users:         users,
		CSRFToken:     r.csrfToken(sessionCookie.Value),
		KnownGroups:   r.user.KnownGroups(),
		AdminGroup:    r.user.UserAdminGroup,
		Static:        r.user.Static,
		ResetLink:     resetLink,
		ResetLinkUser: resetLinkUser,
		Message:       errorMsg,
	}); err != nil {
		slog.Error("failed to render admin template", "error", err)
	}
}

// wantsInlineError reports whether the request came from the admin panel's
// fetch-based modal forms, which show the error inside the modal instead of a
// full page render. Plain form posts (no JS) keep the panel-banner fallback.
func wantsInlineError(req *http.Request) bool {
	return req.Header.Get("X-Requested-With") == "fetch"
}

func (r *Routes) AdminRegister(res http.ResponseWriter, req *http.Request) {
	admin, err := r.getUserFromSession(req)
	if err != nil {
		http.Redirect(res, req, r.url("/login"), http.StatusFound)
		return
	}

	if !r.user.IsAdmin(admin) {
		r.renderError(res, req, http.StatusForbidden, "Access Denied", "Admin access is required for this page.")
		return
	}

	sessionCookie, _ := req.Cookie("session")
	switch req.Method {
	case http.MethodGet:
		r.renderAdminRegister(res, sessionCookie.Value, admin.Username, "")
		return

	case http.MethodPost:
		if err := req.ParseForm(); err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		if !r.validateCSRF(req, sessionCookie.Value) {
			r.renderError(res, req, http.StatusForbidden, "Invalid Request", "The form has expired. Please go back and try again.")
			return
		}
		username := req.Form.Get("username")
		email := req.Form.Get("email")
		password := req.Form.Get("password")
		groups := req.Form["groups"]

		// The admin can either set an initial password or have the new user set
		// their own via a one-time reset link (no password chosen by the admin).
		if req.Form.Get("auth_method") == "reset_link" {
			r.adminRegisterWithResetLink(res, req, admin, sessionCookie.Value, username, email, groups)
			return
		}

		if err := r.user.AdminRegister(admin.ID, username, password, groups, email); err != nil {
			res.WriteHeader(http.StatusBadRequest)
			r.renderAdminRegister(res, sessionCookie.Value, admin.Username, err.Error())
			return
		}

		if err := r.user.SaveUsers(); err != nil {
			slog.Error("failed to save users", "operation", "register", "admin", admin.Username, "new_user", username, "error", err)
			res.WriteHeader(http.StatusInternalServerError)
			r.renderAdminRegister(res, sessionCookie.Value, admin.Username, "Failed to save changes")
			return
		}

		slog.Info("admin registered new user", "admin", admin.Username, "new_user", username)

		http.Redirect(res, req, r.url("/admin"), http.StatusSeeOther)
		return

	default:
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func (r *Routes) renderAdminRegister(res http.ResponseWriter, sessionID, adminUsername, message string) {
	if err := r.template.ExecuteTemplate(res, "admin_register.html", struct {
		Username    string
		Message     string
		CSRFToken   string
		KnownGroups []string
	}{
		Username:    adminUsername,
		Message:     message,
		CSRFToken:   r.csrfToken(sessionID),
		KnownGroups: r.user.KnownGroups(),
	}); err != nil {
		slog.Error("failed to render admin register template", "error", err)
	}
}

// adminRegisterWithResetLink creates a user with no usable password and shows a
// one-time reset link for them, so the new user chooses their own password and
// the admin never sees it.
func (r *Routes) adminRegisterWithResetLink(res http.ResponseWriter, req *http.Request, admin *user.UserInfo, sessionID, username, email string, groups []string) {
	newID, err := r.user.AdminRegisterLocked(admin.ID, username, groups, email)
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)
		r.renderAdminRegister(res, sessionID, admin.Username, err.Error())
		return
	}

	if err := r.user.SaveUsers(); err != nil {
		slog.Error("failed to save users", "operation", "register_locked", "admin", admin.Username, "new_user", username, "error", err)
		res.WriteHeader(http.StatusInternalServerError)
		r.renderAdminRegister(res, sessionID, admin.Username, "Failed to save changes")
		return
	}

	token, err := r.resetTokens.Create(newID)
	if err != nil {
		slog.Error("failed to generate password reset token", "target_user_id", newID, "error", err)
		http.Error(res, "Could not create reset link", http.StatusInternalServerError)
		return
	}

	slog.Info("admin registered new user with reset link", "admin", admin.Username, "new_user", username)
	r.renderAdminPanel(res, req, admin, r.resetLinkURL(token), username, "")
}

func (r *Routes) AdminDeleteUser(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	admin, err := r.getUserFromSession(req)
	if err != nil {
		r.renderError(res, req, http.StatusUnauthorized, "Session Expired", "Your session has expired. Please sign in again.")
		return
	}

	if !r.user.IsAdmin(admin) {
		r.renderError(res, req, http.StatusForbidden, "Access Denied", "Admin access is required for this page.")
		return
	}

	sessionCookie, _ := req.Cookie("session")
	if err := req.ParseForm(); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}
	if !r.validateCSRF(req, sessionCookie.Value) {
		r.renderError(res, req, http.StatusForbidden, "Invalid Request", "The form has expired. Please go back and try again.")
		return
	}
	userId := req.Form.Get("user_id")
	if userId == "" {
		r.renderError(res, req, http.StatusBadRequest, "Invalid Request", "Invalid user ID.")
		return
	}

	if err := r.user.AdminDelete(admin.ID, userId); err != nil {
		r.renderAdminPanel(res, req, admin, "", "", err.Error())
		return
	}

	if err := r.user.SaveUsers(); err != nil {
		slog.Error("failed to save users", "operation", "delete", "admin", admin.Username, "target_user_id", userId, "error", err)
		http.Error(res, "Failed to save changes", http.StatusInternalServerError)
		return
	}

	slog.Info("admin deleted user", "admin", admin.Username, "deleted_user_id", userId)

	http.Redirect(res, req, r.url("/admin"), http.StatusSeeOther)
}

func (r *Routes) AdminResetPassword(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	admin, err := r.getUserFromSession(req)
	if err != nil {
		r.renderError(res, req, http.StatusUnauthorized, "Session Expired", "Your session has expired. Please sign in again.")
		return
	}

	if !r.user.IsAdmin(admin) {
		r.renderError(res, req, http.StatusForbidden, "Access Denied", "Admin access is required for this page.")
		return
	}

	sessionCookie, _ := req.Cookie("session")
	if err := req.ParseForm(); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}
	if !r.validateCSRF(req, sessionCookie.Value) {
		r.renderError(res, req, http.StatusForbidden, "Invalid Request", "The form has expired. Please go back and try again.")
		return
	}
	userId := req.Form.Get("user_id")
	if userId == "" {
		r.renderError(res, req, http.StatusBadRequest, "Invalid Request", "Invalid user ID.")
		return
	}

	newPassword := req.Form.Get("new_password")
	if newPassword == "" {
		http.Error(res, "New password is required", http.StatusBadRequest)
		return
	}

	if err := r.user.AdminResetPassword(admin.ID, userId, newPassword); err != nil {
		if wantsInlineError(req) {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		r.renderAdminPanel(res, req, admin, "", "", err.Error())
		return
	}

	if err := r.user.SaveUsers(); err != nil {
		slog.Error("failed to save users", "operation", "reset_password", "admin", admin.Username, "target_user_id", userId, "error", err)
		http.Error(res, "Failed to save changes", http.StatusInternalServerError)
		return
	}

	// Invalidate the target's existing sessions so an admin reset actually locks
	// out a compromised/departed user (mirrors the reset-link flow).
	r.session.DeleteUserSessions(userId)

	slog.Info("admin reset user password", "admin", admin.Username, "target_user_id", userId)

	http.Redirect(res, req, r.url("/admin"), http.StatusSeeOther)
}

func (r *Routes) AdminUpdateUserGroups(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	admin, err := r.getUserFromSession(req)
	if err != nil {
		r.renderError(res, req, http.StatusUnauthorized, "Session Expired", "Your session has expired. Please sign in again.")
		return
	}

	if !r.user.IsAdmin(admin) {
		r.renderError(res, req, http.StatusForbidden, "Access Denied", "Admin access is required for this page.")
		return
	}

	sessionCookie, _ := req.Cookie("session")
	if err := req.ParseForm(); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}
	if !r.validateCSRF(req, sessionCookie.Value) {
		r.renderError(res, req, http.StatusForbidden, "Invalid Request", "The form has expired. Please go back and try again.")
		return
	}
	userId := req.Form.Get("user_id")
	if userId == "" {
		r.renderError(res, req, http.StatusBadRequest, "Invalid Request", "Invalid user ID.")
		return
	}

	groups := req.Form["groups"]
	if err := r.user.AdminUpdateUserGroups(admin.ID, userId, groups); err != nil {
		if wantsInlineError(req) {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		r.renderAdminPanel(res, req, admin, "", "", err.Error())
		return
	}

	if err := r.user.SaveUsers(); err != nil {
		slog.Error("failed to save users", "operation", "update_groups", "admin", admin.Username, "target_user_id", userId, "error", err)
		http.Error(res, "Failed to save changes", http.StatusInternalServerError)
		return
	}

	slog.Info("admin updated user groups", "admin", admin.Username, "target_user_id", userId, "groups", groups)

	http.Redirect(res, req, r.url("/admin"), http.StatusSeeOther)
}

func (r *Routes) AdminUsersAPI(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	admin, err := r.getUserFromSession(req)
	if err != nil {
		r.renderError(res, req, http.StatusUnauthorized, "Session Expired", "Your session has expired. Please sign in again.")
		return
	}

	if !r.user.IsAdmin(admin) {
		r.renderError(res, req, http.StatusForbidden, "Access Denied", "Admin access is required for this page.")
		return
	}

	users, err := r.user.AdminList(admin.ID)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(res).Encode(users); err != nil {
		slog.Error("failed to write users api response", "error", err)
	}
}
