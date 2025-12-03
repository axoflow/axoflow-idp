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

	"github.com/oklog/ulid/v2"
)

func (r *Routes) AdminPanel(res http.ResponseWriter, req *http.Request) {
	admin, err := r.getUserFromSession(req)
	if err != nil {
		http.Redirect(res, req, "/login", http.StatusFound)
		return
	}

	if !r.user.IsAdmin(admin) {
		http.Error(res, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	users, err := r.user.AdminList(admin.ID)
	if err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := r.template.ExecuteTemplate(res, "admin.html", struct {
		Username string
		Users    any
	}{
		Username: admin.Username,
		Users:    users,
	}); err != nil {
		slog.Error("failed to render admin template", "error", err)
	}
}

func (r *Routes) AdminRegister(res http.ResponseWriter, req *http.Request) {
	admin, err := r.getUserFromSession(req)
	if err != nil {
		http.Redirect(res, req, "/login", http.StatusFound)
		return
	}

	if !r.user.IsAdmin(admin) {
		http.Error(res, "Forbidden: Admin access required", http.StatusForbidden)
		return
	}

	switch req.Method {
	case http.MethodGet:
		if err := r.template.ExecuteTemplate(res, "admin_register.html", struct{ Username string }{Username: admin.Username}); err != nil {
			slog.Error("failed to render admin register template", "error", err)
		}
		return

	case http.MethodPost:
		if err := req.ParseForm(); err != nil {
			http.Error(res, err.Error(), http.StatusBadRequest)
			return
		}
		username := req.Form.Get("username")
		email := req.Form.Get("email")
		password := req.Form.Get("password")
		groups := req.Form["groups"]

		if err := r.user.AdminRegister(admin.ID, username, password, groups, email); err != nil {
			res.WriteHeader(http.StatusBadRequest)
			if err := r.template.ExecuteTemplate(res, "admin_register.html", struct {
				Username string
				Message  string
			}{
				Username: admin.Username,
				Message:  err.Error(),
			}); err != nil {
				slog.Error("failed to render admin register template", "error", err)
			}
			return
		}

		if err := r.user.SaveUsers(); err != nil {
			res.WriteHeader(http.StatusInternalServerError)
			if err := r.template.ExecuteTemplate(res, "admin_register.html", struct {
				Username string
				Message  string
			}{
				Username: admin.Username,
				Message:  err.Error(),
			}); err != nil {
				slog.Error("failed to render admin register template", "error", err)
			}
			return
		}

		slog.Info("admin registered new user", "admin", admin.Username, "new_user", username)

		http.Redirect(res, req, "/admin", http.StatusSeeOther)
		return

	default:
		res.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func (r *Routes) AdminDeleteUser(res http.ResponseWriter, req *http.Request) {
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

	if err := req.ParseForm(); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}
	userId, err := ulid.Parse(req.Form.Get("user_id"))
	if err != nil {
		http.Error(res, "Invalid user ID", http.StatusBadRequest)
		return
	}

	if err := r.user.AdminDelete(admin.ID, userId); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	if err := r.user.SaveUsers(); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("admin deleted user", "admin", admin.Username, "deleted_user_id", userId.String())

	http.Redirect(res, req, "/admin", http.StatusSeeOther)
}

func (r *Routes) AdminResetPassword(res http.ResponseWriter, req *http.Request) {
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

	if err := req.ParseForm(); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}
	userId, err := ulid.Parse(req.Form.Get("user_id"))
	if err != nil {
		http.Error(res, "Invalid user ID", http.StatusBadRequest)
		return
	}

	newPassword := req.Form.Get("new_password")
	if newPassword == "" {
		http.Error(res, "New password is required", http.StatusBadRequest)
		return
	}

	if err := r.user.AdminResetPassword(admin.ID, userId, newPassword); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	if err := r.user.SaveUsers(); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("admin reset user password", "admin", admin.Username, "target_user_id", userId.String())

	http.Redirect(res, req, "/admin", http.StatusSeeOther)
}

func (r *Routes) AdminUpdateUserGroups(res http.ResponseWriter, req *http.Request) {
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

	if err := req.ParseForm(); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}
	userId, err := ulid.Parse(req.Form.Get("user_id"))
	if err != nil {
		http.Error(res, "Invalid user ID", http.StatusBadRequest)
		return
	}

	groups := req.Form["groups"]
	if err := r.user.AdminUpdateUserGroups(admin.ID, userId, groups); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return
	}

	if err := r.user.SaveUsers(); err != nil {
		http.Error(res, err.Error(), http.StatusInternalServerError)
		return
	}

	slog.Info("admin updated user groups", "admin", admin.Username, "target_user_id", userId.String(), "groups", groups)

	http.Redirect(res, req, "/admin", http.StatusSeeOther)
}

func (r *Routes) AdminUsersAPI(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
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
