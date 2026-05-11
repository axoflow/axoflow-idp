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
	"log/slog"
	"net/http"

	"github.com/axoflow/axoflow-idp/pkg/user"
)

func (r *Routes) Index(res http.ResponseWriter, req *http.Request) {
	info := struct {
		Username         string
		Message          string
		Success          string
		IsAdmin          bool
		SiteName         string
		SiteURL          string
		SelfRegistration bool
	}{
		SelfRegistration: r.user.SelfRegistration,
	}
	u, _ := r.getUserFromSession(req)
	if u != nil {
		info.Username = u.Username
		info.IsAdmin = r.user.IsAdmin(u)
	}
	if client := r.oidc.FirstClient(); client != nil {
		info.SiteName = client.Name
		info.SiteURL = client.URL
	}
	switch req.URL.Query().Get("flash") {
	case "login":
		info.Success = "Welcome back, " + info.Username + "!"
	case "logout":
		info.Success = "You have been logged out successfully."
	}

	if err := r.template.ExecuteTemplate(res, "index.html", info); err != nil {
		slog.Error("failed to render index template", "error", err)
	}
}

func (r *Routes) Login(res http.ResponseWriter, req *http.Request) {
	_, err := r.getUserFromSession(req)
	if err == nil {
		http.Redirect(res, req, "/", http.StatusFound)
		return
	}

	switch req.Method {
	case http.MethodGet:
		if err := r.template.ExecuteTemplate(res, "login.html", r.loginTemplateData("")); err != nil {
			slog.Error("failed to render login template", "error", err)
		}
		return

	case http.MethodPost:
		if user := r.login(res, req); user != nil {
			http.Redirect(res, req, "/?flash=login", http.StatusFound)
		}
		return

	default:
		res.WriteHeader(http.StatusMethodNotAllowed)
		if err := r.template.ExecuteTemplate(res, "login.html", r.loginTemplateData("")); err != nil {
			slog.Error("failed to render login template", "error", err)
		}
		return
	}
}

func (r *Routes) loginTemplateData(message string) struct {
	Message          string
	SelfRegistration bool
} {
	return struct {
		Message          string
		SelfRegistration bool
	}{
		Message:          message,
		SelfRegistration: r.user.SelfRegistration,
	}
}

func (r *Routes) login(res http.ResponseWriter, req *http.Request) *user.UserInfo {
	if err := req.ParseForm(); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return nil
	}
	username := req.Form.Get("username")
	password := req.Form.Get("password")

	user, ok := r.user.Authenticate(username, password)
	if !ok {
		res.WriteHeader(http.StatusUnauthorized)
		if err := r.template.ExecuteTemplate(res, "login.html", r.loginTemplateData("Invalid username or password")); err != nil {
			slog.Error("failed to render login template", "error", err)
		}
		return nil
	}

	sessionId := r.session.Create(user.ID)
	http.SetCookie(res, &http.Cookie{
		Name:   "session",
		Value:  sessionId,
		MaxAge: 60 * 60 * 24 * 7,
		Path:   "/",
	})
	return &user
}

func (r *Routes) Logout(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		res.WriteHeader(http.StatusMethodNotAllowed)
		if err := r.template.ExecuteTemplate(res, "logout_failed.html", nil); err != nil {
			slog.Error("failed to render logout_failed template", "error", err)
		}
		return
	}

	session, err := req.Cookie("session")
	if err != nil {
		res.WriteHeader(http.StatusBadRequest)
		if err := r.template.ExecuteTemplate(res, "logout_failed.html", nil); err != nil {
			slog.Error("failed to render logout_failed template", "error", err)
		}
		return
	}

	r.session.Delete(session.Value)
	http.SetCookie(res, &http.Cookie{
		MaxAge: -1,
		Name:   "session",
	})

	http.Redirect(res, req, "/?flash=logout", http.StatusFound)
}

func (r *Routes) Register(res http.ResponseWriter, req *http.Request) {
	_, err := r.getUserFromSession(req)
	if err == nil {
		http.Redirect(res, req, "/", http.StatusFound)
		return
	}

	if !r.user.SelfRegistration {
		http.Error(res, "Self registration is disabled", http.StatusForbidden)
		return
	}

	switch req.Method {
	case http.MethodGet:
		if err := r.template.ExecuteTemplate(res, "register.html", nil); err != nil {
			slog.Error("failed to render register template", "error", err)
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
		passwordConfirm := req.Form.Get("password_confirm")
		if email == "" {
			res.WriteHeader(http.StatusBadRequest)
			if err := r.template.ExecuteTemplate(res, "register.html", struct{ Message string }{"Email is required"}); err != nil {
				slog.Error("failed to render register template", "error", err)
			}
			return
		}
		if password != passwordConfirm {
			res.WriteHeader(http.StatusBadRequest)
			if err := r.template.ExecuteTemplate(res, "register.html", struct{ Message string }{Message: "Passwords do not match"}); err != nil {
				slog.Error("failed to render register template", "error", err)
			}
			return
		}

		if err := r.user.Register(username, password, []string{user.RoleUser}, email); err != nil {
			res.WriteHeader(http.StatusBadRequest)
			if err := r.template.ExecuteTemplate(res, "register.html", struct{ Message string }{Message: err.Error()}); err != nil {
				slog.Error("failed to render register template", "error", err)
			}
			return
		}

		if err := r.user.SaveUsers(); err != nil {
			res.WriteHeader(http.StatusInternalServerError)
			if err := r.template.ExecuteTemplate(res, "register.html", struct{ Message string }{Message: err.Error()}); err != nil {
				slog.Error("failed to render register template", "error", err)
			}
			return
		}

		res.WriteHeader(http.StatusCreated)
		if err := r.template.ExecuteTemplate(res, "register_success.html", nil); err != nil {
			slog.Error("failed to render register_success template", "error", err)
		}

		return

	default:
		res.WriteHeader(http.StatusMethodNotAllowed)
		if err := r.template.ExecuteTemplate(res, "register.html", nil); err != nil {
			slog.Error("failed to render register template", "error", err)
		}
		return
	}
}
