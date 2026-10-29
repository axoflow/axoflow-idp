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
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/axoflow/axoflow-idp/pkg/user"
)

func (r *Routes) Index(res http.ResponseWriter, req *http.Request) {
	info := struct {
		Username         string
		Email            string
		Groups           []string
		Message          string
		Success          string
		IsAdmin          bool
		SiteName         string
		SiteURL          string
		SelfRegistration bool
		Static           bool
		CSRFToken        string
	}{
		SelfRegistration: r.user.SelfRegistration,
		Static:           r.user.Static,
	}
	sessionCookie, _ := req.Cookie("session")
	u, _ := r.getUserFromSession(req)
	if u != nil {
		info.Username = u.Username
		info.Email = u.Email
		info.Groups = u.Groups
		info.IsAdmin = r.user.IsAdmin(u)
		info.CSRFToken = r.csrfToken(sessionCookie.Value)
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
	case "password":
		info.Success = "Your password has been changed. Other sessions were signed out."
	}

	if err := r.template.ExecuteTemplate(res, "index.html", info); err != nil {
		slog.Error("failed to render index template", "error", err)
	}
}

func (r *Routes) Login(res http.ResponseWriter, req *http.Request) {
	_, err := r.getUserFromSession(req)
	if err == nil {
		http.Redirect(res, req, r.url("/"), http.StatusFound)
		return
	}

	switch req.Method {
	case http.MethodGet:
		if r.needsBootstrap() {
			http.Redirect(res, req, r.url("/register"), http.StatusFound)
			return
		}
		data := r.loginTemplateData("")
		if req.URL.Query().Get("flash") == "password_reset" {
			data.Success = "Your password has been set. You can now sign in."
		}
		if err := r.template.ExecuteTemplate(res, "login.html", data); err != nil {
			slog.Error("failed to render login template", "error", err)
		}
		return

	case http.MethodPost:
		if user := r.login(res, req); user != nil {
			http.Redirect(res, req, r.url("/?flash=login"), http.StatusFound)
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

// needsBootstrap reports whether there is no user yet and the registration
// form can create the first one. The sign-in paths then redirect to /register.
func (r *Routes) needsBootstrap() bool {
	return !r.user.Static && r.user.Count() == 0 && r.user.RegistrationOpen()
}

func (r *Routes) loginTemplateData(message string) struct {
	Message          string
	Success          string
	SelfRegistration bool
} {
	return struct {
		Message          string
		Success          string
		SelfRegistration bool
	}{
		Message:          message,
		SelfRegistration: r.user.SelfRegistration,
	}
}

func (r *Routes) login(res http.ResponseWriter, req *http.Request) *user.UserInfo {
	if r.refuseCrossOriginSignIn(res, req) {
		return nil
	}
	if err := req.ParseForm(); err != nil {
		http.Error(res, err.Error(), http.StatusBadRequest)
		return nil
	}
	// from the body only: in the URL the password reaches access logs
	username := req.PostForm.Get("username")
	password := req.PostForm.Get("password")

	// refused like a wrong password, whether the account exists or not
	if wait := r.logins.Wait(username); wait > 0 {
		res.Header().Set("Retry-After", strconv.Itoa(int((wait+time.Second-1)/time.Second)))
		r.renderLoginFailed(res)
		return nil
	}
	account, err := r.user.Verify(username, password)
	if r.refuseBusy(res, req, err) {
		return nil
	}
	if err != nil {
		r.loginFailed(username)
	} else {
		r.logins.Succeed(username)
		if err := r.issueSession(res, account.ID, account.Password); err == nil {
			// The new cookie replaces the request's (the /oidc/auth form signs
			// in over a live session); end the session it pointed to.
			if old, err := req.Cookie("session"); err == nil {
				r.session.Delete(old.Value)
			}
			return &account
		}
		slog.Info("login refused: the password changed while it was checked", "user_id", account.ID)
	}

	r.renderLoginFailed(res)
	return nil
}

func (r *Routes) renderLoginFailed(res http.ResponseWriter) {
	res.WriteHeader(http.StatusUnauthorized)
	if err := r.template.ExecuteTemplate(res, "login.html", r.loginTemplateData("Invalid username or password")); err != nil {
		slog.Error("failed to render login template", "error", err)
	}
}

// errPasswordChanged refuses a session whose password was rotated after the
// request proved it.
var errPasswordChanged = errors.New("the password changed after it was proved")

// issueSession creates a session for userID and sets its cookie, provided
// the user's stored hash is still provedHash: the hash this request verified
// or committed, never one read afterwards. Every password change commits its
// hash before it signs the user out, so either the re-read below sees the
// new hash, or that sign-out runs after Create and removes the session.
func (r *Routes) issueSession(res http.ResponseWriter, userID, provedHash string) error {
	if r.hooks.beforeIssueSession != nil {
		r.hooks.beforeIssueSession()
	}
	id := r.session.Create(userID)
	if r.hooks.afterCreateSession != nil {
		r.hooks.afterCreateSession()
	}
	if u, ok := r.user.Get(userID); !ok || u.Password != provedHash {
		r.session.Delete(id)
		return errPasswordChanged
	}
	r.setSessionCookie(res, id)
	return nil
}

// setSessionCookie writes the session cookie with the standard attributes.
func (r *Routes) setSessionCookie(res http.ResponseWriter, sessionId string) {
	http.SetCookie(res, &http.Cookie{
		Name:     "session",
		Value:    sessionId,
		MaxAge:   int(r.cookieTTL.Seconds()),
		Path:     r.url("/"),
		HttpOnly: true,
		Secure:   r.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (r *Routes) Logout(res http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		slog.Warn("logout attempted with wrong method", "method", req.Method)
		res.WriteHeader(http.StatusMethodNotAllowed)
		if err := r.template.ExecuteTemplate(res, "logout_failed.html", struct{ Message string }{
			"Are you sure you want to sign out? Click the button below to confirm.",
		}); err != nil {
			slog.Error("failed to render logout_failed template", "error", err)
		}
		return
	}

	session, err := req.Cookie("session")
	if err != nil {
		slog.Warn("logout attempted without session cookie")
		http.Redirect(res, req, r.url("/?flash=logout"), http.StatusFound)
		return
	}

	r.session.Delete(session.Value)
	http.SetCookie(res, &http.Cookie{
		MaxAge: -1,
		Name:   "session",
		Path:   r.url("/"),
	})

	http.Redirect(res, req, r.url("/?flash=logout"), http.StatusFound)
}

func (r *Routes) Register(res http.ResponseWriter, req *http.Request) {
	_, err := r.getUserFromSession(req)
	if err == nil {
		http.Redirect(res, req, r.url("/"), http.StatusFound)
		return
	}

	// Picks the page; the binding check is in user.SelfRegister, under the
	// same lock as the append.
	if !r.user.RegistrationOpen() {
		r.renderError(res, req, http.StatusForbidden, "Registration Closed", "Self registration is disabled.")
		return
	}

	switch req.Method {
	case http.MethodGet:
		if err := r.template.ExecuteTemplate(res, "register.html", nil); err != nil {
			slog.Error("failed to render register template", "error", err)
		}
		return

	case http.MethodPost:
		// a registration signs the browser in, as a login does
		if r.refuseCrossOriginSignIn(res, req) {
			return
		}
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

		id, passwordHash, err := r.user.SelfRegister(username, password, []string{user.RoleUser}, email)
		if r.refuseBusy(res, req, err) {
			return
		}
		if err != nil {
			status, message := http.StatusBadRequest, err.Error()
			switch {
			case errors.Is(err, user.ErrRegistrationClosed):
				status = http.StatusForbidden
			case saveFailed(err, "operation", "self_register", "new_user", username):
				status, message = http.StatusInternalServerError, saveFailedMessage
			}
			res.WriteHeader(status)
			if err := r.template.ExecuteTemplate(res, "register.html", struct{ Message string }{Message: message}); err != nil {
				slog.Error("failed to render register template", "error", err)
			}
			return
		}

		// The registrant just proved the password, so the success page can
		// hand them to the relying party without a login stop.
		if err := r.issueSession(res, id, passwordHash); err != nil {
			slog.Info("registrant not signed in: the password changed since registration", "user_id", id)
		}

		var data struct{ SiteName, SiteURL string }
		if client := r.oidc.FirstClient(); client != nil {
			data.SiteName = client.Name
			data.SiteURL = client.URL
		}
		res.WriteHeader(http.StatusCreated)
		if err := r.template.ExecuteTemplate(res, "register_success.html", data); err != nil {
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
