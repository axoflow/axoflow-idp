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
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"

	"github.com/axoflow/axoflow-idp/internal/codestore"
	"github.com/axoflow/axoflow-idp/internal/resettoken"
	"github.com/axoflow/axoflow-idp/internal/session"
	"github.com/axoflow/axoflow-idp/internal/tokenstore"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

type Config struct {
	Oidc          *oidc.Oidc
	Session       *session.Session
	User          *user.User
	CodeStore     *codestore.CodeStore
	TokenStore    *tokenstore.TokenStore
	ResetTokens   *resettoken.Store
	BaseURL       string
	PathPrefix    string
	SecureCookies bool
}

type Routes struct {
	oidc          *oidc.Oidc
	session       *session.Session
	template      *template.Template
	user          *user.User
	store         *codestore.CodeStore
	tokenStore    *tokenstore.TokenStore
	resetTokens   *resettoken.Store
	baseURL       string
	prefix        string
	secureCookies bool
	csrfKey       []byte
}

// templateFuncs are the helpers available to every HTML template.
func templateFuncs(prefix string) template.FuncMap {
	return template.FuncMap{
		// toJSON renders a value as a JSON literal, e.g. to pass a user's groups to
		// client-side JS through a data- attribute as a real array.
		"toJSON": func(v any) (string, error) {
			b, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
		// url turns an app-relative path into one the browser can follow, which
		// is the path itself unless the IdP is served under a prefix.
		"url": func(path string) string {
			return prefix + path
		},
	}
}

// parseTemplates loads every *.html template in dir with templateFuncs
// registered. Both the server and the tests go through it.
func parseTemplates(dir, prefix string) (*template.Template, error) {
	return template.New("").Funcs(templateFuncs(prefix)).ParseGlob(filepath.Join(dir, "*.html"))
}

func New(config Config) (*Routes, error) {
	dir, err := findTemplatesDir()
	if err != nil {
		return nil, err
	}
	tpl, err := parseTemplates(dir, config.PathPrefix)
	if err != nil {
		return nil, fmt.Errorf("parse templates in %s: %w", dir, err)
	}
	return &Routes{
		oidc:          config.Oidc,
		session:       config.Session,
		template:      tpl,
		user:          config.User,
		store:         config.CodeStore,
		tokenStore:    config.TokenStore,
		resetTokens:   config.ResetTokens,
		baseURL:       config.BaseURL,
		prefix:        config.PathPrefix,
		secureCookies: config.SecureCookies,
		csrfKey:       generateCSRFKey(),
	}, nil
}

// findTemplatesDir locates the HTML templates directory. It checks, in order:
// the TEMPLATES_DIR environment variable, ./templates in the current working
// directory, and a templates/ directory next to the running executable.
func findTemplatesDir() (string, error) {
	candidates := make([]string, 0, 3)
	if env := os.Getenv("TEMPLATES_DIR"); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates, "templates")
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "templates"))
	}
	for _, dir := range candidates {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("templates directory not found in any of: %v", candidates)
}

// url is the Go counterpart of the url template func: it scopes an
// app-relative path to the prefix the IdP is served under.
func (r *Routes) url(path string) string {
	return r.prefix + path
}

func (r *Routes) getUserFromSession(req *http.Request) (*user.UserInfo, error) {
	sessionId, err := req.Cookie("session")
	if err != nil {
		return nil, err
	}

	userId, err := r.session.Get(sessionId.Value)
	if err != nil {
		return nil, err
	}

	u, ok := r.user.Get(userId)
	if !ok {
		return nil, errors.New("user not found")
	}

	return &u, nil
}
