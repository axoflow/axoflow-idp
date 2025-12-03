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
	"html/template"
	"net/http"

	"github.com/axoflow/axoflow-idp/internal/codestore"
	"github.com/axoflow/axoflow-idp/internal/session"
	"github.com/axoflow/axoflow-idp/pkg/oidc"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

type Config struct {
	Oidc      *oidc.Oidc
	Session   *session.Session
	User      *user.User
	CodeStore *codestore.CodeStore
}

type Routes struct {
	oidc     *oidc.Oidc
	session  *session.Session
	template *template.Template
	user     *user.User
	store    *codestore.CodeStore
}

func New(config Config) *Routes {
	return &Routes{
		oidc:     config.Oidc,
		session:  config.Session,
		template: template.Must(template.ParseGlob("templates/*.html")),
		user:     config.User,
		store:    config.CodeStore,
	}
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
