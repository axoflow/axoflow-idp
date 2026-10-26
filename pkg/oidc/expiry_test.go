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

package oidc

import (
	"testing"
	"time"

	"github.com/axoflow/axoflow-idp/internal/tokenstore"
	"github.com/axoflow/axoflow-idp/pkg/user"
)

// TestTokenNotAcceptedOnOrAfterExp pins RFC 7519 §4.1.4 and the contract with main.go's revocation list,
// tokenstore.New(o.IDTokenTTL()): a revocation is kept for the token lifetime from the revoke, so the
// validator must refuse the token on its own once its exp second begins. The lifetime is one second here.
func TestTokenNotAcceptedOnOrAfterExp(t *testing.T) {
	o := newTestOidc(t, []Client{{Id: "app", RedirectUri: "https://app.example.com/cb", ClientSecret: "s3cret"}})
	o.idTokenTTL = time.Second
	store := tokenstore.New(o.IDTokenTTL())

	// issue early in a wall-clock second: iat is that second and the record, kept for one second from the
	// revoke, is dropped before the exp second ends
	for time.Now().Nanosecond() > 100_000_000 {
		time.Sleep(time.Millisecond)
	}
	issued := time.Now()
	token, err := o.GenerateAccessToken(user.UserInfo{ID: "u1", Username: "alice"}, "app", "")
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}
	id, err := o.AccessTokenID(token) // the route records the revocation under the jti
	if err != nil {
		t.Fatalf("AccessTokenID: %v", err)
	}
	store.Revoke(id)
	exp := issued.Unix() + 1
	if _, err := o.GetUserinfoFromToken(token); err != nil {
		t.Fatalf("a fresh token is refused: %v", err)
	}

	time.Sleep(time.Until(time.Unix(exp, 500_000_000)))
	store.Revoke("another-id") // a later /revoke prunes the list on write
	if store.IsRevoked(id) {
		t.Errorf("the revocation record outlived the token lifetime")
	}
	if _, err := o.GetUserinfoFromToken(token); err == nil {
		t.Fatalf("token accepted at unix %d, exp %d", time.Now().Unix(), exp)
	}
}
