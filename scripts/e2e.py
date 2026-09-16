#!/usr/bin/env python3
# Copyright © 2026 Axoflow
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""End-to-end tests for the self-service password / admin reset-link features.

Builds the server, runs it against an isolated temp config and a throwaway
users database, and drives the HTTP flows. Uses only the Python standard
library: the `unittest` framework manages/runs the scenarios and `urllib` +
`http.cookiejar` drive HTTP — no third-party dependencies.

Each scenario is a TestCase; the server (and a fresh users DB) is started per
class via setUpClass, so cases are isolated. Read-write cases run against a
normal config, the static case against `static: true`.

Usage:
    python3 scripts/e2e.py            # run all scenarios
    python3 scripts/e2e.py -v         # verbose (per-test names)
    python3 scripts/e2e.py StaticModeTest          # a single case
    E2E_PORT=8080 E2E_KEEP=1 python3 scripts/e2e.py

The server binds :8080 (hard-coded in the server); set E2E_PORT only if you
have patched it. E2E_KEEP=1 keeps the temp working dir for debugging.
Standard unittest flags (-v, -k, -f, test selectors) all work.
"""

import base64
import http.cookiejar
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = int(os.environ.get("E2E_PORT", "8080"))
BASE = f"http://localhost:{PORT}"

# bcrypt hashes (cost 12) of the seed passwords; verifyPassword accepts the
# "$2a$" MCF format. Generated with golang.org/x/crypto/bcrypt.
#   admin / adminpass , bob / bobpass
ADMIN_HASH = "$2a$12$VejNbOikllrg7SZdwhE1U.hC/bJX2a9i48abxFxikqT.AeJyek672"
BOB_HASH = "$2a$12$gBkn0MqTV3AMf50d5GRUsOv53ZwPwhrsjA66vbiyHLWAG7N4iS7.2"

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]*)"')
LINK_RE = re.compile(r"/set-password\?token=([A-Za-z0-9_\-]+)")

# Populated by setUpModule.
_ENV = {}


# --------------------------------------------------------------------------
# HTTP client (cookie jar per instance, never auto-follows redirects)
# --------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # surface 3xx as HTTPError so we can assert on Location


class Client:
    """An isolated browser-like client (its own cookie jar / session)."""

    def __init__(self, base=BASE):
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            _NoRedirect(),
        )

    def _do(self, method, path, form=None):
        body = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(BASE + path, data=body, method=method)
        if body is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            resp = self.opener.open(req, timeout=10)
            return resp.getcode(), resp.headers, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode("utf-8", "replace")

    def get(self, path):
        return self._do("GET", path)

    def post(self, path, form):
        return self._do("POST", path, form)

    def csrf(self, path):
        _, _, body = self.get(path)
        m = CSRF_RE.search(body)
        return m.group(1) if m else ""

    def login(self, username, password):
        return self.post("/login", {"username": username, "password": password})


# --------------------------------------------------------------------------
# server lifecycle (module-level build, per-class run)
# --------------------------------------------------------------------------
def _write_seed_users(path):
    with open(path, "w") as f:
        json.dump([
            {"ID": "admin1", "Username": "admin", "Password": ADMIN_HASH,
             "Groups": ["admin"], "Email": "admin@test.local"},
            {"ID": "bob1", "Username": "bob", "Password": BOB_HASH,
             "Groups": ["user"], "Email": "bob@test.local"},
        ], f)


def _write_empty_users(path):
    with open(path, "w") as f:
        json.dump([], f)


def _write_config(path, users_path, signing_path, static, base=BASE,
                  allow_bootstrap=False):
    with open(path, "w") as f:
        json.dump({
            "baseUrl": base,
            "clients": [{"id": "dev", "name": "Dev", "clientSecret": "s",
                         "redirectUri": BASE + "/cb"}],
            "users": {
                "createIfMissing": False,
                "filePath": users_path,
                "userAdminGroup": "admin",
                # legacy key intentionally left in to prove it is tolerated:
                "passwordChangeable": True,
                "static": static,
                "allowBootstrap": allow_bootstrap,
            },
            "signingKey": {"filePath": signing_path, "generateIfMissing": True},
        }, f)


def _wait_for_port(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def setUpModule():
    if shutil.which("go") is None:
        raise unittest.SkipTest("go toolchain not found on PATH")
    workdir = tempfile.mkdtemp(prefix="idp-e2e-")
    _ENV["workdir"] = workdir
    _ENV["users"] = os.path.join(workdir, "users.json")
    _ENV["signing"] = os.path.join(workdir, "signing-key.json")
    _ENV["cfg_rw"] = os.path.join(workdir, "config_rw.json")
    _ENV["cfg_static"] = os.path.join(workdir, "config_static.json")
    _ENV["cfg_prefix"] = os.path.join(workdir, "config_prefix.json")
    _ENV["cfg_bootstrap"] = os.path.join(workdir, "config_bootstrap.json")
    _ENV["binary"] = os.path.join(workdir, "idp")

    subprocess.run(["go", "build", "-o", _ENV["binary"], "."],
                   cwd=REPO_ROOT, check=True)
    _write_config(_ENV["cfg_rw"], _ENV["users"], _ENV["signing"], static=False)
    _write_config(_ENV["cfg_static"], _ENV["users"], _ENV["signing"], static=True)
    _write_config(_ENV["cfg_prefix"], _ENV["users"], _ENV["signing"],
                  static=False, base=BASE + "/idp")
    _write_config(_ENV["cfg_bootstrap"], _ENV["users"], _ENV["signing"],
                  static=False, allow_bootstrap=True)


def tearDownModule():
    workdir = _ENV.get("workdir")
    if not workdir:
        return
    if os.environ.get("E2E_KEEP"):
        print(f"\n(kept working dir: {workdir})")
    else:
        shutil.rmtree(workdir, ignore_errors=True)


class ServerCase(unittest.TestCase):
    """Base case: starts the server with a fresh users DB for *each* test.

    Per-test isolation matters because most scenarios mutate the users DB; a
    fresh seed + server per test keeps them independent of execution order.
    """

    CONFIG_KEY = "cfg_rw"
    SEED_USERS = staticmethod(_write_seed_users)

    def setUp(self):
        self.SEED_USERS(_ENV["users"])
        config = _ENV[self.CONFIG_KEY]
        env = dict(os.environ)
        env["CONFIG"] = config
        env["TEMPLATES_DIR"] = os.path.join(REPO_ROOT, "templates")
        self._log = open(config + ".log", "w")
        self._proc = subprocess.Popen([_ENV["binary"]], env=env,
                                      stdout=self._log, stderr=subprocess.STDOUT)
        if not _wait_for_port(PORT):
            self._stop()
            raise RuntimeError("server did not start listening (see log)")

    def tearDown(self):
        self._stop()

    def _stop(self):
        if getattr(self, "_proc", None):
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if getattr(self, "_log", None):
            self._log.close()
        time.sleep(0.2)  # let the port free up before the next test


# --------------------------------------------------------------------------
# scenarios
# --------------------------------------------------------------------------
class ChangePasswordTest(ServerCase):
    def test_change_password_and_invalidate_other_sessions(self):
        bob = Client()
        bob.login("bob", "bobpass")
        other = Client()
        other.login("bob", "bobpass")  # a second device

        code, hdrs, _ = bob.post("/password", {
            "current_password": "bobpass", "new_password": "bobpass2",
            "csrf_token": bob.csrf("/password")})
        self.assertEqual(code, 303)
        self.assertEqual(hdrs.get("Location"), "/?flash=password")

        self.assertEqual(Client().login("bob", "bobpass2")[0], 302,
                         "new password should log in")
        self.assertEqual(Client().login("bob", "bobpass")[0], 401,
                         "old password should be rejected")

        code, hdrs, _ = other.get("/password")
        self.assertEqual((code, hdrs.get("Location")), (302, "/login"),
                         "other session should be invalidated")

    def test_wrong_current_password_rejected(self):
        bob = Client()
        bob.login("bob", "bobpass")
        code, _, _ = bob.post("/password", {
            "current_password": "WRONG", "new_password": "newpass12",
            "csrf_token": bob.csrf("/password")})
        self.assertEqual(code, 400)
        self.assertEqual(Client().login("bob", "bobpass")[0], 302,
                         "password must be unchanged")

    def test_invalid_csrf_rejected(self):
        bob = Client()
        bob.login("bob", "bobpass")
        code, _, _ = bob.post("/password", {
            "current_password": "bobpass", "new_password": "x",
            "csrf_token": "bad"})
        self.assertEqual(code, 403)

    def test_requires_login(self):
        code, hdrs, _ = Client().get("/password")
        self.assertEqual((code, hdrs.get("Location")), (302, "/login"))


class AdminResetLinkTest(ServerCase):
    def _admin(self):
        c = Client()
        c.login("admin", "adminpass")
        return c

    def test_self_mint_rejected(self):
        admin = self._admin()
        code, _, _ = admin.post("/admin/users/reset-link",
                                {"user_id": "admin1", "csrf_token": admin.csrf("/admin")})
        self.assertEqual(code, 400)

    def test_anonymous_rejected(self):
        code, _, _ = Client().post("/admin/users/reset-link",
                                   {"user_id": "bob1", "csrf_token": "x"})
        self.assertEqual(code, 401)

    def test_non_admin_forbidden(self):
        bob = Client()
        bob.login("bob", "bobpass")
        code, _, _ = bob.post("/admin/users/reset-link",
                              {"user_id": "admin1", "csrf_token": bob.csrf("/password")})
        self.assertEqual(code, 403)

    def test_mint_set_and_single_use(self):
        admin = self._admin()
        code, _, body = admin.post("/admin/users/reset-link",
                                   {"user_id": "bob1", "csrf_token": admin.csrf("/admin")})
        self.assertEqual(code, 200)
        m = LINK_RE.search(body)
        self.assertIsNotNone(m, "response should contain a reset link")
        token = m.group(1)

        setpw = Client()
        code, hdrs, body = setpw.get("/set-password?token=" + token)
        self.assertEqual(hdrs.get("Referrer-Policy"), "no-referrer")
        self.assertIn('name="new_password"', body)

        code, hdrs, _ = setpw.post("/set-password",
                                   {"token": token, "new_password": "bobpass3"})
        self.assertEqual((code, hdrs.get("Location")),
                         (303, "/login?flash=password_reset"))
        self.assertEqual(hdrs.get("Referrer-Policy"), "no-referrer",
                         "token must stay out of the Referer on the POST too")
        self.assertEqual(Client().login("bob", "bobpass3")[0], 302)

        # single-use: replay must fail and must not change the password
        self.assertEqual(Client().post("/set-password",
                         {"token": token, "new_password": "hacked"})[0], 400)
        self.assertEqual(Client().login("bob", "hacked")[0], 401)


class AdminRegisterLinkTest(ServerCase):
    def test_register_with_reset_link(self):
        admin = Client()
        admin.login("admin", "adminpass")
        code, _, body = admin.post("/admin/register", {
            "auth_method": "reset_link", "username": "carol",
            "email": "carol@test.local", "groups": "user",
            "csrf_token": admin.csrf("/admin/register")})
        self.assertEqual(code, 200)
        m = LINK_RE.search(body)
        self.assertIsNotNone(m, "response should contain a reset link")
        token = m.group(1)

        self.assertEqual(Client().login("carol", "")[0], 401,
                         "new account is locked until the link is used")
        self.assertEqual(Client().post("/set-password",
                         {"token": token, "new_password": "carolpass"})[0], 303)
        self.assertEqual(Client().login("carol", "carolpass")[0], 302)


class AdminGroupHighlightTest(ServerCase):
    def test_admin_group_badge_and_tooltip(self):
        admin = Client()
        admin.login("admin", "adminpass")
        _, _, body = admin.get("/admin")
        self.assertIn('class="badge admin"', body)
        self.assertIn("Member of the administrator group", body)


class AuthorizeRedirectTest(ServerCase):
    """Hardening of the /oidc/auth redirect handling.

    The e2e config registers client "dev" with redirect_uri BASE + "/cb".
    """

    CB = BASE + "/cb"

    def _authorize(self, client, **params):
        return client.get("/oidc/auth?" + urllib.parse.urlencode(params))

    @staticmethod
    def _location_query(hdrs):
        return urllib.parse.parse_qs(
            urllib.parse.urlparse(hdrs["Location"]).query, keep_blank_values=True)

    def test_code_success_encodes_state(self):
        bob = Client()
        bob.login("bob", "bobpass")
        state = "a b&c=d#e"  # chars that would break naive interpolation
        code, hdrs, _ = self._authorize(
            bob, scope="openid", response_type="code",
            client_id="dev", redirect_uri=self.CB, state=state)
        self.assertEqual(code, 302)
        q = self._location_query(hdrs)
        self.assertEqual(q.get("state"), [state])
        self.assertTrue(q.get("code"), "authorization code must be present")

    def test_error_redirect_echoes_state(self):
        bob = Client()
        bob.login("bob", "bobpass")
        state = "s t&u"
        # Missing "openid" scope: valid client/redirect_uri, so the error is
        # redirected back with the state echoed (RFC 6749 §4.1.2.1).
        code, hdrs, _ = self._authorize(
            bob, scope="profile", response_type="code",
            client_id="dev", redirect_uri=self.CB, state=state)
        self.assertEqual(code, 302)
        q = self._location_query(hdrs)
        self.assertEqual(q.get("error"), ["invalid_scope"])
        self.assertEqual(q.get("state"), [state])

    def test_suffix_bypass_rejected(self):
        bob = Client()
        bob.login("bob", "bobpass")
        # Prefix/suffix bypass: the registered value is a prefix of this URI,
        # which the old strings.HasPrefix check accepted. Must now be rejected
        # in place, never a redirect to the attacker host.
        code, hdrs, _ = self._authorize(
            bob, scope="openid", response_type="code",
            client_id="dev", redirect_uri=self.CB + ".evil.com", state="s")
        self.assertEqual(code, 400)
        self.assertIsNone(hdrs.get("Location"),
                          "must not redirect to an unregistered uri")

    def test_path_append_rejected(self):
        bob = Client()
        bob.login("bob", "bobpass")
        code, hdrs, _ = self._authorize(
            bob, scope="openid", response_type="code",
            client_id="dev", redirect_uri=self.CB + "/extra", state="s")
        self.assertEqual(code, 400)
        self.assertIsNone(hdrs.get("Location"))


class StaticModeTest(ServerCase):
    CONFIG_KEY = "cfg_static"

    WRITE_ROUTES = [
        "/password", "/set-password", "/admin/register", "/admin/users/delete",
        "/admin/users/reset-password", "/admin/users/update-groups",
        "/admin/users/reset-link",
    ]

    def test_write_routes_disabled(self):
        for path in self.WRITE_ROUTES:
            with self.subTest(path=path):
                code, _, _ = Client().post(path, {})
                self.assertEqual(code, 404, f"{path} should be disabled")

    def test_reads_still_work(self):
        self.assertEqual(Client().get("/login")[0], 200)
        self.assertEqual(Client().login("bob", "bobpass")[0], 302)
        admin = Client()
        admin.login("admin", "adminpass")
        self.assertEqual(admin.get("/admin/users/api")[0], 200)

    def test_admin_panel_hides_write_controls(self):
        admin = Client()
        admin.login("admin", "adminpass")
        code, _, body = admin.get("/admin")
        self.assertEqual(code, 200)
        self.assertNotIn("<th>Actions</th>", body)
        self.assertNotIn("Register New User", body)


class PathPrefixTest(ServerCase):
    """The server honors a path in baseUrl (here /idp): every route, redirect,
    cookie and generated link lives under the prefix, nothing outside it is
    served, and the tokens/metadata advertise the prefixed issuer."""

    CONFIG_KEY = "cfg_prefix"
    ISSUER = BASE + "/idp"
    CB = BASE + "/cb"

    def test_routes_live_under_the_prefix_only(self):
        c = Client()
        self.assertEqual(c.get("/")[0], 404, "the host root must not be served")
        self.assertEqual(c.get("/login")[0], 404, "unprefixed routes must be gone")
        code, hdrs, _ = c.get("/idp")
        self.assertIn(code, (301, 307), "the bare prefix should redirect")
        self.assertEqual(hdrs.get("Location"), "/idp/")
        self.assertEqual(c.get("/idp/")[0], 200)
        self.assertEqual(c.get("/idp/login")[0], 200)

    def test_discovery_advertises_prefixed_urls(self):
        code, _, body = Client().get("/idp/.well-known/openid-configuration")
        self.assertEqual(code, 200)
        meta = json.loads(body)
        self.assertEqual(meta["issuer"], self.ISSUER)
        self.assertEqual(meta["authorization_endpoint"], self.ISSUER + "/oidc/auth")
        self.assertEqual(meta["token_endpoint"], self.ISSUER + "/token")
        self.assertEqual(meta["jwks_uri"], self.ISSUER + "/oidc/jwks")

    def test_auth_code_flow_issues_prefixed_iss(self):
        bob = Client()
        code, hdrs, _ = bob.post("/idp/login",
                                 {"username": "bob", "password": "bobpass"})
        self.assertEqual((code, hdrs.get("Location")), (302, "/idp/?flash=login"))
        self.assertIn("Path=/idp/", hdrs.get("Set-Cookie", ""),
                      "session cookie must be scoped to the prefix")

        code, hdrs, _ = bob.get("/idp/oidc/auth?" + urllib.parse.urlencode({
            "scope": "openid", "response_type": "code",
            "client_id": "dev", "redirect_uri": self.CB, "state": "s"}))
        self.assertEqual(code, 302)
        q = urllib.parse.parse_qs(urllib.parse.urlparse(hdrs["Location"]).query)
        self.assertTrue(q.get("code"), "authorization code must be present")

        code, _, body = Client().post("/idp/token", {
            "grant_type": "authorization_code", "client_id": "dev",
            "client_secret": "s", "redirect_uri": self.CB,
            "code": q["code"][0]})
        self.assertEqual(code, 200)
        payload = json.loads(body)["id_token"].split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
        self.assertEqual(claims["iss"], self.ISSUER,
                         "iss must match the prefixed issuer")

    def test_logout_clears_the_prefixed_session(self):
        bob = Client()
        bob.post("/idp/login", {"username": "bob", "password": "bobpass"})
        code, hdrs, _ = bob.post("/idp/logout", {})
        self.assertEqual((code, hdrs.get("Location")), (302, "/idp/?flash=logout"))
        self.assertIn("Path=/idp/", hdrs.get("Set-Cookie", ""),
                      "the clearing cookie must use the session cookie's path")
        code, hdrs, _ = bob.get("/idp/password")
        self.assertEqual((code, hdrs.get("Location")), (302, "/idp/login"),
                         "the session must be gone after logout")

    def test_reset_link_carries_the_prefix(self):
        admin = Client()
        admin.post("/idp/login", {"username": "admin", "password": "adminpass"})
        code, _, body = admin.post("/idp/admin/users/reset-link",
                                   {"user_id": "bob1",
                                    "csrf_token": admin.csrf("/idp/admin")})
        self.assertEqual(code, 200)
        self.assertIn(self.ISSUER + "/set-password?token=", body)


class BootstrapTest(ServerCase):
    """users.allowBootstrap against an empty database: the first registration
    creates a signed-in admin, then registration closes."""

    CONFIG_KEY = "cfg_bootstrap"
    SEED_USERS = staticmethod(_write_empty_users)

    @staticmethod
    def _register(client, username):
        return client.post("/register", {
            "username": username, "email": username + "@test.local",
            "password": "password123", "password_confirm": "password123"})

    def test_first_registration_becomes_admin_then_closes(self):
        first = Client()
        code, hdrs, _ = first.get("/login")
        self.assertEqual((code, hdrs.get("Location")), (302, "/register"),
                         "with no users the login page hands over to /register")

        code, _, body = self._register(first, "first")
        self.assertEqual(code, 201)
        self.assertIn("Continue to Dev", body,
                      "the success page links to the first client")
        self.assertEqual(first.get("/admin")[0], 200,
                         "the first user is signed in and is an admin")

        self.assertEqual(Client().get("/register")[0], 403,
                         "registration closes after the first user")
        self.assertEqual(self._register(Client(), "second")[0], 403)
        self.assertEqual(Client().get("/login")[0], 200,
                         "the login form is back")


if __name__ == "__main__":
    unittest.main()
