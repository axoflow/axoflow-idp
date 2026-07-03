# CLAUDE.md — Axoflow OIDC Identity Provider

A small, self-hosted OpenID Connect identity provider. Go standard library
only — `net/http` for routing and `html/template` for server-rendered pages;
no web framework. Users live in a JSON file; passwords are hashed with
argon2id.

## Commands

This repo uses [`just`](https://github.com/casey/just) (see `justfile`):

```sh
just              # list recipes
just verify       # editorconfig + lint + license check + tests (pre-commit gate)
just test         # unit/integration tests
just test-race    # tests with the race detector
just test-e2e     # end-to-end suite (builds the server, drives real HTTP flows)
just lint-go      # golangci-lint
just image        # build the container image
```

Go version is pinned in `.go-version`.

## Running

```sh
CONFIG=config.json go run .   # serves on :8080
```

Templates load from `./templates` (override with `TEMPLATES_DIR`). A minimal
`config.json` needs `baseUrl`, at least one `client` (`id` + `redirectUri`),
and a `signingKey` (`generateIfMissing: true` for local dev). `config.json`,
`users.json`, and `signing-key.json` are gitignored local/dev artifacts — never
commit real secrets or users.

### Local Kubernetes (Axoflow devs)

Axoflow's dev environment runs in minikube (namespace `axoflow-local`). To test
a local build in-cluster without pushing to a registry:

```sh
just minikube-deploy
```

It builds the image into minikube's Docker (tagged `:dev`) and points the
`axoidp` deployment at it. The deployment uses `imagePullPolicy: IfNotPresent`,
so it runs the in-daemon image instead of pulling from the registry.

## Project layout

```
main.go                  # config load + route wiring + server start
internal/routes/         # HTTP handlers (login, password, admin, OIDC), CSRF, templates
internal/session/        # in-memory session store
internal/resettoken/     # single-use password-reset tokens
internal/codestore/      # OIDC authorization codes (carry the grant)
internal/tokenstore/     # OIDC token revocation list
internal/refreshstore/   # rotating refresh tokens (reuse detection, families)
pkg/user/                # user database (users.json), password hashing, admin ops
pkg/oidc/                # OIDC provider, JWKS, signing
pkg/keychain/            # signing-key storage
templates/               # html/template pages
scripts/e2e.py           # stdlib-only end-to-end tests
```

## Endpoints

- **OIDC**: `/.well-known/openid-configuration`, `/oidc/auth` (PKCE S256 supported; per-client `requirePKCE`), `/token` (`authorization_code` + `refresh_token` grants), `/oidc/jwks`, `/oidc/userinfo`, `/revoke`
- **Auth / session**: `/` (profile), `/login`, `/logout`, `/register` (if self-registration is enabled)
- **Self-service**: `/password` (change), `/set-password?token=…` (admin-issued reset link)
- **Admin** (`userAdminGroup` members): `/admin`, `/admin/users/api`, plus writes `/admin/register` and `/admin/users/{delete,reset-password,update-groups,reset-link}`

## Request flow

Login verifies the password and sets a `session` cookie (in-memory `session`
store). OIDC auth issues an authorization code (`codestore`, which carries the
grant); `/token` exchanges it for a JWT signed with the key from `keychain`.
When the `refresh` config block is present and the client is an
`allowOfflineAccess` client that requested `offline_access`, `/token` also
issues a rotating refresh token (`refreshstore`); `grant_type=refresh_token`
then rotates it and re-mints the id_token. `/revoke` kills a refresh token's
whole family, else records the token in `tokenstore`.

## Conventions

- `gofmt` + `goimports`, always. Lint with `just lint-go`.
- Run `just verify` before pushing — the fast CI gates (lint, license, tests).
  Also run `just test-e2e` for significant Go changes (it's a CI gate too, just
  too slow for every push).
- Every source file carries the Apache-2.0 license header; `just license-check`
  enforces it (CI fails without it) — copy the header from any existing file
  when adding one.
- Table-driven tests; run `go test -race` for anything touching concurrency.
- Keep it stdlib-first and small; match the surrounding code.

## Notes

- The user database is a JSON file (`filePath` in config); passwords are
  argon2id (legacy bcrypt and base64 hashes are still verified).
- `users.static: true` makes the database read-only — every mutating
  operation returns `user.ErrReadOnly`, the write routes are not registered,
  and the admin panel hides its write controls (lets the DB be mounted from a
  read-only source such as a Kubernetes Secret).
- Config is loaded from the path in `CONFIG` (default `config.json`).
- PKCE (RFC 7636) is supported on the code flow, **S256 only** (`plain` is
  rejected). The `code_challenge` is bound to the auth code at `/oidc/auth` and
  the `code_verifier` verified at `/token` (`pkg/oidc/pkce.go`). Per-client
  `requirePKCE` makes a challenge mandatory; a verifier presented against a code
  with no bound challenge is rejected (anti-downgrade). Discovery advertises
  `code_challenge_methods_supported: ["S256"]`.
- Refresh tokens are opt-in: a top-level `refresh` block enables them and
  shortens the id_token TTL to 15m (24h otherwise; override with `idTokenTTL`).
  Per-client `allowOfflineAccess` gates issuance and requires a non-empty
  `clientSecret`. Tokens are opaque, server-side, and rotating with family
  reuse detection; state is in-memory (a restart drops all refresh tokens; no
  multi-replica without shared storage). Consent is pre-established per client
  (no consent screen — a deviation from OIDC Core §11), offline grants survive
  logout, and a password change / admin reset / reset-link revokes them.
  `auth_time` is intentionally not emitted until a session-accurate value is
  captured.
