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

## Project layout

```
main.go                  # config load + route wiring + server start
internal/routes/         # HTTP handlers (login, password, admin, OIDC), CSRF, templates
internal/session/        # in-memory session store
internal/resettoken/     # single-use password-reset tokens
internal/codestore/      # OIDC authorization codes
internal/tokenstore/     # OIDC token revocation list
pkg/user/                # user database (users.json), password hashing, admin ops
pkg/oidc/                # OIDC provider, JWKS, signing
pkg/keychain/            # signing-key storage
templates/               # html/template pages
scripts/e2e.py           # stdlib-only end-to-end tests
```

## Endpoints

- **OIDC**: `/.well-known/openid-configuration`, `/oidc/auth`, `/token`, `/oidc/jwks`, `/oidc/userinfo`, `/revoke`
- **Auth / session**: `/` (profile), `/login`, `/logout`, `/register` (if self-registration is enabled)
- **Self-service**: `/password` (change), `/set-password?token=…` (admin-issued reset link)
- **Admin** (`userAdminGroup` members): `/admin`, `/admin/users/api`, plus writes `/admin/register` and `/admin/users/{delete,reset-password,update-groups,reset-link}`

## Request flow

Login verifies the password and sets a `session` cookie (in-memory `session`
store). OIDC auth issues an authorization code (`codestore`); `/token` exchanges
it for a JWT signed with the key from `keychain`; `/revoke` records revocations
in `tokenstore`.

## Conventions

- `gofmt` + `goimports`, always. Lint with `just lint-go`.
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
