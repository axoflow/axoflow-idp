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
`config.json` needs `baseUrl`, at least one `client` (`id`, `redirectUri` or
`redirectUris`, and either `clientSecret` or `public: true`), and a
`signingKey.filePath` (`generateIfMissing: true` for local dev). `config.json`,
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
- **Auth / session**: `/` (profile), `/login`, `/logout`, `/register` (with `selfRegistration` or `allowBootstrap`)
- **Self-service**: `/password` (change), `/set-password?token=…` (admin-issued reset link)
- **Admin** (`userAdminGroup` members): `/admin`, `/admin/users/api`, plus writes `/admin/register` and `/admin/users/{delete,reset-password,update-groups,reset-link}`

## Request flow

Login verifies the password and sets a `session` cookie (in-memory `session`
store). OIDC auth issues an authorization code (`codestore`); `/token` exchanges
it for a JWT signed with the key from `keychain`; `/oidc/userinfo` answers to the
`at+jwt` access token only, never to the ID token; `/revoke` records revocations
in `tokenstore`. The response's access token is a separate JWT (`typ: at+jwt`)
whose `aud` is the requested RFC 8707 `resource`, or the client id without one.

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
- A duration in the JSON config is a string parsed with `time.ParseDuration`
  (`"tokenTTL": "1h"`), never a bare `time.Duration` field: a JSON number would
  decode as nanoseconds.

## Notes

- The user database is a JSON file (`filePath` in config); passwords are
  argon2id (legacy bcrypt and base64 hashes are still verified).
- `users.static: true` makes the database read-only — every mutating
  operation returns `user.ErrReadOnly`, the write routes are not registered,
  and the admin panel hides its write controls (lets the DB be mounted from a
  read-only source such as a Kubernetes Secret).
- Seed users (`users.users`) reach a new database only. With
  `users.updateSeedPasswords`, a seed user's password is the exception: every
  start sets the configured hash on the existing account (see README "Seeding
  the user database"). Config validation requires `filePath` and
  `createIfMissing` with it, and refuses it with `static`.
- Bootstrap: the first user registered into an *empty* database joins
  `users.userAdminGroup`, so a fresh deployment has an admin without anyone
  hand-editing `users.json`. It needs a persistent database (`filePath`);
  a memory-only one is empty after every restart. While the database is
  empty and `/register` can create a user, `GET /login` and the login form
  of `/oidc/auth` redirect to `/register`.
- A successful registration sets the session cookie and the success page
  links to the first client's site, so the bootstrap admin reaches the app
  with a single password entry.
- `users.allowBootstrap: true` (default false) opens `/register` for the
  first user only when self-registration is off. Config validation requires
  a persistent, non-static database with it.
- Admins cannot delete themselves or remove their own admin group, so the
  admin panel can never lose the last admin.
- `baseUrl` may carry a path (e.g. `https://host/idp`). Its path becomes the
  prefix every route, redirect, cookie and template link is scoped to, so a
  reverse proxy must pass the prefix through instead of stripping it.
- A `public: true` client has no `clientSecret`, must use the code flow with
  PKCE `S256` and cannot call `/revoke`; any client may request one `resource`
  from its `resources` list (an empty value counts as omitted), and anything
  else is `invalid_target`.
- `session` (`cookieTTL`, `idleTTL`, `absoluteTTL`, duration strings): the
  cookie lasts 168h by default; idle expiry is off; `absoluteTTL` defaults
  to the cookie TTL, so a session never outlives its cookie; `"0"` disables
  idle or absolute expiry. A user holds at most 50 sessions (the oldest is
  evicted). An hourly sweeper in `main.go` calls `CleanUp` on the session,
  code, token and reset-link stores.
- Config is loaded from the path in `CONFIG` (default `config.json`).
