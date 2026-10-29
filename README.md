# Axoflow-IdP

A lightweight OpenID Connect (OIDC) Identity Provider, designed to work seamlessly with Axoflow.

## Overview

Axoflow-IdP is a simple yet feature-rich OIDC provider that enables authentication for your applications. It supports multiple clients, user self-registration, administrative user management, and JWT-based token signing. The provider implements standard OIDC endpoints including authorization, token exchange, and JWKS discovery.

## Quickstart

1. Create a `config.json` file with your OIDC clients and base URL:

```json
{
    "baseUrl": "http://localhost:8080",
    "clients": [
    {
        "id": "your-client-id",
        "clientSecret": "change-me",
        "redirectUri": "http://localhost:3000/callback"
    }
    ],
    "signingKey": {
        "filePath": "signing-key.pem",
        "generateIfMissing": true
    }
}
```

2. Run the IdP:

```bash
go run main.go
```

3. The IdP will be available at `http://localhost:8080` with OIDC discovery at `/.well-known/openid-configuration`

> `baseUrl` may include a path, e.g. `https://sso.example.com/idp`. The IdP then
> serves every page, every OIDC endpoint and the discovery document under that
> prefix, and advertises it as the `issuer`. A reverse proxy in front of it must
> pass the prefix through rather than strip it, and health/readiness probes must
> target the prefix root (`/idp/`) — outside the prefix everything is 404.
> A trailing slash in `baseUrl` is trimmed, so `https://host/` and `https://host`
> both yield the issuer `https://host`; relying parties that pinned an issuer
> string ending in `/` must drop the slash.

> `redirect_uri` is matched by **exact string comparison** against a client's
> registered URIs at both `/oidc/auth` and `/token`. Register additional
> callbacks with a `redirectUris` array alongside (or instead of) the singular
> `redirectUri`; any request whose `redirect_uri` is not an exact match is
> rejected.

> The implicit flow (`response_type=id_token`) requires a `nonce` and delivers
> its response, the ID token or an error, in the redirect's fragment
> (`#id_token=…&state=…`), never in the query; `response_mode` is ignored. The
> code flow keeps the query (`?code=…&state=…`).

### Public clients

A client that cannot keep a secret, such as a command-line tool, is
registered with `"public": true` and no `clientSecret`. It must use the
authorization code flow with a PKCE `S256` challenge (`plain` is refused) and
sends its `code_verifier` instead of a secret at `/token`.

A `resource` parameter (RFC 8707) names the API the access token is for. A
request may carry at most one; a non-empty value must be one of the client's
`resources`, and a client without that list may not send one. Anything else is
refused with `invalid_target`; a single empty value counts as omitted (RFC 6749
§3.1). A `resource` repeated at `/token` must be the one the code was issued
for; another is refused with `invalid_target` and spends the code.

The access token is a JWT separate from the ID token. Its header carries
`typ: at+jwt` (RFC 9068), so a validator that enforces the profile can tell it
from an ID token. Its `aud` is the requested resource (the client id without
one), and it carries `client_id`. The ID token's `aud` stays the client id.
`/oidc/userinfo` answers to the access token only; the ID token is refused
there. A revocation is recorded under the access token's `jti`, so every
spelling of the revoked token is refused; revoking an ID token records nothing.
A client can revoke only the access tokens issued to it: another client's
token is answered `200` like an unknown token and stays valid.

The tokens are signed from the user's record when the code is redeemed, not
when the user logged in: a user deleted in between gets `invalid_grant`, and a
group removed in between is not in the tokens. `/oidc/userinfo` returns the
user's current groups, name and email, and `401` once the user is deleted. The
user is looked up by ID, so an account deleted and registered again under the
same username is someone else to both. The implicit flow's ID token is
signed from the record as it is after the login. A change after that read
cannot recall a token already issued: a relying party that validates a JWT
offline accepts it, with the groups it was issued with, until its `exp`. A
password reset does not revoke outstanding codes or tokens either.

A public client cannot call `/revoke` (`401 invalid_client`); its tokens expire
instead. A revocation is kept for the maximum token lifetime (24 hours),
whatever the client's `tokenTTL`, and pruned on a later valid access-token revocation.

`tokenTTL` sets the lifetime of a client's ID and access tokens as a Go
duration string such as `"1h"`; the tokens are signed when the code is
redeemed at `/token`, so `expires_in` is this lifetime. The range is `"1m"`
to the default of `"24h"`; a value outside it is refused at start (a
revocation is kept for 24 hours, and a token must not outlive its revocation
record).

```json
{
    "id": "example-cli",
    "name": "Example CLI",
    "public": true,
    "redirectUris": ["http://127.0.0.1/callback"],
    "resources": ["https://api.example.com/v1"],
    "tokenTTL": "1h"
}
```

A client that is not public must have a `clientSecret`.

> Upgrading: the configuration is now checked at start. A client needs
> `redirectUri` or `redirectUris`; every redirect URI, the singular one and each
> list entry, must be an `http` or `https` URL with a host and no fragment; a
> client that is not public needs a `clientSecret`; every `resources` entry must
> have a scheme and no fragment. Correct such entries before upgrading, or the
> server refuses to start and names the client and the value. `/oidc/userinfo`
> now takes the access token only: a client that sent the ID token gets `401`
> and must send the code flow's `access_token`; a token issued before the
> upgrade, when the access token was the ID token, must be re-acquired. The
> undocumented `token.ttl` is no longer read: a revocation is kept for 24 hours,
> the maximum token lifetime. Client ids must be unique, `baseUrl` needs a host
> and no userinfo (`user:password@`), and `signingKey.filePath` is required
> even with `generateIfMissing`: without it every start generated a new key, so
> tokens signed with the previous key no longer validated against the restarted
> provider (a verifier that still held the old key was not affected).

> Upgrading: `/token` and `/revoke` read the client's credentials and the
> secrets of the exchange from the `application/x-www-form-urlencoded` POST
> body only, as a URL reaches access logs and proxies. `/token` reads
> `client_id`, `client_secret`, `code` and `code_verifier` there; `/revoke`
> reads `client_id`, `client_secret` and `token`. A copy in the URL query is
> ignored, so a client that sent one of them only in the query now gets
> `401 invalid_client` for its id or secret, `400 invalid_grant` for the code,
> and for the verifier `400 invalid_request` (public client) or
> `400 invalid_grant` (a confidential client's PKCE code, which is then
> spent). `/revoke` without a `token` in the body is now
> `400 invalid_request`, not `200`. The client authentication methods this
> server supports are `client_secret_post` and, for public clients, `none`.

### Sessions

Signing in sets a `session` cookie. The optional `session` block bounds it,
with Go duration strings as for `tokenTTL` (`"168h"`; `"7d"` is not a Go
duration). These are the defaults:

```json
"session": {
    "cookieTTL": "168h",
    "idleTTL": "0",
    "absoluteTTL": "168h"
}
```

- `cookieTTL` is the cookie's `Max-Age`, in whole seconds (a fraction is
  dropped); at least `"1s"`.
- `idleTTL` ends a session that has not been used for that long. `"0"`, the
  default, sets no idle limit.
- `absoluteTTL` ends a session that long after sign-in, used or not. `"0"`
  sets no limit. Omitted, it is the `cookieTTL` in whole seconds, so by
  default a session does not outlive its cookie. That is the default only:
  an `absoluteTTL` longer than the `cookieTTL`, or `"0"`, keeps the session
  valid on the server after the browser has dropped the cookie.

A negative value, or one too large for a Go duration, is refused at start.
Sessions are held in memory, so a restart still signs everyone out. A user
holds at most 50 sessions: the 51st sign-in ends the oldest. Once an hour the
server drops expired sessions, authorization codes, revocations and reset
links. At start it logs the effective limits, and warns for each client whose
tokens (its `tokenTTL`, or 24 hours) outlive `absoluteTTL`: ending a session
does not revoke the tokens issued during it.

> Upgrading: a session used to last until a restart, sign-out, or a password
> change or deletion of its user. It now also ends `absoluteTTL` after
> sign-in, by default when its 7-day cookie expires. `"absoluteTTL": "0"`
> keeps the previous behavior.

## Seeding the user database

With `users.createIfMissing: true`, the IdP writes `users.users` to
`users.filePath` at startup **only if the file does not exist**. An existing
database is never reseeded, so accounts added or edited via the admin panel
survive restarts and upgrades; conversely, an entry added to the list later
reaches new deployments only.

With `users.updateSeedPasswords: true`, the configuration owns the seed users'
passwords. At every start, a seed user whose password hash differs from its
configured hash gets the configured one, so a deployment can reset a seeded
password through its configuration. A password changed in the IdP lasts until
the next start. Leave the option off when the hash is regenerated at every
deploy, because every deploy would reset the password. An empty configured hash
is not applied, and a seed user deleted from the database is not recreated.
The option needs `users.filePath` and `users.createIfMissing: true` and cannot
be combined with `users.static`; the server refuses to start otherwise.

> Upgrading: a configuration with `users.updateSeedPasswords: true` but without
> `users.createIfMissing: true` or `users.filePath`, or with `users.static`,
> used to start and silently skip the seed passwords, leaving the previous
> password valid. It now refuses to start. Set `createIfMissing` (an existing
> database is never reseeded) or remove the option before upgrading.

```json
"users": {
    "filePath": "/users/users.json",
    "createIfMissing": true,
    "userAdminGroup": "admin",
    "users": [
        { "Username": "admin", "Password": "$2y$10$…", "Groups": ["admin"], "Email": "admin@example.com" }
    ]
}
```

`Password` must already be an argon2id or bcrypt hash — the value is stored as
given. `ID` is optional (a ULID is generated). Duplicate usernames or ids are
rejected before anything is written.

## Identities

These rules apply when an account is created, through `/register` or the admin
panel:

- Leading and trailing whitespace is removed from the username and the email.
  A username that is empty after that is refused, and so is an email made only
  of whitespace.
- A username or email containing a control character is refused, and so is a
  username, email or group that is not valid UTF-8.
- A username or email that differs from an existing one only in letter case is
  a duplicate: `Alice` is refused when `alice` exists.
- An account created by an admin may have no email; an empty email never
  collides with another. The public registration form requires one.

Existing accounts are not checked against these rules. A database holding both
`alice` and `Alice` keeps loading, and login, seed users and loading match a
username byte for byte. The duplicate check does trim the existing names: an
older account named `" alice "` blocks a new `alice` or `Alice`.

The email is what the registrant typed. The IdP does not verify it and emits no
`email_verified` claim, so it is no proof that the user controls the mailbox. A
relying party should link an account by the token's issuer and subject (`iss`
and `sub`), not by its email.

## How the user database is written

Each change is written to a new owner-only (`0600`) file in the directory of
`users.filePath`, flushed to disk and renamed over the database; the running
IdP uses the change only after that. If anything fails before the rename, the
change is dropped: the file and the running IdP keep the previous state and the
request fails with "could not save the user database". After a successful
rename a normal restart loads the new file. The IdP then syncs the directory;
if that fails it logs a warning and keeps the change, but whether the change
survives a crash or power loss is uncertain.

## Hardening

### Failed sign-ins

Five failed sign-ins for one username within 10 minutes put that username in
cooldown: for 10 seconds every sign-in attempt for it, the right password
included, gets the same "Invalid username or password" page with a
`Retry-After` header, and the password is not checked. Each failure after a
cooldown doubles it, up to 30 seconds; a successful sign-in clears the count.
The count is kept in memory per username, for at most 10,000 usernames (the
least recently failed is dropped first), so a restart clears it.

This is a trade-off: someone who knows a username can keep that account in
cooldown for as long as they keep failing to sign in to it. The account's
owner recovers by waiting until the attempts stop. A new password set by an
admin (`/admin`) or through a reset link also clears the count, though
continued attempts put the username back in cooldown.

A confidential client is not throttled: a wrong `client_secret` at `/token`
or `/revoke` is counted and logged as a warning, at most once a minute per
client with the count, and the client is otherwise unaffected. The secret's
length is what bounds a guesser, so the server warns at start for a
`clientSecret` under 16 characters; use a long random one.

## Releases

The container image `ghcr.io/axoflow/axoflow-idp` (linux/amd64 and
linux/arm64) is built by `.github/workflows/image-build.yaml`, which both
`ci.yaml` and `release.yaml` call:

- Its `build` job runs for every caller with a read-only token. It builds the
  image without pushing it, scans it with Trivy and uploads the SARIF. The scan
  is a report: findings do not fail the job. It examines this prepublication
  build; the published image is rebuilt from the layer cache by `publish`, so
  the scan is not a verified scan of the signed image.
- Its `publish` job runs only when the caller publishes, after `build`, in the
  `release` environment, and is the only job with `packages: write` and
  `id-token: write`. It rebuilds the image from the layer cache, pushes it and
  signs every tag keyless with cosign (GitHub OIDC, recorded in Rekor).

Publishing happens on a push to `main` (tags `main` and `latest`), to a
`release-X.Y…` branch (the branch name), and of a tag `X.Y.Z…` (the tag).
Pull requests and manual runs build and scan only. In both workflows the image
build needs `test`, `e2e`, `lint` and `license-check` to pass first.

To verify a published image:

```sh
cosign verify ghcr.io/axoflow/axoflow-idp:1.2.3 \
  --certificate-identity https://github.com/axoflow/axoflow-idp/.github/workflows/image-build.yaml@refs/tags/1.2.3 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The signature shows which workflow and ref built the image, not who approved
it. The checks above are a quality gate: whoever can push a matching tag or
`release-*` branch still chooses the code and the workflow that run. Who may
publish is decided by repository settings, which the owner must configure:

- A tag ruleset on the release tag pattern and a branch ruleset on `release-*`
  that restrict creation, update and deletion to the release team, with no
  other bypass actors.
- Protection rules on the `release` environment: the release team as required
  reviewers, self-review prevented, and deployments limited to `main`,
  `release-*` and the release tags. A push to `main` publishes too, so it then
  waits for that approval.

An environment without protection rules approves nothing, so until these
settings exist anyone with push access can publish a signed image.

## Contributing

If you find this project useful, help us:

- Support the development of this project and star this repo! :star:
- Help new users with issues they may encounter. :muscle:
- Send a pull request with your new features and bug fixes. :rocket:

## License

The project is licensed under the [Apache 2.0 License](LICENSE).
