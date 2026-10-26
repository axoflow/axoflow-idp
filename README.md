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
> the maximum token lifetime.

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

## Contributing

If you find this project useful, help us:

- Support the development of this project and star this repo! :star:
- Help new users with issues they may encounter. :muscle:
- Send a pull request with your new features and bug fixes. :rocket:

## License

The project is licensed under the [Apache 2.0 License](LICENSE).
