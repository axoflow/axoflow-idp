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

## Seeding the user database

With `users.createIfMissing: true`, the IdP writes `users.users` to
`users.filePath` at startup **only if the file does not exist**. An existing
database is never reseeded, so accounts added or edited via the admin panel
survive restarts and upgrades; conversely, an entry added to the list later
reaches new deployments only.

With `users.updateSeedPasswords: true`, a seed user's `Password` is the
exception. When its configured hash changes, the next start sets the new hash
on the existing account, so a deployment can reset a seeded password through
its configuration. A password changed in the IdP stays until the configured
hash changes again. The IdP compares hashes, not passwords: a new salt for the
same password counts as a change, so leave the option off when the hash is
regenerated at every deploy.

The IdP keeps a SHA-256 digest of the hash it last applied on the account
(`SeedDigest`). An account seeded before the digest existed gets the digest of
the current hash and keeps its password. An empty configured hash is not
applied, and a seed user deleted from the database is not recreated.

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
