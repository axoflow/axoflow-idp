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
>
> The one exception is a loopback callback for a native client (RFC 8252 §7.3).
> A registered `http://localhost/...`, `http://127.0.0.1/...` or
> `http://[::1]/...` URI also matches the same URI on any port, because the
> client binds whatever port is free when it runs. Only the port may differ:
> the scheme (`http`), host and escaped path must match exactly, and neither URI
> may carry userinfo, a query or a fragment (not even an empty `?` or `#`).
> Every other callback is still compared exactly.

### Public clients

A client that cannot keep a secret, such as a CLI or an MCP client, is
registered with `"public": true` and no `clientSecret`. It must use the
authorization code flow with a PKCE `S256` challenge (`plain` is refused) and
sends its `code_verifier` instead of a secret at `/token`. The `openid` scope is
optional: without it only an access token is issued. A `resource` parameter
(RFC 8707) becomes the access token's audience; it must be one of the client's
`resources`, and a client without that list may not send one (`invalid_target`).
Without a `resource`, the audience is the client id.

```json
{
    "id": "mcp-cli",
    "name": "MCP CLI",
    "public": true,
    "redirectUris": ["http://127.0.0.1/callback", "http://localhost/callback"],
    "resources": ["https://console.example.com/mcp"]
}
```

A client that is not public must have a `clientSecret`.

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
