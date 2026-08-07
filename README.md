# Axoflow-IdP

A lightweight OpenID Connect (OIDC) Identity Provider, designed to work seamlessly with Axoflow.

## Overview

Axoflow-IdP is a simple yet feature-rich OIDC provider that enables authentication for your applications. It supports multiple clients, user self-registration, administrative user management, JWT-based token signing, and optional rotating refresh tokens. The provider implements standard OIDC endpoints including authorization, token exchange, refresh, revocation, and JWKS discovery.

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

> `redirect_uri` is matched by **exact string comparison** against a client's
> registered URIs at both `/oidc/auth` and `/token`. Register additional
> callbacks with a `redirectUris` array alongside (or instead of) the singular
> `redirectUri`; any request whose `redirect_uri` is not an exact match is
> rejected.

## PKCE

The authorization-code flow supports **PKCE** (RFC 7636) with the **S256**
method. It works automatically for any client that sends a
`code_challenge` (+ `code_challenge_method=S256`) at `/oidc/auth` and the
matching `code_verifier` at `/token`; `plain` and an omitted method are
rejected. Discovery advertises `code_challenge_methods_supported: ["S256"]`.

To *require* PKCE for a client (so a request without a `code_challenge` is
rejected — the defence against challenge-stripping), set `requirePKCE` on
that client:

```json
{ "id": "your-client-id", "redirectUri": "…", "clientSecret": "…", "requirePKCE": true }
```

Clients without `requirePKCE` keep working with or without PKCE.

## Refresh tokens

Refresh tokens are **off by default**. To enable them, add a top-level
`refresh` block and mark each client that may receive them with
`allowOfflineAccess` (such a client **must** have a `clientSecret`):

```json
{
    "baseUrl": "http://localhost:8080",
    "clients": [
        {
            "id": "your-client-id",
            "redirectUri": "http://localhost:3000/callback",
            "clientSecret": "a-strong-secret",
            "allowOfflineAccess": true
        }
    ],
    "refresh": {},
    "signingKey": { "generateIfMissing": true }
}
```

An empty `refresh: {}` uses the defaults: a sliding **idle** lifetime of
168h capped by an **absolute** family lifetime of 720h, and a 10s
reuse-leeway window (override with `idleTTL`, `absoluteTTL`,
`reuseLeeway`, all in nanoseconds). When refresh is enabled the id_token
lifetime defaults to 15m (24h otherwise); override with `idTokenTTL`.

Behaviour:

- A refresh token is issued from `/token` only when the client requested
  the `offline_access` scope **and** it is an `allowOfflineAccess`
  client. Discovery then advertises `refresh_token` in
  `grant_types_supported` and `offline_access` in `scopes_supported`.
- Tokens are **opaque, server-side, and rotating**: every
  `grant_type=refresh_token` exchange returns a new refresh token and
  invalidates the old one. Replaying an already-used token revokes the
  entire token family (reuse detection per the OAuth 2.0 Security BCP).
- `/revoke` on a refresh token kills its whole family. A password change,
  an admin password reset, and a reset-link `set-password` all revoke
  every one of the user's refresh tokens (a deleted user is cut off on
  the next exchange).
- Consent is **pre-established** per client via `allowOfflineAccess`
  (no consent screen — a documented deviation from OIDC Core §11), and
  offline sessions survive logout by design.
- State is **in-memory**: a restart invalidates all refresh tokens, and
  running multiple replicas without shared storage is not supported.

## Contributing

If you find this project useful, help us:

- Support the development of this project and star this repo! :star:
- Help new users with issues they may encounter. :muscle:
- Send a pull request with your new features and bug fixes. :rocket:

## License

The project is licensed under the [Apache 2.0 License](LICENSE).
