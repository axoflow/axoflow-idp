# Axoflow-IdP

A lightweight OpenID Connect (OIDC) Identity Provider, designed to work seamlessly with Axoflow.

## Overview

Axoflow-IdP is a simple yet feature-rich OIDC provider that enables authentication for your applications. It supports multiple clients, user self-registration, administrative user management, and JWT-based token signing. The provider implements standard OIDC endpoints including authorization (with PKCE), token exchange, revocation, and JWKS discovery.

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

## Contributing

If you find this project useful, help us:

- Support the development of this project and star this repo! :star:
- Help new users with issues they may encounter. :muscle:
- Send a pull request with your new features and bug fixes. :rocket:

## License

The project is licensed under the [Apache 2.0 License](LICENSE).
