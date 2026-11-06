# Self-host authentication boundary

The default authentication mode remains `sites`. It preserves the existing ChatGPT Sites identity-header behavior and is intended only for an owner-only Site created by that platform.

The optional `signed_proxy` mode is a verifier for an operator-provided authentication gateway. It is not a login service, OIDC gateway, reverse proxy, or general-purpose multi-user hosting product. It does not validate users from a browser cookie by itself. Do not expose the Worker directly as a public multi-user service.

## Gateway contract

Put the Worker behind a trusted HTTPS gateway and make the Worker unreachable except through that gateway. The gateway must:

- authenticate each browser session and each MCP caller before forwarding requests;
- remove caller-supplied `Authorization` and `oai-authenticated-user-id` headers, then create a fresh short-lived RS256 assertion for the authenticated principal;
- use a private signing key held only by the gateway, and never log, cache, or disclose assertions;
- set `NEW_RELIC_AUTH_ALLOWED_ORIGIN` to the external HTTPS origin. MCP-generated browser links use this configured origin, not an internal hostname passed through by a reverse proxy;
- preserve the same stable subject on `/oauth/start`, `/oauth/complete`, and `/api/oauth/manual-complete`. The current New Relic flow returns to a random localhost URL and the user pastes that callback URL into the Site completion page; the gateway must re-authenticate that browser session and inject a new assertion when the completion form is submitted. The Worker deliberately does not allow an unauthenticated completion;
- enforce its own browser-session CSRF protections and avoid injecting assertions into cross-site requests;
- block direct access to the Worker, use TLS, and protect the signing key and user-to-subject mapping.

The Worker verifies a pinned base64url-encoded SPKI public key, exact issuer and audience, optional key ID, RS256 signature, an allowlisted subject, `iat`/`exp`, and optional `nbf`. Assertions may be at most 15 minutes long; the verifier allows at most 30 seconds of clock skew. It does not fetch JWKS URLs or trust keys supplied in a token. Configurations that are absent or invalid fail closed. The subject is namespaced and hashed before it becomes a D1 user ID.

Configure these Worker variables only after the gateway is built and reviewed:

- `NEW_RELIC_AUTH_MODE=signed_proxy`
- `NEW_RELIC_AUTH_JWT_PUBLIC_KEY`: base64url-encoded SPKI public key; never place the private key here
- `NEW_RELIC_AUTH_JWT_KID`: expected key ID (recommended)
- `NEW_RELIC_AUTH_ISSUER` and `NEW_RELIC_AUTH_AUDIENCE`: exact values emitted by the gateway
- `NEW_RELIC_AUTH_ALLOWED_SUBJECTS`: JSON array of stable subject strings, up to 100 entries
- `NEW_RELIC_AUTH_ALLOWED_ORIGIN`: one exact HTTPS origin for browser-facing requests, such as `https://monitor.example.com`

Static `/`, `/health`, and `/oauth/complete` responses are not login endpoints; the external gateway must still enforce its browser access policy. Authenticated API and MCP calls require an assertion; browser mutations require the configured Origin. `/oauth/callback` is an alternate callback route, but it is not used by the current localhost-paste flow. If an installation uses it, the gateway must issue a new assertion for the same subject as `/oauth/start`. The assertion is not a New Relic credential and never substitutes for New Relic OAuth.

## Compatibility and migration

Leaving `NEW_RELIC_AUTH_MODE` unset or setting it to `sites` preserves the existing behavior and requires no D1 migration. Switching an installation from `sites` to `signed_proxy` intentionally changes the namespaced user identifier. Existing D1 connection rows are not migrated or deleted, and users will need to reconnect. This avoids silently mapping a new gateway principal onto an older Sites identity. Plan the transition with a backup and a separate retention/deletion review for old rows.

No auth mode switch, gateway, identity provider, key, D1 row, or production setting was changed for this implementation. Local tests use synthetic RSA keys and synthetic subjects only. A real gateway, browser login, OAuth redirect loop, multiple real users, and production deployment remain unverified. Until those are tested and independently reviewed, continue using the owner-only Sites mode.
