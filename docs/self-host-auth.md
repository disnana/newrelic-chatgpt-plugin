# Self-host authentication boundary

The default authentication mode remains `sites`. It preserves the existing ChatGPT Sites identity-header behavior and is intended only for an owner-only Site created by that platform.

The optional `signed_proxy` mode is a verifier for an operator-provided authentication gateway. The repository also includes a separate [gateway boundary reference](../examples/self-host-gateway/README.md) and synthetic tests, but that reference is not a login service, OIDC gateway, or complete multi-user hosting product. Its browser/MCP authentication and CSRF adapters are operator-supplied and intentionally non-deployable placeholders. It does not validate users from a browser cookie by itself. Do not expose the Worker directly as a public multi-user service.

## Gateway contract

Put the Worker behind a trusted HTTPS gateway and make the Worker unreachable except through that gateway. The operator's gateway must:

- authenticate each browser session and each MCP caller before forwarding requests;
- remove caller-supplied `Authorization` and `oai-authenticated-user-id` headers, then create a fresh short-lived RS256 assertion for the authenticated principal;
- use a private signing key held only by the gateway, and never log, cache, or disclose assertions;
- set `NEW_RELIC_AUTH_ALLOWED_ORIGIN` to the external HTTPS origin. MCP-generated browser links use this configured origin, not an internal hostname passed through by a reverse proxy;
- preserve the same stable subject on `/oauth/start`, `/oauth/complete`, and `/api/oauth/manual-complete`. The current New Relic flow returns to a random localhost URL and the user pastes that callback URL into the Site completion page; the gateway must re-authenticate that browser session and inject a new assertion when the completion form is submitted. The Worker deliberately does not allow an unauthenticated completion;
- enforce its own browser-session CSRF protections and avoid injecting assertions into cross-site requests;
- apply CSRF checks to every `/api/*` request and both OAuth start/callback routes, including side-effecting GET requests such as `/oauth/start` and `/api/accounts`; checking only POST is insufficient;
- authenticate `/mcp` separately from browser sessions, return a machine-readable Bearer `401` rather than redirecting MCP clients to browser login, and provide standards-compliant MCP OAuth metadata/token issuance if the deployment needs it;
- block direct access to the Worker, use TLS, and protect the signing key and user-to-subject mapping.

The reference wrapper under `examples/self-host-gateway/` enforces a route/method allowlist, strips caller identity/forwarding headers and cookies, signs 60-second assertions, requires an operator CSRF verifier for browser API/OAuth routes, does not follow redirects, and forwards only through an injected private service binding. Only authenticated top-level cross-site GET document navigations to read-only landing/help pages are allowed, so entry from ChatGPT can load the page; cross-site `/api/*` and `/oauth/start` requests remain blocked. In `signed_proxy` mode the `connect_new_relic` MCP tool now points to that landing page with the chosen region in a non-authoritative query hint; the user must still click the same-origin connection button to start OAuth. Its fake adapters are test-only; its placeholder adapters return no authenticated principal. The module does not implement browser login/session establishment, MCP bearer issuance or introspection, account provisioning, or key rotation. A generic Bearer challenge is not OAuth discovery.

The Worker verifies a pinned base64url-encoded SPKI public key, exact issuer and audience, optional key ID, RS256 signature, an allowlisted subject, `iat`/`exp`, and optional `nbf`. Assertions may be at most 15 minutes long; the verifier allows at most 30 seconds of clock skew. It does not fetch JWKS URLs or trust keys supplied in a token. Configurations that are absent or invalid fail closed. The subject is namespaced and hashed before it becomes a D1 user ID.

Configure these Worker variables only after the gateway is built and reviewed:

- `NEW_RELIC_AUTH_MODE=signed_proxy`
- `NEW_RELIC_AUTH_JWT_PUBLIC_KEY`: base64url-encoded SPKI public key; never place the private key here
- `NEW_RELIC_AUTH_JWT_KID`: expected key ID (recommended)
- `NEW_RELIC_AUTH_ISSUER` and `NEW_RELIC_AUTH_AUDIENCE`: exact values emitted by the gateway
- `NEW_RELIC_AUTH_ALLOWED_SUBJECTS`: JSON array of stable subject strings, up to 100 entries
- `NEW_RELIC_AUTH_ALLOWED_ORIGIN`: one exact HTTPS origin for browser-facing requests, such as `https://monitor.example.com`

Static `/`, `/health`, and `/oauth/complete` responses are not login endpoints; the external gateway must still enforce its browser access policy. Authenticated API and MCP calls require an assertion; browser mutations require the configured Origin and the external gateway's own CSRF proof. `/oauth/callback` is an alternate callback route, but it is not used by the current localhost-paste flow. If an installation uses it, the gateway must issue a new assertion for the same subject as `/oauth/start`. The assertion is not a New Relic credential and never substitutes for New Relic OAuth.

## Compatibility and migration

Leaving `NEW_RELIC_AUTH_MODE` unset or setting it to `sites` preserves the existing behavior and requires no D1 migration. An explicitly blank or unknown value is invalid and does not fall back to Sites identity. Switching an installation from `sites` to `signed_proxy` intentionally changes the namespaced user identifier. Existing D1 connection rows are not migrated or deleted, and users will need to reconnect. This avoids silently mapping a new gateway principal onto an older Sites identity. Plan the transition with a backup and a separate retention/deletion review for old rows.

No auth mode switch, identity provider, key, D1 row, or production setting was changed for this implementation. Local tests use synthetic RSA keys, synthetic subjects, fake auth adapters, and a fake private backend only. The gateway reference is not configured or deployed. A real gateway, browser login, OAuth redirect loop, MCP OAuth issuance, multiple real users, and production deployment remain unverified. Until those are implemented, tested, and independently reviewed, continue using the owner-only Sites mode.
