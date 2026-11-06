# Self-host gateway reference (v0.4.0)

This is a **gateway boundary example**, not a complete self-host product. It includes an optional D1-backed browser session/CSRF adapter and an optional generic OIDC browser-login adapter. It still does not provide an MCP OAuth authorization server, automatic user provisioning, dynamic identity discovery, key-rotation service, or deployment configuration. The login path is opt-in and requires the operator to configure a trusted issuer, endpoints, client, encryption key, exact subject allowlist, private D1, and private Worker service binding.

The reference can authenticate browser requests through its optional OIDC adapter and always requires a separate operator-supplied MCP bearer adapter. It runs a separate CSRF verifier for browser routes with side effects, signs a short-lived RS256 assertion, and forwards to an operator-configured private application service. It never discovers a backend URL from a request. Missing or invalid adapters, key material, issuer, audience, origin, or subject list prevent the handler from being constructed.

## Optional generic OIDC browser login

`oidc-login.mjs` implements an opt-in OpenID Connect Authorization Code flow for browser sessions. It is an example adapter, not a production identity product. It uses fixed operator-supplied HTTPS issuer, authorization, token, and JWKS URLs; it does not perform dynamic discovery. Every endpoint origin must appear in the explicit operator allowlist. The client secret and a non-extractable 256-bit AES-GCM key for temporary flow state must come from the gateway secret manager. Do not use the New Relic token-encryption key for OIDC state. Construction also requires a trusted `admitLoginStart(request)` adapter; without it the login adapter fails closed.

Apply `0002_oidc_login_attempts.sql` only to the private gateway `AUTH_DB`, after `0001_browser_sessions.sql`. The table stores a one-time state hash and an encrypted PKCE verifier/nonce. A successful callback consumes the state with a conditional update and clears the encrypted verifier before calling the token endpoint. Stale rows may be removed with `purgeExpiredAttempts()` in bounded batches of 100; login start also attempts one bounded cleanup. New pending flows are capped at 1,000. No cleanup schedule is configured by this example. The cap is not an abuse control: the required admission adapter must enforce atomic per-client and global rate limits before state is created, and fail closed on its own errors. It must derive client identity only from a trusted ingress that strips caller-supplied forwarding headers; never trust raw `X-Forwarded-For` or other client-controlled identifiers. This generic module cannot identify a trusted remote client by itself.

The flow requires top-level navigation, sends `scope=openid`, uses S256 PKCE, binds the callback to both a Secure/HttpOnly/Lax state cookie and a D1 single-use state, and validates the ID Token's RS256 signature against the configured JWKS URI, exact issuer, audience/authorized party, expiry/issued-at, nonce, and stable subject. Token and JWKS requests do not follow redirects, each has a 10-second default timeout (operator-configurable up to 30 seconds), and each response is limited to 64 KiB. Provider errors are not reflected to the browser. The access token and refresh token in the token response are ignored and not persisted. Only an allowlisted subject hash can create a browser session. The gateway's `allowedSubjects` and Worker's `NEW_RELIC_AUTH_ALLOWED_SUBJECTS` must contain the same mapped subject. `mapOidcSubject(issuer, sub)` computes the stable `oidc:<sha256>` mapping for a trusted operator enrollment workflow; the adapter does not disclose unknown subjects or auto-enroll users. Because the callback uses query response mode, configure gateway/proxy logs to redact `/auth/callback` query strings and never log cookies, authorization codes, ID Tokens, or client credentials.

Minimal wiring, with all values read from the operator's own secret/configuration store:

```js
import { createD1BrowserSessionAdapter } from "./browser-session.mjs";
import { createOidcBrowserLogin, importOidcStateEncryptionKey } from "./oidc-login.mjs";

const browserSessions = createD1BrowserSessionAdapter({
  db: env.AUTH_DB,
  externalOrigin: env.EXTERNAL_ORIGIN,
});
const browserLogin = createOidcBrowserLogin({
  db: env.AUTH_DB,
  sessions: browserSessions,
  externalOrigin: env.EXTERNAL_ORIGIN,
  issuer: env.OIDC_ISSUER,
  authorizationEndpoint: env.OIDC_AUTHORIZATION_ENDPOINT,
  tokenEndpoint: env.OIDC_TOKEN_ENDPOINT,
  jwksUri: env.OIDC_JWKS_URI,
  allowedEndpointOrigins: JSON.parse(env.OIDC_TRUSTED_ENDPOINT_ORIGINS),
  clientId: env.OIDC_CLIENT_ID,
  clientSecret: env.OIDC_CLIENT_SECRET,
  tokenEndpointAuthMethod: env.OIDC_CLIENT_AUTH_METHOD || "client_secret_post",
  allowedSubjects: JSON.parse(env.OIDC_ALLOWED_SUBJECT_HASHES),
  // Operator-provided rate limiter backed by a trusted ingress identity.
  // It must atomically enforce per-client and global limits, and fail closed.
  admitLoginStart: request => env.LOGIN_ADMISSION.admit(request),
  stateEncryptionKey: await importOidcStateEncryptionKey(env.OIDC_STATE_KEY_BASE64URL),
});
const gateway = createSelfHostGateway({
  // Other signing, MCP, CSRF, audience, allowlist, and private backend options.
  browserLogin,
  authenticateBrowser: browserSessions.authenticateBrowser,
  verifyBrowserCsrf: browserSessions.verifyBrowserCsrf,
});
```

The gateway serves a static `/login` page and redirects unauthenticated `/` navigation there. The login page does not disclose account data; the user must click a same-origin sign-in link before an authorization request starts. After the callback, `/auth/complete` shows only a non-sensitive completion page with a same-origin Continue link. This intermediate step is required because browsers can keep Fetch Metadata marked cross-site across the IdP redirect chain; the authenticated home page is not served on that cross-site request. Callback mode is `query` for the Lax state cookie. A same-origin CSRF-protected `POST /auth/logout` revokes only the current browser session and preserves the stored New Relic connection. Show the Worker page's logout control only after the route is deployed and CSRF-tested, by setting `NEW_RELIC_AUTH_GATEWAY_LOGOUT_ENABLED=true`; it defaults off. This reference supports `client_secret_post` (default) and `client_secret_basic` token endpoint authentication. Register the exact `https://<external-host>/auth/callback` URL at the identity provider. OIDC browser login only establishes the browser session; it does not provide machine-client OAuth, MCP bearer issuance, or New Relic access by itself.

Tests use synthetic RSA keys, a fake IdP/token endpoint, and isolated SQLite. They do not verify a real issuer, discovery metadata, client registration, JWKS rotation, browser compatibility, or production session security. Independently review the selected provider's endpoints, client policy, stable-subject mapping, secrets, and deployment before use.

## Optional browser session adapter

`browser-session.mjs` supplies the gateway's `authenticateBrowser` and `verifyBrowserCsrf` callbacks after a trusted operator login callback has established the identity. It does **not** authenticate an OIDC response, start a login flow, or expose a route that accepts an arbitrary subject. Apply `0001_browser_sessions.sql` only to a private gateway `AUTH_DB`; it is separate from the New Relic app's six migrations and must never be applied to the production Site database.

```js
import { createD1BrowserSessionAdapter } from "./browser-session.mjs";

const browserSessions = createD1BrowserSessionAdapter({
  db: env.AUTH_DB,
  externalOrigin: "https://monitor.example.com",
});

const gateway = createSelfHostGateway({
  // Keep the existing private gateway options and the separate MCP adapter.
  authenticateBrowser: browserSessions.authenticateBrowser,
  verifyBrowserCsrf: browserSessions.verifyBrowserCsrf,
  // ...
});
```

Only after an operator-selected identity provider has fully verified its callback, issuer, audience, signature, state, nonce and PKCE should that trusted callback call `createBrowserSession({ subject: stableIssuerAndSubjectMapping })`. Return both values in `setCookieHeaders` as separate `Set-Cookie` response headers over HTTPS; never log or place them in URLs. The session cookie is `Secure`, `HttpOnly`, `__Host-`, `SameSite=Lax`; the independent readable CSRF cookie is `Secure`, `__Host-`, and `SameSite=Strict`. The browser pages copy the CSRF cookie into `x-csrf-token` on same-origin API fetches, including the localhost-paste New Relic OAuth completion form. `/oauth/start` is accepted only as a same-origin top-level document navigation with Fetch Metadata; missing required evidence fails closed. The adapter rejects cross-site navigation to `/oauth/callback`; the localhost-paste flow is the supported New Relic callback path, while a direct callback needs a separate provider-state-bound handler and is not implemented. Use `revokeBrowserSession` from a separately protected logout route, clear both cookies, and call `purgeExpiredSessions` from an operator-configured retention job if desired. Each cleanup call deletes at most 100 rows across revoked and expired sessions. No cleanup schedule is installed by this example.

The module stores only hashes of the session cookie and CSRF token. Its random stable `sessionId` is distinct from the cookie and is signed into browser-only approval assertions; a fresh login rotates it. The store keeps the stable mapped subject for authorization. The login route, provider-specific callback validation, subject allowlist, browser redirects, external client secrets, `AUTH_DB` binding and logout CSRF enforcement remain operator inputs and require deployment-specific review.

## Integration contract

```js
import { createSelfHostGateway, importGatewaySigningKey } from "./gateway.mjs";

// `AUTH` and `NEW_RELIC_APP` are private service bindings implemented by the
// deployment operator. The example intentionally does not implement them.
const gateway = createSelfHostGateway({
  externalOrigin: "https://monitor.example.com",
  issuer: "https://auth.example.com/",
  audience: "newrelic-chatgpt-mcp",
  keyId: "gateway-rs256-2026-01",
  allowedSubjects: ["stable-subject-id"], // mirror the Worker's allowlist
  signingKey: await importGatewaySigningKey(env.GATEWAY_SIGNING_KEY_PKCS8_BASE64URL),
  authenticateBrowser: async ({ cookie, url, method }) => {
    // Ask the operator's session service. Return a stable canonical subject
    // and an opaque session-bound csrfContext, or null. Do not log the cookie.
    return null; // intentionally fail closed until an operator implements this
  },
  authenticateMcp: async ({ authorization, url, method }) => {
    // Validate a machine bearer credential independently of browser cookies.
    // Return the same stable subject namespace, or null. Never log the token.
    return null; // intentionally fail closed until an operator implements this
  },
  verifyBrowserCsrf: async ({ request, subject, context, path }) => {
    // Verify the browser session and a CSRF token or strict origin/fetch-metadata
    // proof. This callback is invoked for every /api route and OAuth start/callback,
    // including side-effecting GET requests such as /api/accounts.
    return false; // replace with the operator's reviewed verifier
  },
  backend: env.NEW_RELIC_APP, // must be a private service binding, not a URL
});
```

The snippet is intentionally non-deployable until the operator replaces both auth adapter bodies and the CSRF verifier with real server-side implementations. `authenticateBrowser` receives a narrow metadata object with the browser cookie and fetch/origin headers. `authenticateMcp` receives only URL, method, and the Authorization header. It cannot inspect or fall back to browser cookies. Both adapters must return a plain object `{ subject: "stable-id" }`; the browser adapter may additionally return an opaque `csrfContext` used only by the CSRF verifier. The approval-only routes require an additional `sessionId` field from `authenticateBrowser`, derived from a stable authenticated browser login session and preserved across short-lived assertion renewal. It must rotate on login/logout and must not be the JWT `jti`, token bytes, CSRF context, or subject. Approval assertions contain signed `channel=browser` and `sid` claims; MCP assertions contain `channel=mcp` and no `sid`. The gateway forwards `x-approval-csrf` only on approval routes and continues to withhold browser cookies and `Set-Cookie` from the Worker. Subjects must be stable, non-email identifiers and must appear in both gateway and Worker subject allowlists.

The signing key must be an RSA private key with at least 2048-bit modulus. Keep its base64url-encoded PKCS#8 bytes in the platform secret manager, never in a checked-in file, client bundle, URL, or log. Put only the corresponding public SPKI key in the Worker's pinned public-key setting. This reference currently has one pinned verifier key; coordinate rotation as an operator maintenance window. The gateway issues 60-second assertions (`RS256`, exact issuer/audience, subject, channel, `iat`, `exp`, random `jti`); approval-only browser assertions also contain the stable signed `sid`. The Worker must remain unreachable except through the private backend binding.

## Security behavior and limits

- Requires HTTPS and the exact configured external host. Only known Worker routes and methods are forwarded. Route, authentication, origin, and CSRF rejections happen before the backend call; an invalid response from the backend can only be rejected after that single call.
- `/mcp` is a separate machine-auth path. Browser cookies are not passed to the MCP adapter, missing MCP credentials return JSON `401` with `WWW-Authenticate: Bearer`, and no browser-login redirect or OAuth discovery is provided.
- `/api/*`, `/oauth/start`, and `/oauth/callback` require the operator's browser CSRF verifier. This includes GETs that can contact New Relic, rotate credentials, or change local state. Cross-site fetches and cross-site OAuth/API requests are rejected before auth. Without OIDC browser login, an authenticated top-level GET document navigation to `/`, `/health`, or `/oauth/complete` can enter from ChatGPT; with OIDC enabled, cross-site `/` is redirected to the non-sensitive `/login` page, and the authenticated app is reached only through a fresh same-origin navigation from `/auth/complete`. These routes cannot invoke an API or OAuth start action. Continue from the loaded Site so `/oauth/start` is same-origin, and have the operator verifier handle browsers without fetch metadata and bind CSRF proof to the authenticated session. Operation-approval routes require both this gateway CSRF check and the Worker approval-session proof. They remain disabled unless explicitly enabled, and this release ships neither proposal creation nor provider mutation dispatch.
- The gateway strips caller-provided Authorization, cookies, Sites identity, forwarding, and other unapproved headers before forwarding. It constructs a 60-second assertion and sends only an explicit header allowlist to the private service.
- Request URLs are limited to 8 KiB, request/response headers to 16 KiB and 64 fields; MCP request bodies are limited to 16 KiB; manual OAuth completion and account selection to 8 KiB; disconnect bodies to 1 KiB. Responses are buffered up to 2 MiB so the exact assertion can be rejected if echoed in a header/body. The example is not a general streaming reverse proxy.
- Redirects are never followed. Same-origin redirects are returned; the New Relic OAuth authorization endpoint is allowed only from `/oauth/start`. Unexpected redirects are rejected.
- Cookies and CORS allow headers are removed from backend responses; only an explicit response-header allowlist is returned. Backend errors are replaced with generic gateway errors.
- This module does not protect a publicly reachable Worker origin. Network isolation/private service binding is mandatory. It cannot itself verify that the upstream adapters honor their contract.
- The worker's direct MCP 401 response is still not an OAuth authorization server. This wrapper adds only a generic Bearer challenge; a real ChatGPT MCP client integration still needs an operator-approved OAuth issuer/client registration, resource metadata, and audience/subject mapping.

## Tests

Run `node scripts/test-self-host-gateway.mjs` after `npm run build`. It uses synthetic RSA keys, subjects, sessions, and MCP tokens, an injected fake private backend, and one local gateway-to-bundled-Worker ping test. It makes no network or New Relic calls and does not validate a real identity provider, New Relic OAuth, MCP deployment, service binding isolation, or production key custody.

Do not set `NEW_RELIC_AUTH_MODE=signed_proxy` on a production deployment solely because this reference exists. Use the existing owner-only Sites mode until the operator has implemented the adapters, CSRF/session lifecycle, MCP client authorization, private routing, and key management, then run a separate security review and deployment-specific tests.
