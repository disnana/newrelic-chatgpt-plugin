# Self-host gateway reference (v0.4.0)

This is a **gateway boundary example**, not a complete self-host login product. It does not include an identity provider, browser login/logout/session store, OAuth authorization server for MCP clients, user provisioning, subject mapping, key rotation service, or deployment configuration. Use it only as a code reference after selecting and independently reviewing those pieces.

The reference authenticates browser and MCP requests through two separate operator-supplied adapters, runs a separate CSRF verifier for browser routes with side effects, signs a short-lived RS256 assertion, and forwards to an operator-configured private application service. It never discovers a backend URL from a request. Missing or invalid adapters, key material, issuer, audience, origin, or subject list prevent the handler from being constructed.

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

The snippet is intentionally non-deployable until the operator replaces both auth adapter bodies and the CSRF verifier with real server-side implementations. `authenticateBrowser` receives a narrow metadata object with the browser cookie and fetch/origin headers. `authenticateMcp` receives only URL, method, and the Authorization header. It cannot inspect or fall back to browser cookies. Both adapters must return a plain object `{ subject: "stable-id" }`; the browser adapter may additionally return an opaque `csrfContext` used only by the CSRF verifier. Subjects must be stable, non-email identifiers and must appear in both gateway and Worker subject allowlists.

The signing key must be an RSA private key with at least 2048-bit modulus. Keep its base64url-encoded PKCS#8 bytes in the platform secret manager, never in a checked-in file, client bundle, URL, or log. Put only the corresponding public SPKI key in the Worker's pinned public-key setting. This reference currently has one pinned verifier key; coordinate rotation as an operator maintenance window. The gateway issues 60-second assertions (`RS256`, exact issuer/audience, subject, `iat`, `exp`, random `jti`). The Worker must remain unreachable except through the private backend binding.

## Security behavior and limits

- Requires HTTPS and the exact configured external host. Only known Worker routes and methods are forwarded. Route, authentication, origin, and CSRF rejections happen before the backend call; an invalid response from the backend can only be rejected after that single call.
- `/mcp` is a separate machine-auth path. Browser cookies are not passed to the MCP adapter, missing MCP credentials return JSON `401` with `WWW-Authenticate: Bearer`, and no browser-login redirect or OAuth discovery is provided.
- `/api/*`, `/oauth/start`, and `/oauth/callback` require the operator's browser CSRF verifier. This includes GETs that can contact New Relic, rotate credentials, or change local state. Cross-site fetches and cross-site OAuth/API requests are rejected before auth. To support the existing connect link when a user enters from ChatGPT, only authenticated top-level GET document navigation to `/`, `/health`, or `/oauth/complete` is allowed cross-site; it cannot invoke any API or OAuth start action. Continue from the loaded Site so `/oauth/start` is same-origin, and have the operator verifier handle browsers without fetch metadata and bind CSRF proof to the authenticated session.
- The gateway strips caller-provided Authorization, cookies, Sites identity, forwarding, and other unapproved headers before forwarding. It constructs a 60-second assertion and sends only an explicit header allowlist to the private service.
- Request URLs are limited to 8 KiB, request/response headers to 16 KiB and 64 fields; MCP request bodies are limited to 16 KiB; manual OAuth completion and account selection to 8 KiB; disconnect bodies to 1 KiB. Responses are buffered up to 2 MiB so the exact assertion can be rejected if echoed in a header/body. The example is not a general streaming reverse proxy.
- Redirects are never followed. Same-origin redirects are returned; the New Relic OAuth authorization endpoint is allowed only from `/oauth/start`. Unexpected redirects are rejected.
- Cookies and CORS allow headers are removed from backend responses; only an explicit response-header allowlist is returned. Backend errors are replaced with generic gateway errors.
- This module does not protect a publicly reachable Worker origin. Network isolation/private service binding is mandatory. It cannot itself verify that the upstream adapters honor their contract.
- The worker's direct MCP 401 response is still not an OAuth authorization server. This wrapper adds only a generic Bearer challenge; a real ChatGPT MCP client integration still needs an operator-approved OAuth issuer/client registration, resource metadata, and audience/subject mapping.

## Tests

Run `node scripts/test-self-host-gateway.mjs` after `npm run build`. It uses synthetic RSA keys, subjects, sessions, and MCP tokens, an injected fake private backend, and one local gateway-to-bundled-Worker ping test. It makes no network or New Relic calls and does not validate a real identity provider, New Relic OAuth, MCP deployment, service binding isolation, or production key custody.

Do not set `NEW_RELIC_AUTH_MODE=signed_proxy` on a production deployment solely because this reference exists. Use the existing owner-only Sites mode until the operator has implemented the adapters, CSRF/session lifecycle, MCP client authorization, private routing, and key management, then run a separate security review and deployment-specific tests.
