const encoder = new TextEncoder();
const MAX_ASSERTION_TTL_SECONDS = 60;
const MAX_BODY_BYTES = 16 * 1024;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_URL_BYTES = 8 * 1024;
const MAX_HEADER_BYTES = 16 * 1024;
const MAX_HEADER_COUNT = 64;
const MAX_ALLOWED_SUBJECTS = 100;
const OAUTH_ORIGIN = "https://oauth2.service.newrelic.com";

const ROUTES = new Map([
  ["/", { methods: ["GET"], kind: "browser", csrf: false }],
  ["/health", { methods: ["GET"], kind: "browser", csrf: false }],
  ["/oauth/start", { methods: ["GET"], kind: "browser", csrf: true }],
  ["/oauth/callback", { methods: ["GET"], kind: "browser", csrf: true }],
  ["/oauth/complete", { methods: ["GET"], kind: "browser", csrf: false }],
  ["/api/status", { methods: ["GET"], kind: "browser", csrf: true }],
  ["/api/capabilities", { methods: ["GET"], kind: "browser", csrf: true }],
  ["/api/accounts", { methods: ["GET"], kind: "browser", csrf: true }],
  ["/api/usage-consent", { methods: ["GET", "POST"], kind: "browser", csrf: true, maxBodyBytes: 1024 }],
  ["/api/oauth/manual-complete", { methods: ["POST"], kind: "browser", csrf: true, maxBodyBytes: 8192 }],
  ["/api/select-account", { methods: ["POST"], kind: "browser", csrf: true, maxBodyBytes: 8192 }],
  ["/api/disconnect", { methods: ["POST"], kind: "browser", csrf: true, maxBodyBytes: 1024 }],
  ["/mcp", { methods: ["POST"], kind: "mcp", csrf: false }],
]);

const FORWARDED_HEADERS = [
  "accept", "content-type", "origin", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
  "mcp-protocol-version", "mcp-session-id", "last-event-id", "cache-control",
];
const RESPONSE_HEADERS = new Set([
  "allow", "content-type", "content-security-policy", "location", "mcp-session-id",
  "referrer-policy", "retry-after", "www-authenticate", "x-content-type-options",
]);

function plain(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

/** @typedef {{subject: string, csrfContext?: unknown}} GatewayPrincipal */
/** @typedef {{url: string, method: string, cookie: string, origin: string|null, secFetchSite: string|null, secFetchMode: string|null, csrfToken: string|null}} BrowserAuthContext */
/** @typedef {{url: string, method: string, authorization: string}} McpAuthContext */
/** @typedef {{externalOrigin: string, issuer: string, audience: string, keyId: string, allowedSubjects: string[], signingKey: CryptoKey, authenticateBrowser: (context: BrowserAuthContext) => GatewayPrincipal|null|Promise<GatewayPrincipal|null>, authenticateMcp: (context: McpAuthContext) => GatewayPrincipal|null|Promise<GatewayPrincipal|null>, verifyBrowserCsrf: (context: {request: BrowserAuthContext, subject: string, context: unknown, path: string}) => boolean|Promise<boolean>, backend: {fetch: (request: Request) => Promise<Response>}, now?: () => number}} GatewayOptions */

/** @param {unknown} value @returns {value is GatewayPrincipal} */
function validPrincipal(value) {
  if (!plain(value)) return false;
  const candidate = /** @type {{subject?: unknown}} */ (value);
  return typeof candidate.subject === "string";
}

function exactHttpsOrigin(value) {
  if (typeof value !== "string" || value.length > 512) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.origin !== value || url.username || url.password
      || url.pathname !== "/" || url.search || url.hash) return null;
    return value;
  } catch { return null; }
}

function secureIssuer(value) {
  if (typeof value !== "string" || !value || value.length > 256) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash;
  } catch { return false; }
}

function validSubjects(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > MAX_ALLOWED_SUBJECTS) return null;
  const result = new Set();
  for (const subject of value) {
    if (typeof subject !== "string" || !subject || subject.length > 256
      || /[\u0000-\u001f\u007f]/.test(subject) || result.has(subject)) return null;
    result.add(subject);
  }
  return result;
}

/** @param {unknown} key @returns {key is CryptoKey} */
function validPrivateKey(key) {
  if (typeof key !== "object" || key === null) return false;
  const candidate = /** @type {CryptoKey} */ (key);
  if (candidate.type !== "private" || candidate.algorithm.name !== "RSASSA-PKCS1-v1_5") return false;
  const algorithm = /** @type {RsaHashedKeyAlgorithm} */ (candidate.algorithm);
  return algorithm.hash.name === "SHA-256"
    && Number.isSafeInteger(algorithm.modulusLength) && algorithm.modulusLength >= 2048 && algorithm.modulusLength <= 4096
    && candidate.usages.includes("sign");
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value) {
  if (typeof value !== "string" || !value || value.length > 16384 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new TypeError("Gateway signing key is not valid base64url PKCS#8 data.");
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  if (bytes.byteLength < 512 || bytes.byteLength > 8192) {
    throw new TypeError("Gateway signing key size is invalid.");
  }
  return bytes;
}

/** Import a private key supplied by the operator's secret manager, never source control. */
export async function importGatewaySigningKey(pkcs8Base64Url) {
  try {
    return await crypto.subtle.importKey(
      "pkcs8", decodeBase64Url(pkcs8Base64Url),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"],
    );
  } catch {
    throw new TypeError("Gateway signing key could not be imported.");
  }
}

function encodeJson(value) {
  return base64Url(encoder.encode(JSON.stringify(value)));
}

function noStoreHeaders(extra = {}) {
  return {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...extra,
  };
}

function jsonError(status, code, extraHeaders = {}) {
  return new Response(JSON.stringify({ error: code }), {
    status,
    headers: noStoreHeaders({
      "content-type": "application/json; charset=utf-8",
      ...(status === 401 ? { "www-authenticate": 'Bearer realm="newrelic-chatgpt-mcp"' } : {}),
      ...extraHeaders,
    }),
  });
}

function errorResponse(status, message, extraHeaders = {}) {
  return new Response(message, { status, headers: noStoreHeaders(extraHeaders) });
}

/** @overload @param {Request} request @param {"mcp"} kind @returns {McpAuthContext} */
/** @overload @param {Request} request @param {"browser"} kind @returns {BrowserAuthContext} */
/** @param {Request} request @param {"mcp"|"browser"} kind @returns {McpAuthContext|BrowserAuthContext} */
function authMetadata(request, kind) {
  const url = new URL(request.url);
  if (kind === "mcp") {
    // This deliberately omits Cookie and every other header. An MCP adapter
    // cannot silently authenticate a machine client from a browser session.
    return Object.freeze({
      url: url.toString(),
      method: request.method,
      authorization: request.headers.get("authorization") || "",
    });
  }
  return Object.freeze({
    url: url.toString(),
    method: request.method,
    cookie: request.headers.get("cookie") || "",
    origin: request.headers.get("origin"),
    secFetchSite: request.headers.get("sec-fetch-site"),
    secFetchMode: request.headers.get("sec-fetch-mode"),
    csrfToken: request.headers.get("x-csrf-token"),
  });
}

function requestOriginIsSafe(request, configuredOrigin, allowSafeDocumentNavigation = false) {
  const origin = request.headers.get("origin");
  const crossSite = request.headers.get("sec-fetch-site") === "cross-site";
  if (crossSite) {
    return allowSafeDocumentNavigation && request.method === "GET"
      && request.headers.get("sec-fetch-mode") === "navigate"
      && request.headers.get("sec-fetch-dest") === "document";
  }
  return !origin || origin === configuredOrigin;
}

function headersWithinBounds(headers) {
  let count = 0;
  let bytes = 0;
  let withinBounds = true;
  headers.forEach((value, name) => {
    if (!withinBounds) return;
    count += 1;
    bytes += encoder.encode(name).byteLength + encoder.encode(value).byteLength + 4;
    if (count > MAX_HEADER_COUNT || bytes > MAX_HEADER_BYTES) withinBounds = false;
  });
  return withinBounds;
}

async function readBody(request, maxBytes) {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > maxBytes)) {
    try { await request.body?.cancel(); } catch { /* no-op */ }
    return { tooLarge: true, body: null };
  }
  if (!request.body) return { tooLarge: false, body: null };
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        return { tooLarge: true, body: null };
      }
      chunks.push(value);
    }
  } catch {
    try { await reader.cancel(); } catch { /* no-op */ }
    return { tooLarge: true, body: null };
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return { tooLarge: false, body };
}

async function signedAssertion({ key, kid, issuer, audience, subject, nowSeconds }) {
  const header = { alg: "RS256", typ: "JWT", kid };
  const claims = {
    iss: issuer,
    aud: audience,
    sub: subject,
    iat: nowSeconds,
    exp: nowSeconds + MAX_ASSERTION_TTL_SECONDS,
    jti: base64Url(crypto.getRandomValues(new Uint8Array(16))),
  };
  const signingInput = encodeJson(header) + "." + encodeJson(claims);
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" }, key, encoder.encode(signingInput),
  );
  return signingInput + "." + base64Url(new Uint8Array(signature));
}

function safeRouteRedirect(requestUrl, pathname, response) {
  if (response.status < 300 || response.status >= 400) return true;
  const location = response.headers.get("location");
  if (!location) return true;
  try {
    const target = new URL(location, requestUrl);
    const request = new URL(requestUrl);
    return target.origin === request.origin
      || pathname === "/oauth/start" && target.origin === OAUTH_ORIGIN && target.pathname === "/oauth2/auth";
  } catch { return false; }
}

async function safeBackendResponse(response, assertion) {
  const sourceHeaders = new Headers(response.headers);
  if (!headersWithinBounds(sourceHeaders)) return null;
  const headers = new Headers();
  let safeHeaders = true;
  sourceHeaders.forEach((value, name) => {
    if (value.includes(assertion)) { safeHeaders = false; return; }
    if (RESPONSE_HEADERS.has(name.toLowerCase())) headers.set(name, value);
  });
  if (!safeHeaders) return null;
  const reader = response.body?.getReader();
  const chunks = [];
  let size = 0;
  if (reader) {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          return null;
        }
        chunks.push(value);
      }
    } catch {
      try { await reader.cancel(); } catch { /* no-op */ }
      return null;
    }
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  if (new TextDecoder().decode(bytes).includes(assertion)) return null;
  return { headers, body: size ? bytes : null };
}

/**
 * Create a fail-closed reference gateway around a private Worker service binding.
 * Authentication/session issuance is intentionally delegated to operator-owned
 * adapters. This module is not a login service or an OAuth authorization server.
 * @param {Partial<GatewayOptions>} [options]
 */
export function createSelfHostGateway(options = {}) {
  const authenticateBrowser = options.authenticateBrowser;
  const authenticateMcp = options.authenticateMcp;
  const verifyBrowserCsrf = options.verifyBrowserCsrf;
  const backend = options.backend;
  const signingKey = options.signingKey;
  const issuer = options.issuer;
  const audience = options.audience;
  const externalOrigin = exactHttpsOrigin(options.externalOrigin);
  const subjects = validSubjects(options.allowedSubjects);
  const kid = options.keyId;
  if (typeof authenticateBrowser !== "function"
    || typeof authenticateMcp !== "function"
    || typeof verifyBrowserCsrf !== "function"
    || !backend || typeof backend.fetch !== "function"
    || !validPrivateKey(signingKey)
    || !secureIssuer(issuer)
    || typeof audience !== "string" || !audience || audience.length > 256
    || /[\u0000-\u001f\u007f]/.test(audience)
    || typeof kid !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(kid)
    || !externalOrigin || !subjects) {
    throw new TypeError("Self-host gateway needs trusted browser/MCP auth adapters, CSRF verification, an isolated backend, an RS256 key, and valid issuer/audience/origin/subjects.");
  }
  const now = typeof options.now === "function" ? options.now : () => Date.now();

  return {
    async fetch(request) {
      if (encoder.encode(request.url).byteLength > MAX_URL_BYTES) return errorResponse(414, "Request URL is too large.");
      if (!headersWithinBounds(request.headers)) return errorResponse(431, "Request headers are too large.");
      let url;
      try { url = new URL(request.url); } catch { return errorResponse(400, "Invalid request URL."); }
      if (url.protocol !== "https:" || url.origin !== externalOrigin) return errorResponse(421, "Unexpected host.");
      if (url.username || url.password || url.hash) return errorResponse(400, "Invalid request URL.");

      const route = ROUTES.get(url.pathname);
      if (!route) return errorResponse(404, "Not found.");
      if (!route.methods.includes(request.method)) {
        return errorResponse(405, "Method not allowed.", { allow: route.methods.join(", ") });
      }
      const bodyResult = await readBody(request, route.maxBodyBytes ?? MAX_BODY_BYTES);
      if (bodyResult.tooLarge) return route.kind === "mcp"
        ? jsonError(413, "request_too_large")
        : errorResponse(413, "Request too large.");
      if (route.kind === "mcp") {
        if (!requestOriginIsSafe(request, externalOrigin)) return jsonError(403, "origin_not_allowed");
      } else {
        const safeLanding = !route.csrf && ["/", "/health", "/oauth/complete"].includes(url.pathname);
        if (!requestOriginIsSafe(request, externalOrigin, safeLanding)) return errorResponse(403, "Origin is not allowed.");
      }

      let principal;
      try {
        if (route.kind === "mcp") principal = await authenticateMcp(authMetadata(request, "mcp"));
        else principal = await authenticateBrowser(authMetadata(request, "browser"));
      } catch {
        principal = null;
      }
      if (!validPrincipal(principal) || !subjects.has(principal.subject)) {
        return route.kind === "mcp" ? jsonError(401, "authentication_required") : errorResponse(401, "Authentication required.");
      }

      if (route.csrf) {
        let csrfValid = false;
        try {
          csrfValid = await verifyBrowserCsrf({
            request: authMetadata(request, "browser"),
            subject: principal.subject,
            context: principal.csrfContext,
            path: url.pathname,
          }) === true;
        } catch { csrfValid = false; }
        if (!csrfValid) return errorResponse(403, "Browser request could not be verified.");
      }

      let assertion;
      try {
        const time = now();
        if (!Number.isFinite(time)) throw new Error("invalid_clock");
        assertion = await signedAssertion({
          key: signingKey,
          kid,
          issuer,
          audience,
          subject: principal.subject,
          nowSeconds: Math.floor(time / 1000),
        });
      } catch {
        return errorResponse(503, "Gateway assertion could not be issued.");
      }

      const headers = new Headers();
      for (const name of FORWARDED_HEADERS) {
        const value = request.headers.get(name);
        if (value !== null) headers.set(name, value);
      }
      headers.set("authorization", "Bearer " + assertion);
      headers.set("cache-control", "no-store");

      let forwarded;
      try {
        forwarded = new Request(request, {
          headers,
          body: ["GET", "HEAD"].includes(request.method) ? undefined : bodyResult.body,
          redirect: "manual",
        });
      } catch {
        return errorResponse(400, "Invalid request body.");
      }

      let response;
      try { response = await backend.fetch(forwarded); }
      catch { return errorResponse(502, "Private application is unavailable."); }
      if (!(response instanceof Response) || !safeRouteRedirect(request.url, url.pathname, response)) {
        return errorResponse(502, "Private application returned an invalid response.");
      }

      let safeResponse;
      try { safeResponse = await safeBackendResponse(response, assertion); }
      catch { safeResponse = null; }
      if (!safeResponse) return errorResponse(502, "Private application returned an invalid response.");

      // The backend is private trusted code. These response header removals are
      // defense in depth; the gateway never follows its redirects. A private
      // backend must still be trusted not to encode assertions in a different form.
      const responseHeaders = safeResponse.headers;
      responseHeaders.delete("set-cookie");
      responseHeaders.delete("access-control-allow-origin");
      responseHeaders.delete("access-control-allow-credentials");
      responseHeaders.delete("access-control-allow-headers");
      responseHeaders.delete("access-control-allow-methods");
      responseHeaders.set("cache-control", "no-store");
      responseHeaders.set("x-content-type-options", "nosniff");
      if (route.kind === "mcp" && response.status === 401 && !responseHeaders.has("www-authenticate")) {
        responseHeaders.set("www-authenticate", 'Bearer realm="newrelic-chatgpt-mcp"');
      }
      return new Response(safeResponse.body, {
        status: response.status,
        headers: responseHeaders,
      });
    },
  };
}
