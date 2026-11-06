const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const STATE_COOKIE = "__Host-nr-oidc-state";
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const MAX_ATTEMPT_AGE_MS = 10 * 60 * 1000;
const MAX_TOKEN_RESPONSE_BYTES = 64 * 1024;
const MAX_JWKS_RESPONSE_BYTES = 64 * 1024;
const MAX_JWKS_KEYS = 100;
const CLEANUP_BATCH_SIZE = 100;
const MAX_PENDING_ATTEMPTS = 1000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const MAX_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_LOGIN_RATE_WINDOW_MS = 60_000;
const MAX_LOGIN_RATE_WINDOW_MS = 60 * 60 * 1000;
const MAX_LOGIN_RATE_BUCKETS_PER_PURGE = 100;
const LOGIN_RATE_LIMIT_UPSERT_SQL = `
  WITH current_state AS (
    SELECT
      COALESCE((SELECT window_start FROM nr_gateway_oidc_login_rate_limits
        WHERE bucket_hash = ?), -1) AS client_window,
      COALESCE((SELECT window_start FROM nr_gateway_oidc_login_rate_limits
        WHERE bucket_hash = ?), -1) AS global_window,
      COALESCE((SELECT request_count FROM nr_gateway_oidc_login_rate_limits
        WHERE bucket_hash = ? AND window_start = ?), 0) AS client_count,
      COALESCE((SELECT request_count FROM nr_gateway_oidc_login_rate_limits
        WHERE bucket_hash = ? AND window_start = ?), 0) AS global_count
  )
  INSERT INTO nr_gateway_oidc_login_rate_limits (bucket_hash, window_start, request_count, updated_at)
  SELECT ?, ?, 1, ? FROM current_state
    WHERE client_window <= ? AND global_window <= ? AND client_count < ? AND global_count < ?
  UNION ALL
  SELECT ?, ?, 1, ? FROM current_state
    WHERE client_window <= ? AND global_window <= ? AND client_count < ? AND global_count < ?
  ON CONFLICT(bucket_hash) DO UPDATE SET
    request_count = CASE
      WHEN nr_gateway_oidc_login_rate_limits.window_start = excluded.window_start
      THEN nr_gateway_oidc_login_rate_limits.request_count + 1
      ELSE 1
    END,
    window_start = excluded.window_start,
    updated_at = excluded.updated_at
  RETURNING bucket_hash
`;

function plain(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

function safeHttpsUrl(value, { originOnly = false } = {}) {
  if (typeof value !== "string" || value.length < 8 || value.length > 2048) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search
      || originOnly && (url.origin !== value || url.pathname !== "/" || url.search)) return null;
    return url;
  } catch { return null; }
}

function originValue(value) {
  const url = safeHttpsUrl(value, { originOnly: true });
  return url ? url.origin : null;
}

function validSecret(value, maximum = 4096) {
  return typeof value === "string" && value.length > 0 && value.length <= maximum
    && !/[\r\n\u0000-\u001f\u007f]/.test(value);
}

function validStateKey(value) {
  if (typeof value !== "object" || value === null) return false;
  const key = /** @type {CryptoKey} */ (value);
  const algorithm = /** @type {AesKeyAlgorithm} */ (key.algorithm);
  return key.type === "secret" && key.extractable === false
    && key.algorithm.name === "AES-GCM"
    && Number(algorithm.length) === 256
    && key.usages.includes("encrypt") && key.usages.includes("decrypt");
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64Url(value, maxBytes = 64 * 1024) {
  if (typeof value !== "string" || !value || value.length > Math.ceil(maxBytes * 4 / 3) + 4
    || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) throw new TypeError("Invalid encoded value.");
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  if (binary.length > maxBytes) throw new TypeError("Encoded value is too large.");
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  let difference = a.length ^ b.length;
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    difference |= (a[index] || 0) ^ (b[index] || 0);
  }
  return difference === 0;
}

function randomToken(randomBytes) {
  const bytes = randomBytes(32);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) throw new TypeError("OIDC randomness is unavailable.");
  const token = base64Url(bytes);
  if (!TOKEN_PATTERN.test(token)) throw new TypeError("OIDC randomness is unavailable.");
  return token;
}

function formEncode(value) {
  return new URLSearchParams([["v", value]]).toString().slice(2);
}

async function sha256(value) {
  const result = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(result)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

/** Stable, privacy-preserving subject for mirrored gateway/Worker allowlists. */
export async function mapOidcSubject(issuer, subject) {
  if (!safeHttpsUrl(issuer) || !validSecret(subject, 255)) throw new TypeError("OIDC issuer and subject are required.");
  return "oidc:" + await sha256("newrelic-chatgpt-oidc-subject\0" + issuer + "\0" + subject);
}

/**
 * Create an atomic D1 fixed-window admission limiter for OIDC login starts.
 * `trustedClientKeyFromRequest` must return a 32-byte HMAC-SHA-256 digest
 * (base64url or lowercase hex) derived from a trusted ingress identity. Never
 * return raw IP addresses or trust caller-supplied forwarding headers. This
 * module stores only a second hash of that opaque key, plus per-window counters.
 */
export function createD1OidcLoginStartRateLimiter({
  db,
  trustedClientKeyFromRequest,
  now = () => Date.now(),
  windowMs = DEFAULT_LOGIN_RATE_WINDOW_MS,
  maxPerClient = 10,
  maxGlobal = 500,
}) {
  if (!db || typeof db.prepare !== "function" || typeof trustedClientKeyFromRequest !== "function"
    || typeof now !== "function" || !Number.isSafeInteger(windowMs)
    || windowMs < 1000 || windowMs > MAX_LOGIN_RATE_WINDOW_MS
    || !Number.isSafeInteger(maxPerClient) || maxPerClient < 1 || maxPerClient > 1000
    || !Number.isSafeInteger(maxGlobal) || maxGlobal < 1 || maxGlobal > 100_000) {
    throw new TypeError("OIDC start limiting requires private D1, a trusted client-key adapter, and bounded limits.");
  }

  async function admit(request) {
    const opaqueClientKey = await trustedClientKeyFromRequest(request);
    if (typeof opaqueClientKey !== "string"
      || !/^(?:[A-Za-z0-9_-]{43}|[a-f0-9]{64})$/.test(opaqueClientKey)) {
      throw new TypeError("Trusted OIDC client identity is unavailable.");
    }
    const currentTime = now();
    if (!Number.isSafeInteger(currentTime) || currentTime < 0) {
      throw new TypeError("OIDC rate-limit clock is invalid.");
    }
    const windowStart = Math.floor(currentTime / windowMs) * windowMs;
    const clientHash = await sha256("newrelic-chatgpt-oidc-rate-client\0" + opaqueClientKey);
    const globalHash = await sha256("newrelic-chatgpt-oidc-rate-global\0v1");
    const result = await db.prepare(LOGIN_RATE_LIMIT_UPSERT_SQL).bind(clientHash, globalHash,
      clientHash, windowStart, globalHash, windowStart,
      clientHash, windowStart, currentTime, windowStart, windowStart, maxPerClient, maxGlobal,
      globalHash, windowStart, currentTime, windowStart, windowStart, maxPerClient, maxGlobal).run();
    const changes = Number(result?.meta?.changes || 0);
    if (changes !== 2) return false;
    return true;
  }

  async function purgeExpired({ now: cleanupNow = now() } = {}) {
    if (!Number.isSafeInteger(cleanupNow) || cleanupNow < 0) {
      throw new TypeError("OIDC rate-limit cleanup clock is invalid.");
    }
    const result = await db.prepare(
      "DELETE FROM nr_gateway_oidc_login_rate_limits WHERE bucket_hash IN (SELECT bucket_hash FROM nr_gateway_oidc_login_rate_limits WHERE window_start + ? <= ? ORDER BY window_start ASC, bucket_hash ASC LIMIT ?)",
    ).bind(windowMs, cleanupNow, MAX_LOGIN_RATE_BUCKETS_PER_PURGE).run();
    return Number(result?.meta?.changes || 0);
  }

  Object.defineProperty(admit, "purgeExpired", { value: purgeExpired });
  return Object.freeze({ admit, purgeExpired });
}

/** Import a 32-byte base64url AES-GCM key stored in the gateway's secret manager. */
export async function importOidcStateEncryptionKey(encoded) {
  try {
    const bytes = decodeBase64Url(encoded, 32);
    if (bytes.byteLength !== 32) throw new TypeError("Invalid key length.");
    return await crypto.subtle.importKey("raw", bytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  } catch {
    throw new TypeError("OIDC state encryption key is invalid.");
  }
}

function requestUrl(request, origin, pathname, method, allowedOriginHeaders = [origin], allowCrossSiteOriginHeader = false) {
  if (!(request instanceof Request) || request.method !== method) return null;
  try {
    const url = new URL(request.url);
    if (url.protocol !== "https:" || url.origin !== origin || url.pathname !== pathname
      || url.username || url.password || url.hash) return null;
    const originHeader = request.headers.get("origin");
    if (originHeader !== null && !allowedOriginHeaders.includes(originHeader)
      && !(allowCrossSiteOriginHeader && request.headers.get("sec-fetch-site") === "cross-site")) return null;
    return url;
  } catch { return null; }
}

function topLevelNavigation(request, allowedSites) {
  const site = request.headers.get("sec-fetch-site");
  return request.headers.get("sec-fetch-mode") === "navigate"
    && request.headers.get("sec-fetch-dest") === "document"
    && allowedSites.includes(site);
}

function cookieValue(request, name) {
  const header = request.headers.get("cookie") || "";
  if (header.length > 4096) return null;
  const values = [];
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) values.push(part.slice(separator + 1).trim());
  }
  if (values.length !== 1 || !TOKEN_PATTERN.test(values[0])) return null;
  return values[0];
}

function noStoreHeaders(extra = {}) {
  return new Headers({
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    ...extra,
  });
}

function errorResponse(status, message, clearCookie = false) {
  const headers = noStoreHeaders({ "content-type": "text/plain; charset=utf-8" });
  if (clearCookie) headers.append("set-cookie", `${STATE_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`);
  return new Response(message, { status, headers });
}

function jsonAuthResponse(status, body, cookies = []) {
  const headers = noStoreHeaders({ "content-type": "application/json; charset=utf-8" });
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return new Response(JSON.stringify(body), { status, headers });
}

async function responseJson(response, maxBytes, signal) {
  if (!(response instanceof Response) || response.redirected || response.status !== 200) {
    try { await response?.body?.cancel(); } catch { /* no-op */ }
    return null;
  }
  const reader = response.body?.getReader();
  if (!reader) return null;
  const cancelReader = () => { void reader.cancel().catch(() => {}); };
  signal?.addEventListener("abort", cancelReader, { once: true });
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      if (signal?.aborted) throw new Error("request_timeout");
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch {
    try { await reader.cancel(); } catch { /* no-op */ }
    return null;
  } finally {
    signal?.removeEventListener("abort", cancelReader);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try {
    const value = JSON.parse(decoder.decode(bytes));
    return plain(value) ? value : null;
  } catch { return null; }
}

async function fetchJsonBounded(fetchImpl, url, init, maxBytes, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { ...init, signal: controller.signal });
    return await responseJson(response, maxBytes, controller.signal);
  } catch { return null; }
  finally { clearTimeout(timer); }
}

function parseJwtPart(value, maximum = 16 * 1024) {
  return JSON.parse(decoder.decode(decodeBase64Url(value, maximum)));
}

async function encryptedAttempt({ state, nonce, verifier, issuedAt, key, randomBytes, aad }) {
  const iv = randomBytes(12);
  if (!(iv instanceof Uint8Array) || iv.byteLength !== 12) throw new TypeError("OIDC randomness is unavailable.");
  const plaintext = encoder.encode(JSON.stringify({ state, nonce, verifier, issuedAt }));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: new Uint8Array(iv), additionalData: new Uint8Array(aad).buffer, tagLength: 128 }, key, plaintext,
  );
  return "v1." + base64Url(iv) + "." + base64Url(new Uint8Array(ciphertext));
}

async function decryptAttempt(value, { key, aad }) {
  if (typeof value !== "string" || value.length > 2048) throw new TypeError("OIDC attempt is invalid.");
  const parts = value.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") throw new TypeError("OIDC attempt is invalid.");
  const iv = decodeBase64Url(parts[1], 12);
  if (iv.byteLength !== 12) throw new TypeError("OIDC attempt is invalid.");
  const ciphertext = decodeBase64Url(parts[2], 1024);
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, ciphertext,
  );
  const attempt = JSON.parse(decoder.decode(clear));
  if (!plain(attempt) || !TOKEN_PATTERN.test(attempt.state || "") || !TOKEN_PATTERN.test(attempt.nonce || "")
    || !TOKEN_PATTERN.test(attempt.verifier || "") || !Number.isSafeInteger(attempt.issuedAt)) {
    throw new TypeError("OIDC attempt is invalid.");
  }
  return attempt;
}

async function verifyIdToken({ token, config, fetchImpl, nowSeconds, nonce }) {
  if (typeof token !== "string" || token.length > 16 * 1024) return null;
  const segments = token.split(".");
  if (segments.length !== 3) return null;
  let header;
  let claims;
  let signature;
  try {
    header = parseJwtPart(segments[0], 4096);
    claims = parseJwtPart(segments[1], 12 * 1024);
    signature = decodeBase64Url(segments[2], 512);
  } catch { return null; }
  if (!plain(header) || !plain(claims)
    || ["jku", "jwk", "x5u", "crit", "b64"].some(key => Object.hasOwn(header, key))
    || header.alg !== "RS256"
    || header.typ !== undefined && header.typ !== "JWT"
    || typeof header.kid !== "string" || !/^[A-Za-z0-9._-]{1,256}$/.test(header.kid)
    || header.crit !== undefined) return null;

  const jwks = await fetchJsonBounded(fetchImpl, config.jwksUri,
    { method: "GET", headers: { accept: "application/json" }, redirect: "manual", cache: "no-store" },
    MAX_JWKS_RESPONSE_BYTES, config.requestTimeoutMs);
  if (!plain(jwks) || !Array.isArray(jwks.keys) || jwks.keys.length > MAX_JWKS_KEYS) return null;
  const matches = jwks.keys.filter(candidate => plain(candidate) && candidate.kid === header.kid);
  if (matches.length !== 1) return null;
  const jwk = matches[0];
  if (jwk.kty !== "RSA" || jwk.alg !== undefined && jwk.alg !== "RS256"
    || jwk.use !== undefined && jwk.use !== "sig"
    || jwk.key_ops !== undefined && (!Array.isArray(jwk.key_ops)
      || !jwk.key_ops.includes("verify") || jwk.key_ops.includes("sign"))
    || ["d", "p", "q", "dp", "dq", "qi", "oth"].some(name => jwk[name] !== undefined)) return null;

  let publicKey;
  try {
    publicKey = await crypto.subtle.importKey("jwk", jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  } catch { return null; }
  const algorithm = /** @type {RsaHashedKeyAlgorithm} */ (publicKey.algorithm);
  if (algorithm.name !== "RSASSA-PKCS1-v1_5" || algorithm.hash.name !== "SHA-256"
    || algorithm.modulusLength < 2048 || algorithm.modulusLength > 4096) return null;
  let signatureValid = false;
  try {
    signatureValid = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, publicKey,
      signature, encoder.encode(segments[0] + "." + segments[1]));
  } catch { return null; }
  if (!signatureValid || claims.iss !== config.issuer || !Array.isArray(claims.aud) && typeof claims.aud !== "string") return null;
  const audiences = typeof claims.aud === "string" ? [claims.aud] : claims.aud;
  if (audiences.length < 1 || audiences.length > 10 || audiences.some(value => typeof value !== "string")
    || new Set(audiences).size !== audiences.length || !audiences.includes(config.clientId)) return null;
  if (audiences.length > 1 && claims.azp !== config.clientId
    || claims.azp !== undefined && claims.azp !== config.clientId) return null;
  const verifiedAtSeconds = nowSeconds();
  if (!Number.isSafeInteger(verifiedAtSeconds) || !Number.isSafeInteger(claims.exp) || !Number.isSafeInteger(claims.iat)
    || claims.exp <= verifiedAtSeconds || claims.iat > verifiedAtSeconds + 60 || verifiedAtSeconds - claims.iat > 600
    || claims.exp <= claims.iat || claims.exp - claims.iat > 3600) return null;
  if (claims.nbf !== undefined && (!Number.isSafeInteger(claims.nbf)
    || claims.nbf > verifiedAtSeconds + 60 || claims.nbf > claims.exp)) return null;
  if (!constantTimeEqual(claims.nonce, nonce) || typeof claims.sub !== "string" || claims.sub.length < 1
    || claims.sub.length > 255 || /[\u0000-\u001f\u007f]/.test(claims.sub)) return null;
  return claims;
}

/**
 * Create an optional, generic OIDC browser-login adapter for the reference gateway.
 * The issuer, all endpoints, client credentials, state-encryption key, allowlist,
 * private D1, and the D1-backed browser-session adapter must come from the operator.
 * It never stores ID/access/refresh tokens and never touches New Relic.
 */
export function createOidcBrowserLogin({
  db,
  sessions,
  externalOrigin,
  issuer,
  clientId,
  clientSecret,
  authorizationEndpoint,
  tokenEndpoint,
  jwksUri,
  allowedEndpointOrigins,
  allowedSubjects,
  admitLoginStart,
  stateEncryptionKey,
  tokenEndpointAuthMethod = "client_secret_post",
  requestTimeoutMs = DEFAULT_REQUEST_TIMEOUT_MS,
  fetchImpl = (input, init) => fetch(input, init),
  now = () => Date.now(),
  randomBytes = length => crypto.getRandomValues(new Uint8Array(length)),
}) {
  const origin = originValue(externalOrigin);
  const issuerUrl = safeHttpsUrl(issuer);
  const authorizationUrl = safeHttpsUrl(authorizationEndpoint);
  const tokenUrl = safeHttpsUrl(tokenEndpoint);
  const jwksUrl = safeHttpsUrl(jwksUri);
  const providerOrigins = Array.isArray(allowedEndpointOrigins) && allowedEndpointOrigins.length <= 8
    ? [...new Set(allowedEndpointOrigins.map(originValue))] : [];
  const subjectSet = Array.isArray(allowedSubjects) && allowedSubjects.length <= 100
    ? new Set(allowedSubjects) : null;
  if (!db || typeof db.prepare !== "function" || !sessions || typeof sessions.createBrowserSession !== "function"
    || typeof sessions.authenticateBrowser !== "function" || typeof sessions.verifyBrowserCsrf !== "function"
    || typeof sessions.revokeBrowserSession !== "function"
    || !origin || !issuerUrl || issuer.length > 2048 || !validSecret(clientId, 256) || !validSecret(clientSecret)
    || !authorizationUrl || !tokenUrl || !jwksUrl || providerOrigins.length < 1 || providerOrigins.includes(null)
    || ![authorizationUrl.origin, tokenUrl.origin, jwksUrl.origin].every(value => providerOrigins.includes(value))
    || !providerOrigins.includes(issuerUrl.origin) || !subjectSet || subjectSet.size !== allowedSubjects.length
    || typeof admitLoginStart !== "function"
    || [...subjectSet].some(value => typeof value !== "string" || !/^oidc:[a-f0-9]{64}$/.test(value))
    || !["client_secret_post", "client_secret_basic"].includes(tokenEndpointAuthMethod)
    || !Number.isSafeInteger(requestTimeoutMs) || requestTimeoutMs < 100 || requestTimeoutMs > MAX_REQUEST_TIMEOUT_MS
    || !validStateKey(stateEncryptionKey) || typeof fetchImpl !== "function" || typeof now !== "function"
    || typeof randomBytes !== "function") {
    throw new TypeError("OIDC login requires private D1, a browser-session adapter, trusted login-start admission, HTTPS issuer/endpoints, a non-extractable state key, and an explicit subject allowlist.");
  }
  const redirectUri = origin + "/auth/callback";
  const aad = encoder.encode("newrelic-chatgpt-oidc-attempt\0v1\0" + origin + "\0" + issuer);

  function currentTime() {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - MAX_ATTEMPT_AGE_MS) {
      throw new TypeError("OIDC clock is invalid.");
    }
    return value;
  }

  async function loginPage(request) {
    if (!requestUrl(request, origin, "/login", "GET", [origin], true)
      || !topLevelNavigation(request, ["cross-site", "same-site", "same-origin", "none"])) {
      return errorResponse(403, "Sign-in page request was not allowed.");
    }
    return new Response("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Sign in</title><main><h1>Sign in</h1><p>Continue with your organization account to access this private New Relic connection.</p><p>Only identities explicitly allowed by the operator can continue.</p><a href=\"/auth/start\">Continue to sign in</a></main>", {
      status: 200,
      headers: noStoreHeaders({ "content-type": "text/html; charset=utf-8" }),
    });
  }

  async function loginCompletePage(request) {
    if (!requestUrl(request, origin, "/auth/complete", "GET", [origin], true)
      || !topLevelNavigation(request, ["cross-site", "same-site", "same-origin", "none"])) {
      return errorResponse(403, "Sign-in could not be completed.");
    }
    // IdP redirects may taint Fetch Metadata as cross-site through the next
    // navigation. Keep this page non-sensitive and require a user click before
    // loading the authenticated application at the origin root.
    return new Response("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Sign-in complete</title><main><h1>Sign-in complete</h1><p>Your browser session is ready.</p><a href=\"/\">Continue to New Relic</a></main>", {
      status: 200,
      headers: noStoreHeaders({ "content-type": "text/html; charset=utf-8" }),
    });
  }

  async function start(request) {
    if (!requestUrl(request, origin, "/auth/start", "GET")
      || !topLevelNavigation(request, ["same-origin", "none"])) return errorResponse(403, "Sign-in could not be started.");
    let admitted = false;
    try { admitted = await admitLoginStart(request) === true; }
    catch { return errorResponse(503, "Sign-in is temporarily unavailable."); }
    if (!admitted) return errorResponse(429, "Too many sign-in attempts. Try again later.");
    let state;
    let nonce;
    let verifier;
    let createdAt;
    let challenge;
    let ciphertext;
    let stateHash;
    try {
      state = randomToken(randomBytes);
      nonce = randomToken(randomBytes);
      verifier = randomToken(randomBytes);
      createdAt = currentTime();
      challenge = base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(verifier))));
      ciphertext = await encryptedAttempt({ state, nonce, verifier, issuedAt: createdAt, key: stateEncryptionKey, randomBytes, aad });
      stateHash = await sha256("newrelic-chatgpt-oidc-state\0" + state);
    } catch {
      return errorResponse(503, "Sign-in is temporarily unavailable.");
    }
    // Opportunistic bounded cleanup prevents old one-time challenges from
    // accumulating when the operator has not configured a retention trigger.
    try { await purgeExpiredAttempts({ now: createdAt }); } catch { /* login remains bounded by MAX_PENDING_ATTEMPTS */ }
    let stored;
    try {
      stored = await db.prepare(
        "INSERT INTO nr_gateway_oidc_login_attempts (state_hash, encrypted_attempt, created_at, expires_at, consumed_at) SELECT ?, ?, ?, ?, NULL WHERE (SELECT COUNT(*) FROM nr_gateway_oidc_login_attempts WHERE consumed_at IS NULL AND expires_at > ?) < ?",
      ).bind(stateHash, ciphertext, createdAt, createdAt + MAX_ATTEMPT_AGE_MS, createdAt, MAX_PENDING_ATTEMPTS).run();
    } catch { return errorResponse(503, "Sign-in is temporarily unavailable."); }
    if (Number(stored?.meta?.changes || 0) !== 1) return errorResponse(503, "Sign-in is temporarily unavailable.");

    const authorize = new URL(/** @type {URL} */ (authorizationUrl).toString());
    authorize.searchParams.set("response_type", "code");
    authorize.searchParams.set("response_mode", "query");
    authorize.searchParams.set("client_id", clientId);
    authorize.searchParams.set("redirect_uri", redirectUri);
    authorize.searchParams.set("scope", "openid");
    authorize.searchParams.set("state", state);
    authorize.searchParams.set("nonce", nonce);
    authorize.searchParams.set("code_challenge", challenge);
    authorize.searchParams.set("code_challenge_method", "S256");
    const headers = noStoreHeaders({ location: authorize.toString() });
    headers.append("set-cookie", `${STATE_COOKIE}=${state}; Max-Age=600; Path=/; Secure; HttpOnly; SameSite=Lax`);
    return new Response(null, { status: 302, headers });
  }

  async function consumeAttempt(state) {
    if (!TOKEN_PATTERN.test(state || "")) return null;
    const stateHash = await sha256("newrelic-chatgpt-oidc-state\0" + state);
    const row = await db.prepare(
      "SELECT state_hash, encrypted_attempt, created_at, expires_at, consumed_at FROM nr_gateway_oidc_login_attempts WHERE state_hash = ?",
    ).bind(stateHash).first();
    const time = currentTime();
    if (!row || row.state_hash !== stateHash || typeof row.encrypted_attempt !== "string"
      || !Number.isSafeInteger(Number(row.created_at)) || !Number.isSafeInteger(Number(row.expires_at))
      || row.consumed_at !== null && row.consumed_at !== undefined
      || Number(row.created_at) > time || Number(row.expires_at) <= time
      || Number(row.expires_at) > Number(row.created_at) + MAX_ATTEMPT_AGE_MS) return null;
    const changed = await db.prepare(
      "UPDATE nr_gateway_oidc_login_attempts SET consumed_at = ?, encrypted_attempt = '' WHERE state_hash = ? AND consumed_at IS NULL AND created_at <= ? AND expires_at > ?",
    ).bind(time, stateHash, time, time).run();
    if (Number(changed?.meta?.changes || 0) !== 1) return null;
    let attempt;
    try { attempt = await decryptAttempt(row.encrypted_attempt, { key: stateEncryptionKey, aad }); }
    catch { return null; }
    if (attempt.state !== state || attempt.issuedAt !== Number(row.created_at)
      || attempt.issuedAt + MAX_ATTEMPT_AGE_MS !== Number(row.expires_at)) return null;
    return { attempt, time };
  }

  async function callback(request) {
    const url = requestUrl(request, origin, "/auth/callback", "GET", [origin, ...providerOrigins]);
    if (!url || !topLevelNavigation(request, ["cross-site", "same-site", "same-origin", "none"])) {
      return errorResponse(403, "Sign-in could not be completed.", true);
    }
    const stateValues = url.searchParams.getAll("state");
    const codeValues = url.searchParams.getAll("code");
    const errorValues = url.searchParams.getAll("error");
    const issuerValues = url.searchParams.getAll("iss");
    if (stateValues.length !== 1 || codeValues.length > 1 || errorValues.length > 1
      || issuerValues.length > 1 || issuerValues.length === 1 && issuerValues[0] !== issuer
      || codeValues.length === 1 && errorValues.length === 1) return errorResponse(400, "Sign-in could not be completed.", true);
    const state = stateValues[0];
    const cookieState = cookieValue(request, STATE_COOKIE);
    if (!cookieState || !constantTimeEqual(state, cookieState)) return errorResponse(400, "Sign-in could not be completed.", true);
    let consumed;
    try { consumed = await consumeAttempt(state); } catch { consumed = null; }
    if (!consumed) return errorResponse(400, "Sign-in could not be completed.", true);
    if (errorValues.length === 1) return errorResponse(403, "Sign-in was not completed.", true);
    const code = codeValues[0];
    if (!validSecret(code, 4096)) return errorResponse(400, "Sign-in could not be completed.", true);

    let tokenResponse;
    try {
      const form = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        code_verifier: consumed.attempt.verifier,
      });
      const headers = { accept: "application/json", "content-type": "application/x-www-form-urlencoded" };
      if (tokenEndpointAuthMethod === "client_secret_post") form.set("client_secret", clientSecret);
      else headers.authorization = "Basic " + btoa(formEncode(clientId) + ":" + formEncode(clientSecret));
      tokenResponse = await fetchJsonBounded(fetchImpl, /** @type {URL} */ (tokenUrl).toString(), {
        method: "POST",
        headers,
        body: form.toString(), redirect: "manual", cache: "no-store",
      }, MAX_TOKEN_RESPONSE_BYTES, requestTimeoutMs);
    } catch { tokenResponse = null; }
    if (!tokenResponse || typeof tokenResponse.id_token !== "string") {
      return errorResponse(502, "Identity provider could not complete sign-in.", true);
    }
    let claims;
    try {
      claims = await verifyIdToken({ token: tokenResponse.id_token,
        config: { issuer, clientId, jwksUri: /** @type {URL} */ (jwksUrl).toString(), requestTimeoutMs },
        fetchImpl, nowSeconds: () => Math.floor(currentTime() / 1000), nonce: consumed.attempt.nonce });
    } catch { claims = null; }
    if (!claims) return errorResponse(502, "Identity provider response could not be verified.", true);

    let subject;
    try { subject = await mapOidcSubject(issuer, claims.sub); }
    catch { return errorResponse(502, "Identity provider response could not be verified.", true); }
    if (!subjectSet?.has(subject)) return errorResponse(403, "This identity is not allowed by the operator.", true);
    let session;
    try { session = await sessions.createBrowserSession({ subject }); }
    catch { return errorResponse(503, "A browser session could not be created.", true); }
    const cookies = session?.setCookieHeaders;
    const sessionCookie = Array.isArray(cookies) && cookies.length === 2
      ? cookies.find(value => typeof value === "string" && value.startsWith("__Host-nr-gateway-session=")) : null;
    const csrfCookie = Array.isArray(cookies) && cookies.length === 2
      ? cookies.find(value => typeof value === "string" && value.startsWith("__Host-nr-gateway-csrf=")) : null;
    const sessionCookieMatch = typeof sessionCookie === "string"
      ? /^__Host-nr-gateway-session=([A-Za-z0-9_-]{43}); Max-Age=(\d+); Path=\/; Secure; HttpOnly; SameSite=Lax$/.exec(sessionCookie) : null;
    const csrfCookieMatch = typeof csrfCookie === "string"
      ? /^__Host-nr-gateway-csrf=([A-Za-z0-9_-]{43}); Max-Age=(\d+); Path=\/; Secure; SameSite=Strict$/.exec(csrfCookie) : null;
    const sessionNow = currentTime();
    const cookieMaxAge = sessionCookieMatch ? Number(sessionCookieMatch[2]) : 0;
    if (!sessionCookieMatch || !csrfCookieMatch || sessionCookieMatch[1] === csrfCookieMatch[1]
      || sessionCookieMatch[2] !== csrfCookieMatch[2]
      || !Number.isSafeInteger(session.expiresAt) || cookieMaxAge < 300 || cookieMaxAge > 86400
      || session.expiresAt <= sessionNow || session.expiresAt > sessionNow + 24 * 60 * 60 * 1000
      || cookieMaxAge * 1000 > session.expiresAt - sessionNow + 1000) {
      return errorResponse(503, "A browser session could not be created.", true);
    }
    const headers = noStoreHeaders({ location: origin + "/auth/complete" });
    headers.append("set-cookie", sessionCookie);
    headers.append("set-cookie", csrfCookie);
    headers.append("set-cookie", `${STATE_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`);
    return new Response(null, { status: 303, headers });
  }

  async function logout(request) {
    if (!requestUrl(request, origin, "/auth/logout", "POST")
      || request.headers.get("sec-fetch-site") !== "same-origin"
      || request.headers.get("sec-fetch-mode") !== "cors"
      || request.headers.get("sec-fetch-dest") !== "empty"
      || ![null, "0"].includes(request.headers.get("content-length"))) {
      return jsonAuthResponse(403, { error: "Sign-out request could not be verified." });
    }
    const context = Object.freeze({
      url: request.url,
      method: request.method,
      cookie: request.headers.get("cookie") || "",
      origin: request.headers.get("origin"),
      secFetchSite: request.headers.get("sec-fetch-site"),
      secFetchMode: request.headers.get("sec-fetch-mode"),
      secFetchDest: request.headers.get("sec-fetch-dest"),
      csrfToken: request.headers.get("x-csrf-token"),
    });
    let principal = null;
    try { principal = await sessions.authenticateBrowser(context); } catch { /* fail closed */ }
    if (!plain(principal) || typeof principal.subject !== "string" || !principal.csrfContext) {
      return jsonAuthResponse(401, { error: "Browser session is not active." });
    }
    let csrfValid = false;
    try {
      csrfValid = await sessions.verifyBrowserCsrf({
        request: context,
        subject: principal.subject,
        context: principal.csrfContext,
        path: "/api/logout",
      }) === true;
    } catch { csrfValid = false; }
    if (!csrfValid) return jsonAuthResponse(403, { error: "Sign-out request could not be verified." });
    let result;
    try { result = await sessions.revokeBrowserSession({ cookie: context.cookie }); }
    catch { return jsonAuthResponse(503, { error: "Browser session could not be revoked." }); }
    if (result?.revoked !== true) return jsonAuthResponse(503, { error: "Browser session could not be revoked." });
    const cleared = result?.setCookieHeaders;
    const sessionClear = Array.isArray(cleared) && cleared.length === 2
      ? cleared.find(value => value === "__Host-nr-gateway-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax") : null;
    const csrfClear = Array.isArray(cleared) && cleared.length === 2
      ? cleared.find(value => value === "__Host-nr-gateway-csrf=; Max-Age=0; Path=/; Secure; SameSite=Strict") : null;
    if (!sessionClear || !csrfClear) return jsonAuthResponse(503, { error: "Browser session could not be revoked." });
    return jsonAuthResponse(200, { signedOut: true, newRelicConnectionPreserved: true }, [
      sessionClear, csrfClear, `${STATE_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`,
    ]);
  }

  async function fetchHandler(request) {
    let path;
    try { path = new URL(request.url).pathname; } catch { return errorResponse(400, "Sign-in request was invalid."); }
    if (path === "/login") return loginPage(request);
    if (path === "/auth/complete") return loginCompletePage(request);
    if (path === "/auth/start") return start(request);
    if (path === "/auth/callback") return callback(request);
    if (path === "/auth/logout") return logout(request);
    return errorResponse(404, "Not found.");
  }

  async function purgeExpiredAttempts({ now: cleanupNow = currentTime() } = {}) {
    if (!Number.isSafeInteger(cleanupNow) || cleanupNow < 0) throw new TypeError("OIDC cleanup clock is invalid.");
    const result = await db.prepare(
      "DELETE FROM nr_gateway_oidc_login_attempts WHERE state_hash IN (SELECT state_hash FROM nr_gateway_oidc_login_attempts WHERE consumed_at IS NOT NULL OR expires_at <= ? ORDER BY COALESCE(consumed_at, expires_at) ASC LIMIT ?)",
    ).bind(cleanupNow, CLEANUP_BATCH_SIZE).run();
    const attemptCount = Number(result?.meta?.changes || 0);
    const cleanupRateLimits = admitLoginStart.purgeExpired;
    const rateLimitCount = typeof cleanupRateLimits === "function"
      ? await cleanupRateLimits({ now: cleanupNow }) : 0;
    return attemptCount + rateLimitCount;
  }

  return Object.freeze({ fetch: fetchHandler, purgeExpiredAttempts });
}

export const OIDC_LOGIN_LIMITS = Object.freeze({
  attemptTtlMs: MAX_ATTEMPT_AGE_MS,
  cleanupBatchSize: CLEANUP_BATCH_SIZE,
  maxPendingAttempts: MAX_PENDING_ATTEMPTS,
  requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS,
  stateCookie: STATE_COOKIE,
});
