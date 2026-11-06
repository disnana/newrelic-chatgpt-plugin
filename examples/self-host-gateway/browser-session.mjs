const encoder = new TextEncoder();
const SESSION_COOKIE = "__Host-nr-gateway-session";
const CSRF_COOKIE = "__Host-nr-gateway-csrf";
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{32}$/;
const DEFAULT_SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const CLEANUP_BATCH_SIZE = 100;

/** @typedef {{url: string, method: string, cookie: string, origin: string|null, secFetchSite: string|null, secFetchMode: string|null, secFetchDest: string|null, csrfToken: string|null}} BrowserAuthContext */
/** @typedef {{sessionHash: string, subject: string, csrfHash: string, expiresAt: number}} BrowserCsrfContext */

function exactHttpsOrigin(value) {
  if (typeof value !== "string" || value.length > 512) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.origin !== value || url.username || url.password
      || url.pathname !== "/" || url.search || url.hash) return null;
    return value;
  } catch { return null; }
}

function validSubject(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 256
    && !value.includes("@") && !/[\u0000-\u001f\u007f]/.test(value);
}

function validNow(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER - MAX_SESSION_TTL_MS;
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function cookieValue(header, name) {
  if (typeof header !== "string" || header.length > 4096) return null;
  const values = [];
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === name) values.push(part.slice(separator + 1).trim());
  }
  if (values.length !== 1 || !TOKEN_PATTERN.test(values[0])) return null;
  return values[0];
}

function constantTimeTextEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) difference |= (a[index] || 0) ^ (b[index] || 0);
  return difference === 0;
}

function cookieHeaders(sessionToken, csrfToken, maxAge) {
  const session = `${SESSION_COOKIE}=${sessionToken}; Max-Age=${maxAge}; Path=/; Secure; HttpOnly; SameSite=Lax`;
  const csrf = `${CSRF_COOKIE}=${csrfToken}; Max-Age=${maxAge}; Path=/; Secure; SameSite=Strict`;
  return [session, csrf];
}

function expiredCookieHeaders() {
  return [
    `${SESSION_COOKIE}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax`,
    `${CSRF_COOKIE}=; Max-Age=0; Path=/; Secure; SameSite=Strict`,
  ];
}

/**
 * Create a provider-neutral browser session adapter for the gateway's existing
 * authenticateBrowser and verifyBrowserCsrf callbacks. It does not authenticate
 * identities or implement a login route. Call createBrowserSession only after a
 * trusted operator identity adapter has verified its own login/callback.
 * @param {{db: {prepare: Function}, externalOrigin: string, now?: () => number,
 *   randomBytes?: (length: number) => Uint8Array, sessionTtlMs?: number}} options
 */
export function createD1BrowserSessionAdapter({
  db,
  externalOrigin,
  now = () => Date.now(),
  randomBytes = length => crypto.getRandomValues(new Uint8Array(length)),
  sessionTtlMs = DEFAULT_SESSION_TTL_MS,
}) {
  const origin = exactHttpsOrigin(externalOrigin);
  if (!db || typeof db.prepare !== "function" || !origin || typeof now !== "function"
    || typeof randomBytes !== "function"
    || !Number.isSafeInteger(sessionTtlMs) || sessionTtlMs < 5 * 60 * 1000 || sessionTtlMs > MAX_SESSION_TTL_MS) {
    throw new TypeError("Browser sessions require D1, an exact HTTPS origin, and a bounded session lifetime.");
  }

  function currentTime() {
    const value = now();
    if (!validNow(value)) throw new TypeError("Browser session clock is invalid.");
    return value;
  }

  function token(length) {
    const bytes = randomBytes(length);
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== length) {
      throw new TypeError("Browser session randomness is unavailable.");
    }
    return base64Url(bytes);
  }

  async function digest(label, value) {
    const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(label + "\0" + value));
    return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, "0")).join("");
  }

  /** @param {BrowserAuthContext} request */
  function safeRequestContext(request) {
    if (!request || typeof request !== "object" || typeof request.url !== "string"
      || typeof request.method !== "string") return null;
    try {
      const url = new URL(request.url);
      if (url.protocol !== "https:" || url.origin !== origin || url.username || url.password) return null;
      return url;
    } catch { return null; }
  }

  /** @param {string} sessionToken */
  async function findSession(sessionToken) {
    const sessionHash = await digest("nr-selfhost-session", sessionToken);
    const row = await db.prepare(
      "SELECT session_hash, subject, session_id, csrf_hash, created_at, expires_at, revoked_at FROM nr_gateway_browser_sessions WHERE session_hash = ?",
    ).bind(sessionHash).first();
    if (!row || row.session_hash !== sessionHash || !validSubject(row.subject)
      || typeof row.session_id !== "string" || !SESSION_ID_PATTERN.test(row.session_id)
      || typeof row.csrf_hash !== "string" || !HASH_PATTERN.test(row.csrf_hash)
      || !Number.isSafeInteger(Number(row.created_at)) || !Number.isSafeInteger(Number(row.expires_at))) return null;
    const time = currentTime();
    if (row.revoked_at !== null && row.revoked_at !== undefined
      || Number(row.created_at) > time || Number(row.expires_at) <= time
      || Number(row.expires_at) > Number(row.created_at) + sessionTtlMs) return null;
    return {
      sessionHash,
      subject: row.subject,
      sessionId: row.session_id,
      csrfHash: row.csrf_hash,
      createdAt: Number(row.created_at),
      expiresAt: Number(row.expires_at),
    };
  }

  /** @param {{subject: string}} options */
  async function createBrowserSession({ subject }) {
    if (!validSubject(subject)) throw new TypeError("A stable verified identity subject is required.");
    const createdAt = currentTime();
    const sessionToken = token(32);
    const csrfToken = token(32);
    const sessionId = token(24);
    if (!TOKEN_PATTERN.test(sessionToken) || !TOKEN_PATTERN.test(csrfToken) || !SESSION_ID_PATTERN.test(sessionId)) {
      throw new TypeError("Browser session randomness is unavailable.");
    }
    const sessionHash = await digest("nr-selfhost-session", sessionToken);
    const csrfHash = await digest("nr-selfhost-csrf", csrfToken);
    const expiresAt = createdAt + sessionTtlMs;
    const result = await db.prepare(
      "INSERT INTO nr_gateway_browser_sessions (session_hash, subject, session_id, csrf_hash, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, NULL)",
    ).bind(sessionHash, subject, sessionId, csrfHash, createdAt, expiresAt).run();
    if (Number(result?.meta?.changes || 0) !== 1) throw new Error("Browser session could not be created.");
    return Object.freeze({
      expiresAt,
      setCookieHeaders: Object.freeze(cookieHeaders(sessionToken, csrfToken, Math.floor(sessionTtlMs / 1000))),
    });
  }

  /** @param {BrowserAuthContext} request */
  async function authenticateBrowser(request) {
    if (!safeRequestContext(request)) return null;
    const sessionToken = cookieValue(request.cookie, SESSION_COOKIE);
    if (!sessionToken) return null;
    const session = await findSession(sessionToken);
    if (!session) return null;
    return Object.freeze({
      subject: session.subject,
      sessionId: session.sessionId,
      csrfContext: Object.freeze({
        sessionHash: session.sessionHash,
        subject: session.subject,
        csrfHash: session.csrfHash,
        expiresAt: session.expiresAt,
      }),
    });
  }

  /** @param {{request: BrowserAuthContext, subject: string, context: BrowserCsrfContext, path: string}} options */
  async function verifyBrowserCsrf({ request, subject, context, path }) {
    const url = safeRequestContext(request);
    if (!url || !validSubject(subject) || !context || context.subject !== subject
      || context.expiresAt <= currentTime()) return false;
    if (request.origin !== null && request.origin !== origin) return false;
    if (request.secFetchSite !== null && request.secFetchSite !== "same-origin") return false;

    // OAuth start is a same-origin top-level link, not a fetch. Reject it unless
    // Fetch Metadata confirms that exact navigation; cross-site requests are
    // rejected by the outer gateway before this callback is reached.
    if (path === "/oauth/start" && request.method === "GET") {
      const current = await authenticateBrowser(request);
      if (!current || current.subject !== subject) return false;
      return current.csrfContext.sessionHash === context.sessionHash
        && request.secFetchSite === "same-origin"
        && request.secFetchMode === "navigate"
        && request.secFetchDest === "document";
    }

    const allowedPath = typeof path === "string" && (path.startsWith("/api/") || path === "/oauth/callback");
    if (!allowedPath || !(request.origin === origin || request.secFetchSite === "same-origin")) return false;
    const csrfCookie = cookieValue(request.cookie, CSRF_COOKIE);
    const csrfHeader = request.csrfToken;
    if (!csrfCookie || !TOKEN_PATTERN.test(csrfHeader || "") || !constantTimeTextEqual(csrfCookie, csrfHeader)) return false;
    const current = await authenticateBrowser(request);
    if (!current || current.subject !== subject || current.csrfContext.sessionHash !== context.sessionHash
      || current.csrfContext.csrfHash !== context.csrfHash) return false;
    return constantTimeTextEqual(await digest("nr-selfhost-csrf", csrfHeader), context.csrfHash);
  }

  /** @param {{cookie?: string|null}} options */
  async function revokeBrowserSession({ cookie }) {
    const sessionToken = cookieValue(cookie, SESSION_COOKIE);
    const cleared = expiredCookieHeaders();
    if (!sessionToken) return Object.freeze({ revoked: false, setCookieHeaders: Object.freeze(cleared) });
    const sessionHash = await digest("nr-selfhost-session", sessionToken);
    const result = await db.prepare(
      "UPDATE nr_gateway_browser_sessions SET revoked_at = ? WHERE session_hash = ? AND revoked_at IS NULL",
    ).bind(currentTime(), sessionHash).run();
    return Object.freeze({
      revoked: Number(result?.meta?.changes || 0) === 1,
      setCookieHeaders: Object.freeze(cleared),
    });
  }

  /** @param {{now?: number}} [options] */
  async function purgeExpiredSessions({ now: cleanupNow = currentTime() } = {}) {
    if (!validNow(cleanupNow)) throw new TypeError("Browser session cleanup clock is invalid.");
    const revoked = await db.prepare(
      "DELETE FROM nr_gateway_browser_sessions WHERE session_hash IN (SELECT session_hash FROM nr_gateway_browser_sessions WHERE revoked_at IS NOT NULL ORDER BY revoked_at ASC LIMIT ?)",
    ).bind(CLEANUP_BATCH_SIZE).run();
    const revokedCount = Number(revoked?.meta?.changes || 0);
    const remainingBudget = Math.max(0, CLEANUP_BATCH_SIZE - revokedCount);
    if (remainingBudget === 0) return revokedCount;
    const expired = await db.prepare(
      "DELETE FROM nr_gateway_browser_sessions WHERE session_hash IN (SELECT session_hash FROM nr_gateway_browser_sessions WHERE revoked_at IS NULL AND expires_at <= ? ORDER BY expires_at ASC LIMIT ?)",
    ).bind(cleanupNow, remainingBudget).run();
    return revokedCount + Number(expired?.meta?.changes || 0);
  }

  return Object.freeze({ createBrowserSession, authenticateBrowser, verifyBrowserCsrf, revokeBrowserSession, purgeExpiredSessions });
}

export const BROWSER_SESSION_LIMITS = Object.freeze({
  defaultTtlMs: DEFAULT_SESSION_TTL_MS,
  maxTtlMs: MAX_SESSION_TTL_MS,
  cleanupBatchSize: CLEANUP_BATCH_SIZE,
});
