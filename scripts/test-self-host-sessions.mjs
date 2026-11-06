import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";
import { BROWSER_SESSION_LIMITS, createD1BrowserSessionAdapter } from "../examples/self-host-gateway/browser-session.mjs";
import { createSelfHostGateway } from "../examples/self-host-gateway/gateway.mjs";

globalThis.crypto ||= webcrypto;
globalThis.fetch = async () => { throw new Error("Live network calls are disabled in this test."); };
const origin = "https://monitor.example.test";
const issuer = "https://auth.example.test/";
const audience = "newrelic-chatgpt-mcp";
const subject = "oidc:synthetic-issuer:opaque-subject-01";
let time = 1_800_000_000_000;
let randomCounter = 1;
const randomBytes = length => new Uint8Array(length).fill(randomCounter++);
const sqlite = new DatabaseSync(":memory:");
sqlite.exec(await readFile(new URL("../examples/self-host-gateway/0001_browser_sessions.sql", import.meta.url), "utf8"));
const db = {
  prepare(query) {
    const statement = sqlite.prepare(query);
    let values = [];
    return {
      bind(...args) { values = args; return this; },
      async run() { return { meta: { changes: Number(statement.run(...values).changes) } }; },
      async first() { return statement.get(...values) || null; },
    };
  },
};

assert.throws(() => createD1BrowserSessionAdapter({ db, externalOrigin: "http://monitor.example.test" }), /exact HTTPS origin/);
assert.throws(() => createD1BrowserSessionAdapter({ db, externalOrigin: origin, sessionTtlMs: 48 * 60 * 60 * 1000 }), /bounded session lifetime/);
const sessions = createD1BrowserSessionAdapter({ db, externalOrigin: origin, now: () => time, randomBytes });
await assert.rejects(() => sessions.createBrowserSession({ subject: "" }), /stable verified identity subject/);
await assert.rejects(() => sessions.createBrowserSession({ subject: "owner@example.test" }), /stable verified identity subject/);
const issued = await sessions.createBrowserSession({ subject });
assert.equal(issued.expiresAt, time + 8 * 60 * 60 * 1000);
assert.equal(issued.setCookieHeaders.length, 2);
assert.match(issued.setCookieHeaders[0], /^__Host-nr-gateway-session=[A-Za-z0-9_-]{43}; Max-Age=28800; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
assert.match(issued.setCookieHeaders[1], /^__Host-nr-gateway-csrf=[A-Za-z0-9_-]{43}; Max-Age=28800; Path=\/; Secure; SameSite=Strict$/);
const sessionToken = issued.setCookieHeaders[0].match(/=([^;]+)/)[1];
const csrfToken = issued.setCookieHeaders[1].match(/=([^;]+)/)[1];
const cookie = `${issued.setCookieHeaders[0].split(";", 1)[0]}; ${issued.setCookieHeaders[1].split(";", 1)[0]}`;
const stored = sqlite.prepare("SELECT * FROM nr_gateway_browser_sessions").get();
assert.equal(stored.subject, subject);
assert.notEqual(stored.session_hash, sessionToken, "raw browser session tokens are never stored");
assert.notEqual(stored.csrf_hash, csrfToken, "raw CSRF values are never stored");
assert.match(stored.session_id, /^[A-Za-z0-9_-]{32}$/);
assert.notEqual(stored.session_id, sessionToken, "approval session id is distinct from the browser cookie");

function authContext({ method = "GET", path = "/api/accounts", requestCookie = cookie, originHeader = origin,
  secFetchSite = "same-origin", secFetchMode = "cors", secFetchDest = "empty", csrfHeader = csrfToken } = {}) {
  return {
    url: origin + path, method, cookie: requestCookie,
    origin: originHeader, secFetchSite, secFetchMode, secFetchDest, csrfToken: csrfHeader,
  };
}
const principal = await sessions.authenticateBrowser(authContext());
assert.equal(principal.subject, subject);
assert.ok(principal.sessionId);
assert.equal(principal.csrfContext.subject, subject);
assert.equal(await sessions.verifyBrowserCsrf({ request: authContext(), subject, context: principal.csrfContext, path: "/api/accounts" }), true);
assert.equal(await sessions.verifyBrowserCsrf({ request: authContext({ csrfHeader: "X".repeat(43) }), subject, context: principal.csrfContext, path: "/api/accounts" }), false);
assert.equal(await sessions.verifyBrowserCsrf({ request: authContext({ originHeader: "https://attacker.example" }), subject, context: principal.csrfContext, path: "/api/accounts" }), false);
assert.equal(await sessions.verifyBrowserCsrf({ request: authContext({ secFetchSite: "same-site" }), subject, context: principal.csrfContext, path: "/api/accounts" }), false);
assert.equal(await sessions.verifyBrowserCsrf({ request: authContext({ path: "/api/accounts?x=1", requestCookie: cookie + "; " + cookie.split("; ")[0] }), subject, context: principal.csrfContext, path: "/api/accounts" }), false,
  "duplicate session cookies fail closed");
assert.equal(await sessions.verifyBrowserCsrf({ request: authContext({ method: "GET", path: "/oauth/start", csrfHeader: null,
  secFetchSite: "same-origin", secFetchMode: "navigate", secFetchDest: "document" }), subject, context: principal.csrfContext, path: "/oauth/start" }), true,
"OAuth start permits only an authenticated same-origin top-level document navigation");
assert.equal(await sessions.verifyBrowserCsrf({ request: authContext({ method: "GET", path: "/oauth/start", csrfHeader: null,
  secFetchSite: "cross-site", secFetchMode: "navigate", secFetchDest: "document" }), subject, context: principal.csrfContext, path: "/oauth/start" }), false);
assert.equal(await sessions.verifyBrowserCsrf({ request: authContext({ path: "/unknown" }), subject, context: principal.csrfContext, path: "/unknown" }), false);
const secondBrowser = await sessions.createBrowserSession({ subject });
const secondBrowserCookie = secondBrowser.setCookieHeaders.map(header => header.split(";", 1)[0]).join("; ");
const secondBrowserPrincipal = await sessions.authenticateBrowser(authContext({ requestCookie: secondBrowserCookie }));
assert.notEqual(secondBrowserPrincipal.sessionId, principal.sessionId, "two browser sessions for one owner receive distinct approval bindings");
assert.equal(await sessions.verifyBrowserCsrf({ request: authContext({ requestCookie: secondBrowserCookie }),
  subject, context: principal.csrfContext, path: "/api/accounts" }), false,
"a CSRF session cannot be swapped across browser cookies");

// An external operator login callback must pass a verified stable subject to the
// adapter. This test injects a synthetic principal and exercises the real gateway.
const keys = await crypto.subtle.generateKey({
  name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1),
  hash: "SHA-256",
}, false, ["sign", "verify"]);
const pinnedWorkerKey = Buffer.from(await crypto.subtle.exportKey("spki", keys.publicKey)).toString("base64url");
let backendCalls = 0;
const gateway = createSelfHostGateway({
  externalOrigin: origin, issuer, audience, keyId: "synthetic-key", allowedSubjects: [subject],
  signingKey: keys.privateKey,
  authenticateBrowser: sessions.authenticateBrowser,
  authenticateMcp: async () => null,
  verifyBrowserCsrf: sessions.verifyBrowserCsrf,
  backend: { async fetch(request) {
    backendCalls += 1;
    assert.equal(request.headers.get("cookie"), null, "the browser cookie remains at the gateway");
    assert.equal(request.headers.get("x-csrf-token"), null, "CSRF proof is consumed at the gateway");
    assert.match(request.headers.get("authorization"), /^Bearer /);
    if (new URL(request.url).pathname === "/oauth/start") {
      return new Response(null, { status: 302,
        headers: { location: "https://oauth2.service.newrelic.com/oauth2/auth?client_id=synthetic" } });
    }
    return Response.json({ ok: true });
  } },
  now: () => time,
});
const accepted = await gateway.fetch(new Request(origin + "/api/accounts", {
  method: "GET", headers: { cookie, origin, "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty", "x-csrf-token": csrfToken },
}));
assert.equal(accepted.status, 200);
assert.equal(backendCalls, 1);
const oauthStart = await gateway.fetch(new Request(origin + "/oauth/start", {
  method: "GET", headers: { cookie, origin, "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(oauthStart.status, 302, "same-origin top-level OAuth navigation passes the session CSRF gate");
assert.equal(oauthStart.headers.get("location"), "https://oauth2.service.newrelic.com/oauth2/auth?client_id=synthetic");
assert.equal(backendCalls, 2);
const badOAuthNavigation = await gateway.fetch(new Request(origin + "/oauth/start", {
  method: "GET", headers: { cookie, origin, "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" },
}));
assert.equal(badOAuthNavigation.status, 403, "fetch-style OAuth starts fail closed");
assert.equal(backendCalls, 2);
const crossSite = await gateway.fetch(new Request(origin + "/api/accounts", {
  method: "GET", headers: { cookie, origin: "https://attacker.example", "sec-fetch-site": "cross-site", "x-csrf-token": csrfToken },
}));
assert.equal(crossSite.status, 403);
assert.equal(backendCalls, 2, "cross-site CSRF rejection happens before the backend");

// Execute the real localhost-paste controller through the real gateway/session
// adapter. Only the private backend is fake; no New Relic request is possible.
const completionHtml = await readFile(new URL("../worker/oauth-complete.html", import.meta.url), "utf8");
const completionScript = completionHtml.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(completionScript);
const completionNodes = new Map();
const completionDocument = {
  cookie: issued.setCookieHeaders[1].split(";", 1)[0],
  querySelector(selector) {
    if (!completionNodes.has(selector)) completionNodes.set(selector, {
      value: "", textContent: "", className: "", disabled: false,
      listeners: new Map(),
      addEventListener(type, handler) { this.listeners.set(type, handler); },
    });
    return completionNodes.get(selector);
  },
};
let completionLocation = null;
const completionFetchCalls = [];
runInNewContext(completionScript, {
  document: completionDocument,
  fetch: async (path, options) => {
    completionFetchCalls.push({ path, options });
    const headers = new Headers(options.headers);
    headers.set("cookie", cookie);
    headers.set("origin", origin);
    headers.set("sec-fetch-site", "same-origin");
    headers.set("sec-fetch-mode", "cors");
    headers.set("sec-fetch-dest", "empty");
    const response = await gateway.fetch(new Request(origin + path, {
      method: options.method, headers, body: options.body,
    }));
    return { ok: response.ok, status: response.status, json: () => response.json() };
  },
  setTimeout(callback) { callback(); },
  location: { replace(path) { completionLocation = path; } },
}, { timeout: 1000 });
completionNodes.get("#callback-url").value = "http://localhost:12345/callback?code=synthetic&state=synthetic";
await completionNodes.get("#complete-form").listeners.get("submit")({ preventDefault() {} });
assert.equal(completionFetchCalls.length, 1);
assert.equal(completionFetchCalls[0].path, "/api/oauth/manual-complete");
assert.equal(completionFetchCalls[0].options.headers["x-csrf-token"], csrfToken);
assert.equal(completionLocation, "/");
assert.match(completionNodes.get("#status").textContent, /接続しました/);
assert.equal(backendCalls, 3, "the genuine completion page reaches only the synthetic private backend after CSRF validation");

// Connect the same browser-session adapter through the actual Worker so the
// approval UI's browser sid and Worker CSRF session are proven end to end.
const appSqlite = new DatabaseSync(":memory:");
for (const migration of [
  "0000_newrelic_mcp.sql", "0001_refresh_locks.sql", "0002_oauth_completion_fence.sql",
  "0003_usage_consents.sql", "0004_operation_approval_store.sql", "0005_approval_retention_indexes.sql",
]) appSqlite.exec(await readFile(new URL("../drizzle/" + migration, import.meta.url), "utf8"));
const appDb = {
  prepare(query) {
    const statement = appSqlite.prepare(query);
    let values = [];
    return {
      bind(...args) { values = args; return this; },
      async run() { return { meta: { changes: Number(statement.run(...values).changes) } }; },
      async first() { return statement.get(...values) || null; },
      async all() { return { results: statement.all(...values) }; },
    };
  },
  async batch(statements) {
    appSqlite.exec("BEGIN IMMEDIATE");
    try {
      const results = [];
      for (const statement of statements) results.push(await statement.run());
      appSqlite.exec("COMMIT");
      return results;
    } catch (error) {
      appSqlite.exec("ROLLBACK");
      throw error;
    }
  },
};
const worker = (await import(new URL("../dist/server/index.js", import.meta.url).href + "?selfhost-session=" + Date.now())).default;
const workerEnv = {
  DB: appDb,
  NEW_RELIC_AUTH_MODE: "signed_proxy",
  NEW_RELIC_AUTH_JWT_PUBLIC_KEY: pinnedWorkerKey,
  NEW_RELIC_AUTH_JWT_KID: "synthetic-key",
  NEW_RELIC_AUTH_ISSUER: issuer,
  NEW_RELIC_AUTH_AUDIENCE: audience,
  NEW_RELIC_AUTH_ALLOWED_ORIGIN: origin,
  NEW_RELIC_AUTH_ALLOWED_SUBJECTS: JSON.stringify([subject]),
  NEW_RELIC_OPERATION_APPROVALS_ENABLED: "true",
};
let workerBackendCalls = 0;
const approvalGateway = createSelfHostGateway({
  externalOrigin: origin, issuer, audience, keyId: "synthetic-key", allowedSubjects: [subject],
  signingKey: keys.privateKey,
  authenticateBrowser: sessions.authenticateBrowser,
  authenticateMcp: async () => null,
  verifyBrowserCsrf: sessions.verifyBrowserCsrf,
  backend: { async fetch(request) {
    workerBackendCalls += 1;
    assert.equal(request.headers.get("cookie"), null);
    assert.equal(request.headers.get("x-csrf-token"), null);
    if (new URL(request.url).pathname.endsWith("/session")) assert.equal(request.headers.get("x-approval-csrf"), null);
    else assert.match(request.headers.get("x-approval-csrf"), /^[A-Za-z0-9_-]{43}$/);
    return worker.fetch(request, workerEnv);
  } },
  // The Worker validates gateway JWT timestamps against the real wall clock.
  // Keep this integration assertion inside that clock window; the synthetic
  // D1 browser-session clock above remains independently controlled.
  now: () => Date.now(),
});
const protectedHeaders = {
  cookie, origin, "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty",
  "x-csrf-token": csrfToken, "content-type": "application/json",
};
const approvalBootstrap = await approvalGateway.fetch(new Request(origin + "/api/operation-approvals/session", {
  method: "POST", headers: protectedHeaders, body: "{}",
}));
assert.equal(approvalBootstrap.status, 200);
assert.equal(approvalBootstrap.headers.get("set-cookie"), null, "gateway session cookies are not exposed to the Worker response path");
const workerApprovalSession = await approvalBootstrap.json();
assert.match(workerApprovalSession.csrfToken, /^[A-Za-z0-9_-]{43}$/);
assert.equal(appSqlite.prepare("SELECT count(*) AS count FROM nr_approval_sessions").get().count, 1);
const invalidApprovalCsrf = await approvalGateway.fetch(new Request(origin + "/api/operation-approvals/list", {
  method: "POST", headers: { ...protectedHeaders, "x-approval-csrf": "A".repeat(43) }, body: "{}",
}));
assert.equal(invalidApprovalCsrf.status, 403, "the Worker rejects a forged approval CSRF token through the real gateway");
const swappedBrowserSession = await approvalGateway.fetch(new Request(origin + "/api/operation-approvals/list", {
  method: "POST",
  headers: {
    ...protectedHeaders,
    cookie: secondBrowserCookie,
    "x-csrf-token": secondBrowser.setCookieHeaders[1].match(/=([^;]+)/)[1],
    "x-approval-csrf": workerApprovalSession.csrfToken,
  },
  body: "{}",
}));
assert.equal(swappedBrowserSession.status, 401, "a different authenticated browser sid cannot reuse the first approval session");
const approvalList = await approvalGateway.fetch(new Request(origin + "/api/operation-approvals/list", {
  method: "POST", headers: { ...protectedHeaders, "x-approval-csrf": workerApprovalSession.csrfToken }, body: "{}",
}));
assert.equal(approvalList.status, 200);
assert.deepEqual((await approvalList.json()).items, []);
assert.equal(workerBackendCalls, 4);

const revoked = await sessions.revokeBrowserSession({ cookie });
assert.equal(revoked.revoked, true);
assert.equal((await sessions.revokeBrowserSession({ cookie })).revoked, false, "logout revocation is one-way");
assert.ok(revoked.setCookieHeaders.every(header => /Max-Age=0/.test(header)));
assert.equal(await sessions.authenticateBrowser(authContext()), null, "revocation blocks subsequent requests");
assert.equal(await sessions.purgeExpiredSessions(), 1, "revoked sessions can be purged immediately");
assert.equal((await sessions.revokeBrowserSession({ cookie: secondBrowserCookie })).revoked, true);
const nextLogin = await sessions.createBrowserSession({ subject });
const nextCookie = nextLogin.setCookieHeaders[0].match(/=([^;]+)/)[1];
const nextCsrf = nextLogin.setCookieHeaders[1].match(/=([^;]+)/)[1];
assert.notEqual(nextCookie, sessionToken);
assert.notEqual(nextLogin.setCookieHeaders[1].match(/=([^;]+)/)[1], csrfToken);
const nextCookieHeader = nextLogin.setCookieHeaders.map(header => header.split(";", 1)[0]).join("; ");
const nextPrincipal = await sessions.authenticateBrowser(authContext({ requestCookie: nextCookieHeader, csrfHeader: nextCsrf }));
assert.notEqual(nextPrincipal.sessionId, principal.sessionId, "new login rotates the approval session binding");

// Expired and revoked rows are pruned with a bounded cleanup operation.
time += 9 * 60 * 60 * 1000;
assert.equal(await sessions.authenticateBrowser(authContext({ requestCookie: nextCookieHeader })), null);
for (let index = 0; index < 100; index += 1) await sessions.createBrowserSession({ subject: "cleanup-owner-" + index });
time += 9 * 60 * 60 * 1000;
const expiredPlan = sqlite.prepare("EXPLAIN QUERY PLAN SELECT session_hash FROM nr_gateway_browser_sessions WHERE revoked_at IS NULL AND expires_at <= ? ORDER BY expires_at ASC LIMIT ?")
  .all(time, BROWSER_SESSION_LIMITS.cleanupBatchSize).map(row => row.detail).join(" ");
assert.match(expiredPlan, /nr_gateway_browser_sessions_expiry_cleanup/);
assert.doesNotMatch(expiredPlan, /USE TEMP B-TREE/);
const revokedPlan = sqlite.prepare("EXPLAIN QUERY PLAN SELECT session_hash FROM nr_gateway_browser_sessions WHERE revoked_at IS NOT NULL ORDER BY revoked_at ASC LIMIT ?")
  .all(BROWSER_SESSION_LIMITS.cleanupBatchSize).map(row => row.detail).join(" ");
assert.match(revokedPlan, /nr_gateway_browser_sessions_revocation_cleanup/);
assert.doesNotMatch(revokedPlan, /USE TEMP B-TREE/);
const firstPurge = await sessions.purgeExpiredSessions();
assert.equal(firstPurge, 100, "one purge invocation deletes at most 100 sessions");
assert.equal(await sessions.purgeExpiredSessions(), 2, "the next invocation deletes only the remaining expired sessions");
assert.equal(sqlite.prepare("SELECT count(*) AS count FROM nr_gateway_browser_sessions").get().count, 0);

console.log("Self-host browser-session adapter tests passed: hashed cookies, CSRF, stable approval sid, revocation, expiry, bounded purge; provider calls: 0");
