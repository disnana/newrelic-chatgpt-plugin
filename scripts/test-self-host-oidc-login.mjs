import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { createD1OidcLoginStartRateLimiter, createOidcBrowserLogin, importOidcStateEncryptionKey, mapOidcSubject } from "../examples/self-host-gateway/oidc-login.mjs";
import { createSelfHostGateway } from "../examples/self-host-gateway/gateway.mjs";
import { createD1BrowserSessionAdapter } from "../examples/self-host-gateway/browser-session.mjs";

globalThis.crypto ||= webcrypto;
globalThis.fetch = async () => { throw new Error("Live network calls are disabled in this test."); };

const origin = "https://monitor.example.test";
const issuer = "https://auth.example.test/tenant";
const authorizationEndpoint = "https://auth.example.test/tenant/oauth2/authorize";
const tokenEndpoint = "https://auth.example.test/tenant/oauth2/token";
const jwksUri = "https://auth.example.test/tenant/oauth2/keys";
const clientId = "synthetic-client-id";
const clientSecret = "synthetic:client secret+%";
const now = 1_800_000_000_000;
let liveNow = now;
let randomCounter = 1;
const randomBytes = length => new Uint8Array(length).fill(randomCounter++);
const sqlite = new DatabaseSync(":memory:");
sqlite.exec(await readFile(new URL("../examples/self-host-gateway/0001_browser_sessions.sql", import.meta.url), "utf8"));
sqlite.exec(await readFile(new URL("../examples/self-host-gateway/0002_oidc_login_attempts.sql", import.meta.url), "utf8"));
sqlite.exec(await readFile(new URL("../examples/self-host-gateway/0003_oidc_login_rate_limits.sql", import.meta.url), "utf8"));
let pendingRateLimitPause = null;
function pauseNextRateLimitWrite() {
  let markStarted;
  let release;
  const started = new Promise(resolve => { markStarted = resolve; });
  const paused = new Promise(resolve => { release = resolve; });
  pendingRateLimitPause = { markStarted, paused };
  return { started, release };
}
const db = {
  prepare(query) {
    const statement = sqlite.prepare(query);
    let values = [];
    return {
      bind(...args) { values = args; return this; },
      async run() {
        if (query.includes("INSERT INTO nr_gateway_oidc_login_rate_limits") && pendingRateLimitPause) {
          const gate = pendingRateLimitPause;
          pendingRateLimitPause = null;
          gate.markStarted();
          await gate.paused;
        }
        return { meta: { changes: Number(statement.run(...values).changes) } };
      },
      async first() { return statement.get(...values) || null; },
    };
  },
};

const signing = await crypto.subtle.generateKey({
  name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256",
}, true, ["sign", "verify"]);
const stateKey = await importOidcStateEncryptionKey(Buffer.alloc(32, 0x42).toString("base64url"));
assert.equal(stateKey.extractable, false);
await assert.rejects(() => importOidcStateEncryptionKey("not-a-key"), /invalid/);
const publicJwk = {
  ...await crypto.subtle.exportKey("jwk", signing.publicKey),
  kid: "synthetic-key-1", alg: "RS256", use: "sig", key_ops: ["verify"],
};
const expectedSubject = await mapOidcSubject(issuer, "synthetic-user-subject");
const calls = { token: [], jwks: 0, backend: 0 };
let tokenResponseMode = "valid";
let tokenAuthMethodForNext = "client_secret_post";
let activeNonce = "";
let activeCodeVerifier = "";
let activeSubject = "synthetic-user-subject";

function base64url(value) { return Buffer.from(value).toString("base64url"); }
async function signJwt(claims, key = signing.privateKey, kid = "synthetic-key-1") {
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid, x5t: "synthetic-certificate-thumbprint" }));
  const payload = base64url(JSON.stringify(claims));
  const input = header + "." + payload;
  const signature = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, new TextEncoder().encode(input));
  return input + "." + Buffer.from(signature).toString("base64url");
}

const fetchImpl = async (input, init) => {
  const url = String(input);
  assert.equal(init.redirect, "manual", "OIDC endpoint redirects are not followed");
  assert.equal(init.cache, "no-store");
  if (url === tokenEndpoint) {
    calls.token.push(init);
    assert.equal(init.method, "POST");
    assert.equal(init.headers["content-type"], "application/x-www-form-urlencoded");
    const form = new URLSearchParams(init.body);
    assert.equal(form.get("grant_type"), "authorization_code");
    assert.equal(form.get("client_id"), clientId);
    if (tokenAuthMethodForNext === "client_secret_post") {
      assert.equal(form.get("client_secret"), clientSecret, "confidential-client secret is sent only to the configured token endpoint");
      assert.equal(init.headers.authorization, undefined);
    } else {
      assert.equal(form.get("client_secret"), null, "Basic mode does not duplicate the client secret in the form body");
      assert.equal(Buffer.from(init.headers.authorization.replace(/^Basic /, ""), "base64").toString(),
        new URLSearchParams([["v", clientId]]).toString().slice(2) + ":"
          + new URLSearchParams([["v", clientSecret]]).toString().slice(2),
        "Basic client credentials are form-encoded and sent only in Authorization to the configured token endpoint");
    }
    assert.equal(form.get("redirect_uri"), origin + "/auth/callback");
    assert.equal(form.get("code_verifier"), activeCodeVerifier, "PKCE verifier matches the encrypted transaction");
    if (tokenResponseMode === "redirect") return new Response(null, { status: 302, headers: { location: "https://attacker.invalid/steal" } });
    const sub = activeSubject;
    const claims = {
      iss: issuer, sub, aud: clientId, exp: Math.floor(now / 1000) + 300,
      iat: Math.floor(now / 1000), nonce: activeNonce,
    };
    if (tokenResponseMode === "wrong-issuer") claims.iss = "https://attacker.invalid/";
    if (tokenResponseMode === "wrong-nonce") claims.nonce = "A".repeat(43);
    const idToken = await signJwt(claims);
    return Response.json({ id_token: idToken, access_token: "synthetic-access-token", refresh_token: "synthetic-refresh-token" });
  }
  if (url === jwksUri) {
    calls.jwks += 1;
    if (tokenResponseMode === "expire-during-jwks") liveNow = now + 10 * 60 * 1000;
    return Response.json({ keys: [publicJwk] });
  }
  throw new Error("OIDC adapter attempted an unconfigured endpoint: " + url);
};

const sessions = createD1BrowserSessionAdapter({ db, externalOrigin: origin, now: () => liveNow, randomBytes });
const admitLoginStart = async () => true;
const browserLogin = createOidcBrowserLogin({
  db, sessions, externalOrigin: origin, issuer, clientId, clientSecret,
  authorizationEndpoint, tokenEndpoint, jwksUri, allowedEndpointOrigins: ["https://auth.example.test"],
  allowedSubjects: [expectedSubject], admitLoginStart, stateEncryptionKey: stateKey, fetchImpl, now: () => liveNow, randomBytes,
});

await assert.rejects(async () => createOidcBrowserLogin({
  db, sessions, externalOrigin: origin, issuer, clientId, clientSecret,
  authorizationEndpoint, tokenEndpoint, jwksUri: "https://evil.invalid/keys",
  allowedEndpointOrigins: ["https://auth.example.test"], allowedSubjects: [expectedSubject], admitLoginStart,
  stateEncryptionKey: stateKey, fetchImpl, now: () => now, randomBytes,
}), /explicit subject allowlist/);

let limiterNow = now;
const syntheticIngressHmacKey = await crypto.subtle.importKey(
  "raw", Buffer.from("synthetic-only-ingress-hmac-key"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
);
const syntheticClientKeyFromRequest = async request => {
  const client = request.headers.get("x-synthetic-client");
  if (!client) return null;
  return Buffer.from(await crypto.subtle.sign("HMAC", syntheticIngressHmacKey, new TextEncoder().encode(client)))
    .toString("base64url");
};
const loginStartLimiter = createD1OidcLoginStartRateLimiter({
  db,
  trustedClientKeyFromRequest: syntheticClientKeyFromRequest,
  now: () => limiterNow,
  windowMs: 60_000,
  maxPerClient: 2,
  maxGlobal: 3,
});
const limitedLogin = createOidcBrowserLogin({
  db, sessions, externalOrigin: origin, issuer, clientId, clientSecret,
  authorizationEndpoint, tokenEndpoint, jwksUri, allowedEndpointOrigins: ["https://auth.example.test"],
  allowedSubjects: [expectedSubject], stateEncryptionKey: stateKey, admitLoginStart: loginStartLimiter.admit,
  fetchImpl, now: () => limiterNow, randomBytes,
});
const attemptsBeforeAdmission = sqlite.prepare("SELECT COUNT(*) AS count FROM nr_gateway_oidc_login_attempts").get().count;
const limitedStart = request => limitedLogin.fetch(new Request(origin + "/auth/start", {
  headers: { origin, "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document",
    "x-synthetic-client": request },
}));
assert.equal((await limitedStart("synthetic-client-a")).status, 302);
assert.equal((await limitedStart("synthetic-client-a")).status, 302);
assert.equal((await limitedStart("synthetic-client-b")).status, 302,
  "a separate client may use remaining global capacity");
const clientLimit = await limitedStart("synthetic-client-a");
assert.equal(clientLimit.status, 429, "per-client window limit rejects an over-limit start");
const globalLimit = await limitedStart("synthetic-client-b");
assert.equal(globalLimit.status, 429, "global window limit rejects starts after shared capacity is used");
assert.equal(clientLimit.headers.get("set-cookie"), null, "a rejected login start does not create state cookies");
assert.equal(globalLimit.headers.get("set-cookie"), null, "a rejected login start does not create state cookies");
limiterNow += 60_000;
assert.equal((await limitedStart("synthetic-client-a")).status, 302, "client and global counters reset at the next fixed window");
assert.equal((await limitedStart("synthetic-client-b")).status, 302);
limiterNow += 60_000;
const concurrentStarts = await Promise.all(Array.from({ length: 8 }, () => limitedStart("synthetic-client-c")));
assert.equal(concurrentStarts.filter(response => response.status === 302).length, 2,
  "the atomic limiter statement respects the per-client limit under overlapping synthetic requests");
assert.equal(concurrentStarts.filter(response => response.status === 429).length, 6);
const rateRowsBeforePurge = sqlite.prepare("SELECT COUNT(*) AS count FROM nr_gateway_oidc_login_rate_limits").get().count;
assert.ok(rateRowsBeforePurge >= 2);
assert.ok(await loginStartLimiter.purgeExpired({ now: now + 3 * 60_000 }) >= 2,
  "expired per-client and global rate-limit buckets are removed in a bounded batch");
limiterNow = now + 4 * 60_000;
const delayedWindowLimiter = createD1OidcLoginStartRateLimiter({
  db, trustedClientKeyFromRequest: syntheticClientKeyFromRequest,
  now: () => limiterNow, windowMs: 60_000, maxPerClient: 1, maxGlobal: 10,
});
const delayedRateRequest = new Request(origin, { headers: { "x-synthetic-client": "synthetic-delayed-window-client" } });
const pause = pauseNextRateLimitWrite();
const delayedPriorWindowAdmission = delayedWindowLimiter.admit(delayedRateRequest);
await pause.started;
limiterNow += 60_000;
assert.equal(await delayedWindowLimiter.admit(delayedRateRequest), true,
  "the current window admits its first request while an older SQL write is delayed");
assert.equal(await delayedWindowLimiter.admit(delayedRateRequest), false,
  "the current window limit is consumed before the delayed older write resumes");
pause.release();
assert.equal(await delayedPriorWindowAdmission, false,
  "a delayed request from an older window is rejected instead of rewinding counters");
assert.equal(await delayedWindowLimiter.admit(delayedRateRequest), false,
  "the delayed older request cannot reset the current per-client quota");

limiterNow = now + 6 * 60_000;
const globalWindowLimiter = createD1OidcLoginStartRateLimiter({
  db, trustedClientKeyFromRequest: syntheticClientKeyFromRequest,
  now: () => limiterNow, windowMs: 60_000, maxPerClient: 10, maxGlobal: 1,
});
const staleClientRequest = new Request(origin, { headers: { "x-synthetic-client": "synthetic-stale-global-client" } });
const currentClientRequest = new Request(origin, { headers: { "x-synthetic-client": "synthetic-current-global-client" } });
const globalPause = pauseNextRateLimitWrite();
const delayedGlobalAdmission = globalWindowLimiter.admit(staleClientRequest);
await globalPause.started;
limiterNow += 60_000;
assert.equal(await globalWindowLimiter.admit(currentClientRequest), true,
  "a new client can consume the new window's shared global capacity");
globalPause.release();
assert.equal(await delayedGlobalAdmission, false,
  "a delayed old-window request from a different client cannot rewind the global bucket");
assert.equal(await globalWindowLimiter.admit(currentClientRequest), false,
  "the stale different-client request does not reset shared global capacity");

const brokenLimiter = createD1OidcLoginStartRateLimiter({
  db, trustedClientKeyFromRequest: async () => null, now: () => limiterNow,
});
const brokenLogin = createOidcBrowserLogin({
  db, sessions, externalOrigin: origin, issuer, clientId, clientSecret,
  authorizationEndpoint, tokenEndpoint, jwksUri, allowedEndpointOrigins: ["https://auth.example.test"],
  allowedSubjects: [expectedSubject], stateEncryptionKey: stateKey, admitLoginStart: brokenLimiter.admit,
  fetchImpl, now: () => liveNow, randomBytes,
});
const attemptsBeforeBrokenAdmission = sqlite.prepare("SELECT COUNT(*) AS count FROM nr_gateway_oidc_login_attempts").get().count;
const identityUnavailable = await brokenLogin.fetch(new Request(origin + "/auth/start", {
  headers: { origin, "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(identityUnavailable.status, 503, "missing trusted ingress identity fails closed");
assert.equal(sqlite.prepare("SELECT COUNT(*) AS count FROM nr_gateway_oidc_login_attempts").get().count,
  attemptsBeforeBrokenAdmission, "failed admission creates no OIDC state");
assert.equal(sqlite.prepare("SELECT COUNT(*) AS count FROM nr_gateway_oidc_login_attempts").get().count,
  attemptsBeforeAdmission + 2 + 1 + 2 + 2,
  "accepted starts create state; rejected or missing identities do not");

const gatewayKeys = await crypto.subtle.generateKey({
  name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256",
}, true, ["sign", "verify"]);
let browserCookie = "";
const gateway = createSelfHostGateway({
  externalOrigin: origin, issuer: "https://gateway.example.test/", audience: "newrelic-chatgpt-mcp",
  keyId: "gateway-key", allowedSubjects: [expectedSubject], signingKey: gatewayKeys.privateKey,
  authenticateBrowser: sessions.authenticateBrowser,
  authenticateMcp: async () => null,
  verifyBrowserCsrf: sessions.verifyBrowserCsrf,
  browserLogin,
  backend: { async fetch(request) {
    calls.backend += 1;
    assert.equal(request.headers.get("cookie"), null, "browser cookies terminate at the gateway");
    assert.match(request.headers.get("authorization"), /^Bearer /);
    return Response.json({ ok: true });
  } },
  now: () => liveNow,
});

const unauthenticatedLanding = await gateway.fetch(new Request(origin + "/", {
  headers: { "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(unauthenticatedLanding.status, 303);
assert.equal(unauthenticatedLanding.headers.get("location"), origin + "/login");
assert.equal(calls.backend, 0, "unauthenticated landing never reaches the private app");

const loginPage = await gateway.fetch(new Request(origin + "/login", {
  headers: { origin: "https://chatgpt.com", "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(loginPage.status, 200);
assert.match(await loginPage.text(), /Only identities explicitly allowed by the operator/);
assert.equal(loginPage.headers.get("cache-control"), "no-store");

const attemptsBeforeBlockedStart = sqlite.prepare("SELECT COUNT(*) AS count FROM nr_gateway_oidc_login_attempts").get().count;
const blockedStart = await gateway.fetch(new Request(origin + "/auth/start", {
  headers: { origin: "https://attacker.invalid", "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(blockedStart.status, 403, "cross-site login initiation is rejected");
assert.equal(sqlite.prepare("SELECT COUNT(*) AS count FROM nr_gateway_oidc_login_attempts").get().count,
  attemptsBeforeBlockedStart, "cross-site login initiation creates no durable state");

const start = await gateway.fetch(new Request(origin + "/auth/start", {
  headers: { origin, "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(start.status, 302);
const authorization = new URL(start.headers.get("location"));
assert.equal(authorization.origin, "https://auth.example.test");
assert.equal(authorization.searchParams.get("response_type"), "code");
assert.equal(authorization.searchParams.get("response_mode"), "query");
assert.equal(authorization.searchParams.get("client_id"), clientId);
assert.equal(authorization.searchParams.get("redirect_uri"), origin + "/auth/callback");
assert.equal(authorization.searchParams.get("scope"), "openid");
assert.equal(authorization.searchParams.get("code_challenge_method"), "S256");
assert.match(authorization.searchParams.get("code_challenge"), /^[A-Za-z0-9_-]{43}$/);
const stateCookie = start.headers.getSetCookie().find(value => value.startsWith("__Host-nr-oidc-state="));
assert.match(stateCookie, /^__Host-nr-oidc-state=[A-Za-z0-9_-]{43}; Max-Age=600; Path=\/; Secure; HttpOnly; SameSite=Lax$/);
const state = authorization.searchParams.get("state");
assert.equal(stateCookie.split("=", 2)[1].split(";", 1)[0], state);
const attemptRow = sqlite.prepare("SELECT * FROM nr_gateway_oidc_login_attempts WHERE state_hash = ?")
  .get(Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("newrelic-chatgpt-oidc-state\0" + state))).toString("hex"));
assert.ok(attemptRow);
assert.notEqual(attemptRow.encrypted_attempt.includes(state), true, "raw state, nonce, and verifier are not stored in D1");
const [version, iv, cipher] = attemptRow.encrypted_attempt.split(".");
assert.equal(version, "v1");
const aad = new TextEncoder().encode("newrelic-chatgpt-oidc-attempt\0v1\0" + origin + "\0" + issuer);
const clearAttempt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(iv, "base64url"), additionalData: aad, tagLength: 128 },
  stateKey, Buffer.from(cipher, "base64url"));
const attempt = JSON.parse(new TextDecoder().decode(clearAttempt));
activeNonce = attempt.nonce;
activeCodeVerifier = attempt.verifier;
assert.equal(authorization.searchParams.get("nonce"), attempt.nonce);
assert.equal(authorization.searchParams.get("code_challenge"), Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(activeCodeVerifier))).toString("base64url"));
assert.equal(attemptRow.encrypted_attempt.includes(activeNonce), false);
assert.equal(attemptRow.encrypted_attempt.includes(activeCodeVerifier), false);

const callback = await gateway.fetch(new Request(origin + "/auth/callback?code=synthetic-code&state=" + encodeURIComponent(state), {
  headers: { cookie: stateCookie.split(";", 1)[0], "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(callback.status, 303);
assert.equal(callback.headers.get("location"), origin + "/auth/complete");
const setCookies = callback.headers.getSetCookie();
assert.equal(setCookies.length, 3, "session cookies and state-cookie removal are set separately");
assert.match(setCookies[0], /^__Host-nr-gateway-session=/);
assert.match(setCookies[1], /^__Host-nr-gateway-csrf=/);
assert.match(setCookies[2], /^__Host-nr-oidc-state=; Max-Age=0/);
browserCookie = setCookies.slice(0, 2).map(value => value.split(";", 1)[0]).join("; ");
const callbackCompletion = await gateway.fetch(new Request(origin + "/auth/complete", {
  headers: { cookie: browserCookie, origin: issuer, "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(callbackCompletion.status, 200, "the IdP redirect chain can reach a non-sensitive completion page");
const completionHtml = await callbackCompletion.text();
assert.match(completionHtml, /Continue to New Relic/);
assert.doesNotMatch(completionHtml, /account|synthetic-user-subject|New Relic data/i,
  "cross-site completion page discloses no account or monitoring data");
assert.equal(callbackCompletion.headers.get("cache-control"), "no-store");
const consumedRow = sqlite.prepare("SELECT consumed_at, encrypted_attempt FROM nr_gateway_oidc_login_attempts WHERE state_hash = ?")
  .get(attemptRow.state_hash);
assert.ok(consumedRow.consumed_at);
assert.equal(consumedRow.encrypted_attempt, "", "PKCE verifier and nonce are erased on first claim");
const afterLogin = await gateway.fetch(new Request(origin + "/", { headers: { cookie: browserCookie, origin,
  "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" } }));
assert.equal(afterLogin.status, 200);
assert.equal(calls.backend, 1, "only the authenticated browser reaches the private app");
const workerPath = resolve(fileURLToPath(new URL("..", import.meta.url)), "dist/server/index.js");
const worker = (await import(pathToFileURL(workerPath).href + "?oidc-login-test=" + Date.now())).default;
const workerPublicKey = Buffer.from(await crypto.subtle.exportKey("spki", gatewayKeys.publicKey)).toString("base64url");
const workerEnv = {
  NEW_RELIC_AUTH_MODE: "signed_proxy",
  NEW_RELIC_AUTH_ISSUER: "https://gateway.example.test/",
  NEW_RELIC_AUTH_AUDIENCE: "newrelic-chatgpt-mcp",
  NEW_RELIC_AUTH_JWT_KID: "gateway-key",
  NEW_RELIC_AUTH_JWT_PUBLIC_KEY: workerPublicKey,
  NEW_RELIC_AUTH_ALLOWED_SUBJECTS: JSON.stringify([expectedSubject]),
  NEW_RELIC_AUTH_ALLOWED_ORIGIN: origin,
};
const workerGateway = createSelfHostGateway({
  externalOrigin: origin, issuer: workerEnv.NEW_RELIC_AUTH_ISSUER, audience: workerEnv.NEW_RELIC_AUTH_AUDIENCE,
  keyId: workerEnv.NEW_RELIC_AUTH_JWT_KID, allowedSubjects: [expectedSubject], signingKey: gatewayKeys.privateKey,
  authenticateBrowser: sessions.authenticateBrowser, authenticateMcp: async () => null,
  verifyBrowserCsrf: sessions.verifyBrowserCsrf, browserLogin,
  backend: { fetch: request => worker.fetch(request, workerEnv) },
});
const pageDefault = await workerGateway.fetch(new Request(origin + "/", { headers: { cookie: browserCookie, origin,
  "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" } }));
assert.match((await pageDefault.text()).match(/<section id="gateway-session"[^>]*>/)[0], /hidden/,
  "self-host sign-out UI stays hidden until the gateway logout route is enabled");
workerEnv.NEW_RELIC_AUTH_GATEWAY_LOGOUT_ENABLED = "true";
const pageWithLogout = await workerGateway.fetch(new Request(origin + "/", { headers: { cookie: browserCookie, origin,
  "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" } }));
assert.equal(pageWithLogout.status, 200);
const pageWithLogoutHtml = await pageWithLogout.text();
assert.doesNotMatch(pageWithLogoutHtml.match(/<section id="gateway-session"[^>]*>/)[0], /hidden/,
  "sign-out UI appears only when the explicit gateway logout flag is enabled");
delete workerEnv.NEW_RELIC_AUTH_GATEWAY_LOGOUT_ENABLED;
const authenticatedCrossSiteRoot = await gateway.fetch(new Request(origin + "/", { headers: { cookie: browserCookie,
  origin: "https://chatgpt.com", "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" } }));
assert.equal(authenticatedCrossSiteRoot.status, 303, "cross-site navigation never receives the authenticated private home page");
assert.equal(authenticatedCrossSiteRoot.headers.get("location"), origin + "/login");
assert.equal(calls.backend, 1, "cross-site home navigation does not reach the private app even with a session cookie");
const csrfCookieValue = setCookies[1].split("=", 2)[1].split(";", 1)[0];
const badLogout = await gateway.fetch(new Request(origin + "/auth/logout", {
  method: "POST", headers: { cookie: browserCookie, origin, "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" },
}));
assert.equal(badLogout.status, 403, "logout requires same-origin CSRF proof");
assert.ok(await sessions.authenticateBrowser({ url: origin + "/", method: "GET", cookie: browserCookie,
  origin, secFetchSite: "same-origin", secFetchMode: "navigate", secFetchDest: "document", csrfToken: null }),
"a failed CSRF attempt does not revoke the browser session");
const logout = await gateway.fetch(new Request(origin + "/auth/logout", {
  method: "POST", headers: { cookie: browserCookie, origin, "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty", "x-csrf-token": csrfCookieValue },
}));
assert.equal(logout.status, 200);
assert.deepEqual(await logout.json(), { signedOut: true, newRelicConnectionPreserved: true });
assert.deepEqual(logout.headers.getSetCookie(), [
  "__Host-nr-gateway-session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax",
  "__Host-nr-gateway-csrf=; Max-Age=0; Path=/; Secure; SameSite=Strict",
  "__Host-nr-oidc-state=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax",
]);
assert.equal(await sessions.authenticateBrowser({ url: origin + "/", method: "GET", cookie: browserCookie,
  origin, secFetchSite: "same-origin", secFetchMode: "navigate", secFetchDest: "document", csrfToken: csrfCookieValue }), null,
"logout revokes only the current browser session");
const afterLogout = await gateway.fetch(new Request(origin + "/", { headers: { cookie: browserCookie, origin,
  "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" } }));
assert.equal(afterLogout.status, 303);
assert.equal(afterLogout.headers.get("location"), origin + "/login");
assert.equal(calls.backend, 1, "revoked sessions do not reach the private app");
assert.equal(JSON.stringify(calls).includes("synthetic-access-token"), false);
assert.equal(JSON.stringify(calls).includes("synthetic-refresh-token"), false);
assert.equal(JSON.stringify(setCookies).includes("synthetic-access-token"), false);

const replay = await gateway.fetch(new Request(origin + "/auth/callback?code=synthetic-code&state=" + encodeURIComponent(state), {
  headers: { cookie: stateCookie.split(";", 1)[0], "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(replay.status, 400, "callback state is single-use");
assert.equal(calls.token.length, 1, "state replay never reaches the token endpoint");

async function newAttempt(adapter = browserLogin, throughGateway = adapter === browserLogin) {
  const startRequest = new Request(origin + "/auth/start", {
    headers: { origin, "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
  });
  const response = throughGateway ? await gateway.fetch(startRequest) : await adapter.fetch(startRequest);
  const authorizeUrl = new URL(response.headers.get("location"));
  const stateValue = authorizeUrl.searchParams.get("state");
  const stateValueCookie = response.headers.getSetCookie().find(value => value.startsWith("__Host-nr-oidc-state=")).split(";", 1)[0];
  const hash = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("newrelic-chatgpt-oidc-state\0" + stateValue))).toString("hex");
  const row = sqlite.prepare("SELECT encrypted_attempt FROM nr_gateway_oidc_login_attempts WHERE state_hash = ?").get(hash);
  const [_, attemptIv, attemptCipher] = row.encrypted_attempt.split(".");
  const attemptAad = new TextEncoder().encode("newrelic-chatgpt-oidc-attempt\0v1\0" + origin + "\0" + issuer);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: Buffer.from(attemptIv, "base64url"), additionalData: attemptAad, tagLength: 128 }, stateKey, Buffer.from(attemptCipher, "base64url"));
  const transaction = JSON.parse(new TextDecoder().decode(decrypted));
  return { state: stateValue, cookie: stateValueCookie, transaction };
}

// Wrong issuer and nonce, unlisted subject, and provider redirects all stop before a session is created.
for (const mode of ["wrong-issuer", "wrong-nonce", "redirect", "expire-during-jwks"]) {
  const tx = await newAttempt();
  activeNonce = tx.transaction.nonce;
  activeCodeVerifier = tx.transaction.verifier;
  activeSubject = "synthetic-user-subject";
  tokenResponseMode = mode;
  const response = await gateway.fetch(new Request(origin + "/auth/callback?code=synthetic-code&state=" + tx.state, {
    headers: { cookie: tx.cookie, "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
  }));
  assert.equal(response.status, 502, mode);
  assert.match(response.headers.getSetCookie()[0], /^__Host-nr-oidc-state=; Max-Age=0/);
  liveNow = now;
}
tokenResponseMode = "valid";
const unknown = await newAttempt();
activeNonce = unknown.transaction.nonce;
activeCodeVerifier = unknown.transaction.verifier;
activeSubject = "unlisted-user-subject";
const unknownSubject = await gateway.fetch(new Request(origin + "/auth/callback?code=synthetic-code&state=" + unknown.state, {
  headers: { cookie: unknown.cookie, "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(unknownSubject.status, 403);
activeSubject = "synthetic-user-subject";

const basicLogin = createOidcBrowserLogin({
  db, sessions, externalOrigin: origin, issuer, clientId, clientSecret,
  authorizationEndpoint, tokenEndpoint, jwksUri, allowedEndpointOrigins: ["https://auth.example.test"],
  allowedSubjects: [expectedSubject], stateEncryptionKey: stateKey, tokenEndpointAuthMethod: "client_secret_basic", admitLoginStart,
  fetchImpl, now: () => liveNow, randomBytes,
});
const basic = await newAttempt(basicLogin, false);
activeNonce = basic.transaction.nonce;
activeCodeVerifier = basic.transaction.verifier;
tokenAuthMethodForNext = "client_secret_basic";
const basicCallback = await basicLogin.fetch(new Request(origin + "/auth/callback?code=synthetic-code&state=" + basic.state, {
  headers: { cookie: basic.cookie, "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
tokenAuthMethodForNext = "client_secret_post";
assert.equal(basicCallback.status, 303, "client_secret_basic is supported");

// Concurrent duplicate callbacks race on the D1 CAS; only one may redeem the code.
const concurrent = await newAttempt();
activeNonce = concurrent.transaction.nonce;
activeCodeVerifier = concurrent.transaction.verifier;
const beforeConcurrent = calls.token.length;
const concurrentRequest = () => new Request(origin + "/auth/callback?code=synthetic-code&state=" + concurrent.state, {
  headers: { cookie: concurrent.cookie, "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
});
const simultaneous = await Promise.all([gateway.fetch(concurrentRequest()), gateway.fetch(concurrentRequest())]);
assert.deepEqual(simultaneous.map(response => response.status).sort(), [303, 400]);
assert.equal(calls.token.length, beforeConcurrent + 1, "D1 CAS permits only one concurrent code redemption");

assert.equal(calls.jwks, 7, "JWKS is retrieved only for successful token responses");
let stalledJwksCancelled = false;
const stalledJwksLogin = createOidcBrowserLogin({
  db, sessions, externalOrigin: origin, issuer, clientId, clientSecret,
  authorizationEndpoint, tokenEndpoint, jwksUri, allowedEndpointOrigins: ["https://auth.example.test"],
  allowedSubjects: [expectedSubject], admitLoginStart, stateEncryptionKey: stateKey, requestTimeoutMs: 100,
  fetchImpl: async url => {
    if (String(url) === tokenEndpoint) {
      const idToken = await signJwt({ iss: issuer, sub: "synthetic-user-subject", aud: clientId,
        exp: Math.floor(now / 1000) + 300, iat: Math.floor(now / 1000), nonce: activeNonce });
      return Response.json({ id_token: idToken });
    }
    if (String(url) === jwksUri) return new Response(new ReadableStream({
      pull() { return new Promise(() => {}); },
      cancel() { stalledJwksCancelled = true; },
    }), { status: 200 });
    throw new Error("unexpected URL");
  },
  now: () => liveNow, randomBytes,
});
const stalledJwks = await newAttempt(stalledJwksLogin, false);
activeNonce = stalledJwks.transaction.nonce;
activeCodeVerifier = stalledJwks.transaction.verifier;
const stalledJwksCallback = await stalledJwksLogin.fetch(new Request(origin + "/auth/callback?code=synthetic-code&state=" + stalledJwks.state, {
  headers: { cookie: stalledJwks.cookie, "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(stalledJwksCallback.status, 502, "a stalled JWKS body fails closed within its timeout");
assert.equal(stalledJwksCancelled, true, "aborting a stalled JWKS read cancels its body stream");

const timeoutLogin = createOidcBrowserLogin({
  db, sessions, externalOrigin: origin, issuer, clientId, clientSecret,
  authorizationEndpoint, tokenEndpoint, jwksUri, allowedEndpointOrigins: ["https://auth.example.test"],
  allowedSubjects: [expectedSubject], admitLoginStart, stateEncryptionKey: stateKey, requestTimeoutMs: 100,
  fetchImpl: (_url, init) => new Promise((_resolve, reject) => {
    init.signal.addEventListener("abort", () => reject(new Error("mock timeout")), { once: true });
  }), now: () => liveNow, randomBytes,
});
const timeoutStart = await timeoutLogin.fetch(new Request(origin + "/auth/start", {
  headers: { origin, "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
const timeoutAuthorize = new URL(timeoutStart.headers.get("location"));
const timeoutCookie = timeoutStart.headers.getSetCookie().find(value => value.startsWith("__Host-nr-oidc-state=")).split(";", 1)[0];
const timeoutCallback = await timeoutLogin.fetch(new Request(origin + "/auth/callback?code=synthetic-code&state=" + timeoutAuthorize.searchParams.get("state"), {
  headers: { cookie: timeoutCookie, "sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document" },
}));
assert.equal(timeoutCallback.status, 502, "a stalled token endpoint is aborted within its configured bound");
assert.equal(timeoutCallback.headers.getSetCookie()[0], "__Host-nr-oidc-state=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax");
const beforeCleanup = sqlite.prepare("SELECT COUNT(*) AS count FROM nr_gateway_oidc_login_attempts").get().count;
assert.ok(beforeCleanup > 0);
assert.equal(await browserLogin.purgeExpiredAttempts({ now: now + 14 * 60 * 1000 }), beforeCleanup);
assert.equal(sqlite.prepare("SELECT COUNT(*) AS count FROM nr_gateway_oidc_login_attempts").get().count, 0);
console.log("Self-host OIDC login tests passed: PKCE, nonce, signature/issuer/audience checks, D1 single-use state, allowlist, browser session issuance, and gateway isolation; provider calls: mock only");
