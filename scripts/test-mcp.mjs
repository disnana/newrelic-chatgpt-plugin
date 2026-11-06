import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { resolve } from "node:path";
import { runInNewContext } from "node:vm";
import { fileURLToPath, pathToFileURL } from "node:url";

globalThis.crypto ||= webcrypto;
const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const workerPath = resolve(root, "dist/server/index.js");
const worker = (await import(pathToFileURL(workerPath).href + "?test=" + Date.now())).default;
const { normalizeNrql, buildComparisonNrql, validateLogFilter, validateLogWindow, filterMetricNames } =
  await import(pathToFileURL(resolve(root, "worker/nrql.js")).href + "?test=" + Date.now());
const { schemaFingerprint, canonicalJson } = await import(pathToFileURL(resolve(root, "worker/mcp-policy.js")).href + "?test=" + Date.now());
const { beginNewRelicAuthorization, completePastedNewRelicAuthorization, disconnectNewRelic, decryptSecret, encryptSecret, siteUserId, approvalBrowserBinding, getConnectionStatus, withNewRelicSession, findNewRelicTool } =
  await import(pathToFileURL(resolve(root, "worker/newrelic.js")).href + "?test=" + Date.now());
const { updateUsageConsents } = await import(pathToFileURL(resolve(root, "worker/usage-consent.js")).href + "?test=" + Date.now());

class MemoryD1 {
  states = new Map();
  connections = new Map();
  preferences = new Map();
  rates = new Map();
  locks = new Map();
  consents = new Map();
  operations = 0;

  prepare(query) {
    this.operations += 1;
    const normalized = query.replace(/\s+/g, " ").trim().toUpperCase();
    const database = this;
    return {
      values: [],
      bind(...values) { this.values = values; return this; },
      async run() { return database.run(normalized, this.values); },
      async first() { return database.first(normalized, this.values); },
      async all() { return database.all(normalized, this.values); },
    };
  }

  async batch(statements) {
    const results = [];
    for (const statement of statements) {
      results.push(await statement.run());
      await this.afterBatchStatement?.(results.length, statement);
    }
    return results;
  }

  async run(query, values) {
    if (query.startsWith("INSERT INTO NR_USAGE_CONSENTS")) {
      const [user_id, capability, granted_at, expires_at] = values;
      this.consents.set(user_id + ":" + capability, { user_id, capability, granted_at, expires_at });
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM NR_USAGE_CONSENTS WHERE USER_ID = ? AND CAPABILITY = ?")) {
      const changed = this.consents.delete(values[0] + ":" + values[1]);
      return { meta: { changes: changed ? 1 : 0 } };
    }
    if (query.startsWith("INSERT INTO NR_REFRESH_LOCKS")) {
      const [userId, owner, expires, now] = values;
      const prior = this.locks.get(userId);
      if (prior && prior.expires_at >= now) return { meta: { changes: 0 } };
      this.locks.set(userId, { owner, expires_at: expires });
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM NR_REFRESH_LOCKS")) {
      const [userId, owner] = values;
      if (this.locks.get(userId)?.owner === owner) this.locks.delete(userId);
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM NR_CONNECTIONS WHERE USER_ID = ?")) {
      const changed = this.connections.delete(values[0]);
      return { meta: { changes: changed ? 1 : 0 } };
    }
    if (query.startsWith("DELETE FROM NR_PREFERENCES WHERE USER_ID = ?")) {
      const changed = this.preferences.delete(values[0]);
      return { meta: { changes: changed ? 1 : 0 } };
    }
    if (query.startsWith("INSERT INTO NR_PREFERENCES")) {
      const [user_id, account_id, account_name, updated_at, selection_generation] = values;
      const prior = this.preferences.get(user_id);
      this.preferences.set(user_id, {
        user_id, account_id, account_name, updated_at,
        selection_generation: prior && prior.account_id === account_id ? prior.selection_generation : selection_generation,
      });
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM NR_OAUTH_STATES WHERE USER_ID = ?")) {
      let changes = 0;
      for (const [key, row] of this.states) if (row.user_id === values[0]) { this.states.delete(key); changes += 1; }
      return { meta: { changes } };
    }
    if (query.startsWith("UPDATE NR_OAUTH_STATES SET CONSUMED_AT = ?")) {
      const [consumedAt, stateHash, userId, expiresAt] = values;
      const row = this.states.get(stateHash);
      if (row?.user_id === userId && row.consumed_at == null && row.expires_at >= expiresAt) {
        row.consumed_at = consumedAt;
        return { meta: { changes: 1 } };
      }
      return { meta: { changes: 0 } };
    }
    if (query.startsWith("UPDATE NR_CONNECTIONS SET ENCRYPTED_ACCESS_TOKEN")) {
      const [access, refresh, expiry, userId, oldRefresh, lockUser, owner, now] = values;
      const row = this.connections.get(userId);
      const lock = this.locks.get(lockUser);
      if (!row || row.encrypted_refresh_token !== oldRefresh || lock?.owner !== owner || lock.expires_at <= now) return { meta: { changes: 0 } };
      Object.assign(row, { encrypted_access_token: access, encrypted_refresh_token: refresh, access_expires_at: expiry });
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM NR_OAUTH_STATES WHERE EXPIRES_AT <")) {
      for (const [key, row] of this.states) if (row.expires_at < values[0]) this.states.delete(key);
      return { meta: { changes: 0 } };
    }
    if (query.startsWith("INSERT INTO NR_OAUTH_STATES")) {
      const [state_hash, user_id, encrypted_verifier, redirect_uri, region, expires_at] = values;
      this.states.set(state_hash, { state_hash, user_id, encrypted_verifier, redirect_uri, region, expires_at, consumed_at: null });
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM NR_OAUTH_STATES WHERE STATE_HASH = ? AND USER_ID = ?")) {
      const [stateHash, userId, consumedAt] = values;
      const row = this.states.get(stateHash);
      const allowed = row?.user_id === userId && (values.length < 3 || row.consumed_at === consumedAt);
      if (allowed) this.states.delete(stateHash);
      return { meta: { changes: allowed ? 1 : 0 } };
    }
    if (query.startsWith("DELETE FROM NR_RATE_LIMITS")) {
      const [userId, before] = values;
      for (const [key, row] of this.rates) if (row.user_id === userId && row.window_start < before) this.rates.delete(key);
      return { meta: { changes: 0 } };
    }
    if (query.startsWith("INSERT INTO NR_RATE_LIMITS")) {
      const [userId, windowStart] = values;
      const key = userId + ":" + windowStart;
      const row = this.rates.get(key) || { user_id: userId, window_start: windowStart, call_count: 0 };
      row.call_count += 1;
      this.rates.set(key, row);
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("INSERT INTO NR_CONNECTIONS")) {
      const [user_id, encrypted_access_token, encrypted_refresh_token, access_expires_at, connected_at, region, connection_generation, stateHash, expectedUserId, consumedAt, nowSeconds] = values;
      if (query.includes("WHERE EXISTS (SELECT 1 FROM NR_OAUTH_STATES")) {
        const state = this.states.get(stateHash);
        if (state?.user_id !== expectedUserId || state.consumed_at !== consumedAt || state.expires_at < nowSeconds) return { meta: { changes: 0 } };
      }
      this.connections.set(user_id, { user_id, encrypted_access_token, encrypted_refresh_token, access_expires_at, connected_at, region, connection_generation });
      return { meta: { changes: 1 } };
    }
    throw new Error("Unexpected mock D1 run query: " + query);
  }

  async first(query, values) {
    if (query.includes("FROM NR_CONNECTIONS WHERE USER_ID = ?")) { const row = this.connections.get(values[0]); return row ? { ...row } : null; }
    if (query.includes("FROM NR_PREFERENCES WHERE USER_ID = ?")) return this.preferences.get(values[0]) || null;
    if (query.startsWith("SELECT USER_ID, ENCRYPTED_VERIFIER")) return this.states.get(values[0]) || null;
    if (query.startsWith("SELECT CALL_COUNT FROM NR_RATE_LIMITS")) {
      const [userId, windowStart] = values;
      return this.rates.get(userId + ":" + windowStart) || null;
    }
    throw new Error("Unexpected mock D1 first query: " + query);
  }

  async all(query, values) {
    if (query.includes("FROM NR_USAGE_CONSENTS WHERE USER_ID = ?")) {
      return { results: [...this.consents.values()].filter(row => row.user_id === values[0]).map(row => ({ ...row })) };
    }
    throw new Error("Unexpected mock D1 all query: " + query);
  }
}

async function call(method, params = {}, env = {}, identity = null, id = 1) {
  const headers = { "content-type": "application/json" };
  if (identity) headers["oai-authenticated-user-id"] = identity;
  const request = new Request("https://example.test/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
  });
  const response = await worker.fetch(request, env);
  const raw = await response.text();
  return { response, raw, payload: JSON.parse(raw) };
}

const discovery = await call("server/discover");
assert.equal(discovery.response.status, 200);
assert.deepEqual(discovery.payload.result.supportedVersions, ["2026-07-28"]);

const listed = await call("tools/list");
const toolNames = listed.payload.result.tools.map((tool) => tool.name);
for (const name of [
  "ping",
  "get_connection_status",
  "connect_new_relic",
  "disconnect_new_relic",
  "list_accounts",
  "select_account",
  "execute_nrql",
  "search_metrics",
  "query_logs",
  "list_alerts",
  "investigate_latency",
  "compare_time_ranges",
]) assert.ok(toolNames.includes(name), "Missing MCP tool " + name);
assert.equal(listed.payload.result.tools.find(tool => tool.name === "get_mcp_capability_schema")
  .inputSchema.properties.offset.maximum, 1024 * 1024,
"schema chunks can continue through the maximum canonical schema size");
assert.equal(listed.payload.result.tools.find((tool) => tool.name === "disconnect_new_relic").annotations.readOnlyHint, false);
assert.equal(listed.payload.result.tools.find((tool) => tool.name === "disconnect_new_relic").annotations.destructiveHint, true);
assert.equal(listed.payload.result.tools.find((tool) => tool.name === "execute_nrql").annotations.readOnlyHint, true);

const rejectedContentType = await worker.fetch(new Request("https://example.test/mcp", {
  method: "POST", headers: { "content-type": "text/plain" }, body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/list" }),
}), {});
assert.equal((await rejectedContentType.json()).error.code, -32600);
const oversizedStream = new ReadableStream({
  start(controller) { controller.enqueue(new Uint8Array(16 * 1024 + 1)); controller.close(); },
});
const rejectedOversizedBody = await worker.fetch(new Request("https://example.test/mcp", {
  method: "POST", headers: { "content-type": "application/json" }, body: oversizedStream, duplex: "half",
}), {});
assert.equal((await rejectedOversizedBody.json()).error.message, "Request too large");
const oversizedApiBody = new ReadableStream({
  start(controller) { controller.enqueue(new Uint8Array(8193)); controller.close(); },
});
const rejectedOversizedApi = await worker.fetch(new Request("https://example.test/api/oauth/manual-complete", {
  method: "POST", headers: { "content-type": "application/json", origin: "https://example.test", "oai-authenticated-user-id": "test-user" },
  body: oversizedApiBody, duplex: "half",
}), {});
assert.equal((await rejectedOversizedApi.json()).error, "リクエストが大きすぎます。");

const pong = await call("tools/call", { name: "ping", arguments: {} });
assert.equal(pong.payload.result.content[0].text, "pong");
assert.equal(pong.payload.result.structuredContent.ok, true);
const oversizedId = await call("tools/call", { name: "ping", arguments: {} }, {}, null, "x".repeat(12000));
assert.equal(oversizedId.payload.error.code, -32600);
assert.equal(oversizedId.payload.id, null);
assert.ok(new TextEncoder().encode(oversizedId.raw).byteLength <= 10000, "oversized request IDs must not defeat the MCP response budget");

// Signed-proxy self-host auth is opt-in and uses a pinned public key. The Site
// identity header must never act as a fallback in this mode.
const gatewayKeys = await webcrypto.subtle.generateKey({
  name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256",
}, true, ["sign", "verify"]);
const gatewayPublicKey = Buffer.from(await webcrypto.subtle.exportKey("spki", gatewayKeys.publicKey)).toString("base64url");
const signedProxyEnv = {
  NEW_RELIC_AUTH_MODE: "signed_proxy",
  NEW_RELIC_AUTH_JWT_PUBLIC_KEY: gatewayPublicKey,
  NEW_RELIC_AUTH_JWT_KID: "fixture-key",
  NEW_RELIC_AUTH_ISSUER: "https://auth.example.test/",
  NEW_RELIC_AUTH_AUDIENCE: "newrelic-chatgpt-mcp",
  NEW_RELIC_AUTH_ALLOWED_ORIGIN: "https://example.test",
  NEW_RELIC_AUTH_ALLOWED_SUBJECTS: JSON.stringify(["owner-1", "member-2"]),
};
const encodeJwtPart = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
async function makeGatewayJwt(claims, header = {}, signingKeys = gatewayKeys) {
  const protectedHeader = { alg: "RS256", typ: "JWT", kid: "fixture-key", ...header };
  const signingInput = encodeJwtPart(protectedHeader) + "." + encodeJwtPart(claims);
  const signature = await webcrypto.subtle.sign("RSASSA-PKCS1-v1_5", signingKeys.privateKey, new TextEncoder().encode(signingInput));
  return signingInput + "." + Buffer.from(signature).toString("base64url");
}
const issuedAt = Math.floor(Date.now() / 1000);
const ownerClaims = {
  iss: signedProxyEnv.NEW_RELIC_AUTH_ISSUER,
  aud: signedProxyEnv.NEW_RELIC_AUTH_AUDIENCE,
  sub: "owner-1",
  iat: issuedAt,
  exp: issuedAt + 300,
};
const ownerJwt = await makeGatewayJwt(ownerClaims);
const signedRequest = new Request("https://example.test/mcp", {
  headers: { authorization: "Bearer " + ownerJwt, "oai-authenticated-user-id": "forged-sites-user" },
});
const ownerUserId = await siteUserId(signedRequest, signedProxyEnv);
assert.ok(ownerUserId);
assert.equal(await siteUserId(new Request("https://example.test/", {
  headers: { "oai-authenticated-user-id": "forged-sites-user" },
}), signedProxyEnv), null, "a forged Sites identity header is ignored by signed-proxy mode");
const sameOwnerJwt = await makeGatewayJwt({ ...ownerClaims, iat: issuedAt + 1, exp: issuedAt + 301 });
assert.equal(await siteUserId(new Request("https://example.test/", {
  headers: { authorization: "Bearer " + sameOwnerJwt },
}), signedProxyEnv), ownerUserId, "principal storage identity is stable across short-lived assertions");
const browserSessionId = "stable-browser-session-identifier-0123456789";
const browserAssertion = await makeGatewayJwt({ ...ownerClaims, channel: "browser", sid: browserSessionId });
const browserApprovalRequest = new Request("https://example.test/api/operation-approvals/session", {
  method: "POST", headers: { authorization: "Bearer " + browserAssertion },
});
const approvalBinding = await approvalBrowserBinding(browserApprovalRequest, signedProxyEnv);
assert.match(approvalBinding, /^[A-Za-z0-9_-]{43}$/);
const renewedBrowserAssertion = await makeGatewayJwt({
  ...ownerClaims, channel: "browser", sid: browserSessionId, iat: issuedAt + 1, exp: issuedAt + 301,
});
assert.equal(await approvalBrowserBinding(new Request("https://example.test/api/operation-approvals/session", {
  headers: { authorization: "Bearer " + renewedBrowserAssertion },
}), signedProxyEnv), approvalBinding, "renewed gateway assertions preserve the signed browser-session binding");
assert.equal(await approvalBrowserBinding(new Request("https://example.test/api/operation-approvals/session", {
  headers: { authorization: "Bearer " + ownerJwt },
}), signedProxyEnv), null, "MCP/legacy assertions cannot bootstrap approval sessions");
const otherBrowserAssertion = await makeGatewayJwt({ ...ownerClaims, channel: "browser", sid: "another-browser-session-id-0123456789" });
assert.notEqual(await approvalBrowserBinding(new Request("https://example.test/api/operation-approvals/session", {
  headers: { authorization: "Bearer " + otherBrowserAssertion },
}), signedProxyEnv), approvalBinding, "different gateway browser sessions use different approval bindings");
const memberJwt = await makeGatewayJwt({ ...ownerClaims, sub: "member-2" });
const memberUserId = await siteUserId(new Request("https://example.test/", {
  headers: { authorization: "Bearer " + memberJwt },
}), signedProxyEnv);
assert.notEqual(memberUserId, ownerUserId, "signed-proxy subjects map to separate storage identities");
const rotatedGatewayKeys = await webcrypto.subtle.generateKey({
  name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256",
}, true, ["sign", "verify"]);
const rotatedGatewayPublicKey = Buffer.from(await webcrypto.subtle.exportKey("spki", rotatedGatewayKeys.publicKey)).toString("base64url");
const rotatedEnv = { ...signedProxyEnv, NEW_RELIC_AUTH_JWT_PUBLIC_KEY: rotatedGatewayPublicKey, NEW_RELIC_AUTH_JWT_KID: "rotated-key" };
const rotatedOwnerJwt = await makeGatewayJwt(ownerClaims, { kid: "rotated-key" }, rotatedGatewayKeys);
assert.equal(await siteUserId(new Request("https://example.test/", {
  headers: { authorization: "Bearer " + rotatedOwnerJwt },
}), rotatedEnv), ownerUserId, "key rotation preserves a subject's storage identity");
const [headerPart, claimsPart, signaturePart] = ownerJwt.split(".");
const tamperedSignature = (signaturePart[0] === "A" ? "B" : "A") + signaturePart.slice(1);
const invalidJwtRequests = [
  "Bearer invalid",
  "Bearer " + headerPart + "." + claimsPart + "." + tamperedSignature,
  "Bearer " + await makeGatewayJwt({ ...ownerClaims, iss: "https://wrong.example.test/" }),
  "Bearer " + await makeGatewayJwt({ ...ownerClaims, aud: "wrong-audience" }),
  "Bearer " + await makeGatewayJwt({ ...ownerClaims, exp: issuedAt - 60 }),
  "Bearer " + await makeGatewayJwt({ ...ownerClaims, iat: issuedAt + 600 }),
  "Bearer " + await makeGatewayJwt({ ...ownerClaims, exp: issuedAt + 901 }),
  "Bearer " + await makeGatewayJwt({ ...ownerClaims, nbf: issuedAt + 60 }),
  "Bearer " + await makeGatewayJwt({ ...ownerClaims, nbf: issuedAt + 301 }),
  "Bearer " + await makeGatewayJwt({ ...ownerClaims, sub: "not-allowed" }),
  "Bearer " + await makeGatewayJwt(ownerClaims, { alg: "HS256" }),
  "Bearer " + await makeGatewayJwt(ownerClaims, { jku: "https://attacker.example/keys" }),
  "Bearer " + await makeGatewayJwt(ownerClaims, { kid: "other-key" }),
];
for (const authorization of invalidJwtRequests) {
  assert.equal(await siteUserId(new Request("https://example.test/", {
    headers: { authorization, "oai-authenticated-user-id": "forged-sites-user" },
  }), signedProxyEnv), null, "invalid signed assertions fail closed without Sites-header fallback");
}
assert.equal(await siteUserId(new Request("https://example.test/", {
  headers: { authorization: "Bearer " + ownerJwt },
}), { ...signedProxyEnv, NEW_RELIC_AUTH_JWT_PUBLIC_KEY: "bad-key" }), null, "malformed auth config fails closed");
assert.equal(await siteUserId(new Request("https://example.test/", {
  headers: { authorization: "Bearer " + ownerJwt },
}), { ...signedProxyEnv, NEW_RELIC_AUTH_ISSUER: "http://auth.example.test/" }), null, "insecure issuer configuration fails closed");
assert.equal(await siteUserId(new Request("https://example.test/", {
  headers: { authorization: "Bearer " + ownerJwt },
}), { ...signedProxyEnv, NEW_RELIC_AUTH_ALLOWED_ORIGIN: "http://example.test" }), null, "insecure Origin configuration fails closed");

const signedPingRequest = new Request("https://example.test/mcp", {
  method: "POST",
  headers: { "content-type": "application/json", authorization: "Bearer " + ownerJwt, origin: "https://example.test" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "ping", arguments: {} } }),
});
const signedPing = await worker.fetch(signedPingRequest, signedProxyEnv);
assert.equal(signedPing.status, 200);
assert.equal((await signedPing.json()).result.content[0].text, "pong");
const signedCrossOrigin = await worker.fetch(new Request("https://example.test/mcp", {
  method: "POST",
  headers: { "content-type": "application/json", authorization: "Bearer " + ownerJwt, origin: "https://attacker.example" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 5, method: "tools/list" }),
}), signedProxyEnv);
assert.equal(signedCrossOrigin.status, 403, "signed-proxy mode rejects browser MCP requests from other origins");
const signedCrossSiteWithoutOrigin = await worker.fetch(new Request("https://example.test/mcp", {
  method: "POST",
  headers: { "content-type": "application/json", authorization: "Bearer " + ownerJwt, "sec-fetch-site": "cross-site" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 6, method: "tools/list" }),
}), signedProxyEnv);
assert.equal(signedCrossSiteWithoutOrigin.status, 403, "signed-proxy mode checks fetch metadata even without an Origin header");
const unauthenticatedSignedMcp = await worker.fetch(new Request("https://example.test/mcp", {
  method: "POST", headers: { "content-type": "application/json", "oai-authenticated-user-id": "forged-sites-user" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 3, method: "tools/list" }),
}), signedProxyEnv);
assert.equal(unauthenticatedSignedMcp.status, 401);
assert.equal((await unauthenticatedSignedMcp.text()).includes(ownerJwt), false);
const invalidBearerMarker = "synthetic-invalid-private-marker";
const invalidBearerMcp = await worker.fetch(new Request("https://example.test/mcp", {
  method: "POST", headers: { "content-type": "application/json", authorization: "Bearer " + invalidBearerMarker },
  body: JSON.stringify({ jsonrpc: "2.0", id: 10, method: "tools/list" }),
}), signedProxyEnv);
assert.equal(invalidBearerMcp.status, 401);
assert.equal((await invalidBearerMcp.text()).includes(invalidBearerMarker), false, "authentication errors never echo assertion text");
const invalidAuthMode = await worker.fetch(new Request("https://example.test/mcp", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/list" }),
}), { NEW_RELIC_AUTH_MODE: "unknown" });
assert.equal(invalidAuthMode.status, 503);
const blankAuthMode = await worker.fetch(new Request("https://example.test/mcp", {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 12, method: "tools/list" }),
}), { NEW_RELIC_AUTH_MODE: "" });
assert.equal(blankAuthMode.status, 503, "an explicitly blank auth mode must not silently fall back to Sites identity headers");
const signedDeniedEnv = { ...signedProxyEnv, DB: new MemoryD1() };
const noAuthUpstreamFetch = globalThis.fetch;
let unauthenticatedUpstreamCalls = 0;
globalThis.fetch = async () => { unauthenticatedUpstreamCalls += 1; throw new Error("unexpected unauthenticated upstream request"); };
try {
  const unauthenticatedRoutes = [
    ["/api/status", { method: "GET" }],
    ["/api/select-account", { method: "POST" }],
    ["/oauth/start", { method: "GET" }],
    ["/oauth/callback?state=untrusted&code=untrusted", { method: "GET" }],
    ["/mcp", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" }) }],
  ];
  for (const [path, init] of unauthenticatedRoutes) {
    const headers = new Headers(init.headers || {});
    headers.set("authorization", "Bearer invalid");
    headers.set("oai-authenticated-user-id", "forged-sites-user");
    const response = await worker.fetch(new Request("https://example.test" + path, { ...init, headers }), signedDeniedEnv);
    assert.equal(response.status, 401, "invalid signed assertions deny every protected route");
  }
} finally {
  globalThis.fetch = noAuthUpstreamFetch;
}
assert.equal(signedDeniedEnv.DB.operations, 0, "invalid assertions cause zero D1 operations");
assert.equal(unauthenticatedUpstreamCalls, 0, "invalid assertions cause zero provider requests");
const signedRuntimeEnv = {
  ...signedProxyEnv,
  NEW_RELIC_TOKEN_ENCRYPTION_KEY: Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString("base64url"),
  DB: new MemoryD1(),
};
const signedInternalConnect = await worker.fetch(new Request("https://worker.internal/mcp", {
  method: "POST",
  headers: { "content-type": "application/json", authorization: "Bearer " + ownerJwt, origin: "https://example.test" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "connect_new_relic", arguments: { region: "jp" } } }),
}), signedRuntimeEnv);
const signedInternalConnectPayload = await signedInternalConnect.json();
assert.equal(new URL(signedInternalConnectPayload.result.structuredContent.connectUrl).origin, "https://example.test",
  "self-host authorization links use the configured external origin behind a reverse proxy");
assert.equal(new URL(signedInternalConnectPayload.result.structuredContent.connectUrl).pathname, "/",
  "ChatGPT connect links go to the safe landing page, not a cross-site side-effecting OAuth GET");
assert.equal(new URL(signedInternalConnectPayload.result.structuredContent.connectUrl).searchParams.get("connect_region"), "jp");
const signedInternalDisconnect = await worker.fetch(new Request("https://worker.internal/mcp", {
  method: "POST",
  headers: { "content-type": "application/json", authorization: "Bearer " + ownerJwt, origin: "https://example.test" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 8, method: "tools/call", params: { name: "disconnect_new_relic", arguments: {} } }),
}), signedRuntimeEnv);
const signedInternalDisconnectPayload = await signedInternalDisconnect.json();
assert.equal(new URL(signedInternalDisconnectPayload.result.structuredContent.connectionPage).origin, "https://example.test",
  "self-host account links use the configured external origin behind a reverse proxy");
const signedMissingStatus = await worker.fetch(new Request("https://example.test/api/status"), signedRuntimeEnv);
assert.equal(signedMissingStatus.status, 401, "self-host API status requires the gateway assertion");
const signedMissingOAuth = await worker.fetch(new Request("https://example.test/oauth/start?region=jp"), signedRuntimeEnv);
assert.equal(signedMissingOAuth.status, 401, "self-host OAuth start requires the gateway assertion");
const signedCrossOriginOAuth = await worker.fetch(new Request("https://example.test/oauth/start?region=jp", {
  headers: { authorization: "Bearer " + ownerJwt, origin: "https://attacker.example", "sec-fetch-site": "cross-site" },
}), signedRuntimeEnv);
assert.equal(signedCrossOriginOAuth.status, 403, "cross-site OAuth start is rejected in signed-proxy mode");
const signedOwnerStart = await worker.fetch(new Request("https://example.test/oauth/start?region=jp", {
  headers: { authorization: "Bearer " + ownerJwt },
}), signedRuntimeEnv);
assert.equal(signedOwnerStart.status, 302);
assert.equal([...signedRuntimeEnv.DB.states.values()][0].user_id, ownerUserId, "OAuth state is bound to the signed owner principal");
const signedMemberStart = await worker.fetch(new Request("https://example.test/oauth/start?region=jp", {
  headers: { authorization: "Bearer " + memberJwt },
}), signedRuntimeEnv);
assert.equal(signedMemberStart.status, 302);
assert.deepEqual(new Set([...signedRuntimeEnv.DB.states.values()].map(row => row.user_id)), new Set([ownerUserId, memberUserId]));
const signedOAuthLocation = new URL(signedOwnerStart.headers.get("location"));
const signedCallbackUrl = signedOAuthLocation.searchParams.get("redirect_uri") + "?code=synthetic-signed-code&state="
  + encodeURIComponent(signedOAuthLocation.searchParams.get("state"));
const signedOriginalFetch = globalThis.fetch;
globalThis.fetch = async (url, options) => {
  assert.equal(String(url), "https://oauth2.service.newrelic.com/oauth2/token");
  assert.equal(new URLSearchParams(options.body).get("code"), "synthetic-signed-code");
  return Response.json({ access_token: "synthetic-access-token", refresh_token: "synthetic-refresh-token", expires_in: 300 });
};
try {
  const wrongSignedPrincipal = await worker.fetch(new Request("https://example.test/api/oauth/manual-complete", {
    method: "POST",
    headers: { authorization: "Bearer " + memberJwt, origin: "https://example.test", "content-type": "application/json" },
    body: JSON.stringify({ callbackUrl: signedCallbackUrl }),
  }), signedRuntimeEnv);
  assert.equal(wrongSignedPrincipal.status, 401, "a second signed subject cannot consume another user's OAuth state");
  const signedOwnerCompletion = await worker.fetch(new Request("https://example.test/api/oauth/manual-complete", {
    method: "POST",
    headers: { authorization: "Bearer " + ownerJwt, origin: "https://example.test", "content-type": "application/json" },
    body: JSON.stringify({ callbackUrl: signedCallbackUrl }),
  }), signedRuntimeEnv);
  assert.equal(signedOwnerCompletion.status, 200);
  assert.deepEqual(await signedOwnerCompletion.json(), { connected: true, region: "jp" });
  assert.ok(signedRuntimeEnv.DB.connections.has(ownerUserId), "OAuth completion stores credentials only for the initiating subject");
  assert.equal(signedRuntimeEnv.DB.connections.has(memberUserId), false);
} finally {
  globalThis.fetch = signedOriginalFetch;
}
signedRuntimeEnv.DB.connections.get(ownerUserId).access_expires_at = Date.now() - 1000;
const signedStatusFetch = globalThis.fetch;
let signedStatusUpstreamCalls = 0;
globalThis.fetch = async () => { signedStatusUpstreamCalls += 1; throw new Error("status must remain local"); };
let signedOwnerStatus;
let signedMcpStatus;
try {
  signedOwnerStatus = await worker.fetch(new Request("https://example.test/api/status", {
    headers: { authorization: "Bearer " + ownerJwt },
  }), signedRuntimeEnv);
  signedMcpStatus = await worker.fetch(new Request("https://example.test/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + ownerJwt },
    body: JSON.stringify({ jsonrpc: "2.0", id: 11, method: "tools/call", params: { name: "get_connection_status", arguments: {} } }),
  }), signedRuntimeEnv);
} finally {
  globalThis.fetch = signedStatusFetch;
}
assert.equal(signedOwnerStatus.status, 200);
const localApiStatus = await signedOwnerStatus.json();
assert.equal(localApiStatus.tokenRefreshDue, true);
assert.equal(localApiStatus.statusSource, "local_metadata");
assert.equal(localApiStatus.providerReachable, null);
const localMcpStatus = await signedMcpStatus.json();
assert.equal(localMcpStatus.result.structuredContent.tokenRefreshDue, true);
assert.equal(localMcpStatus.result.structuredContent.statusSource, "local_metadata");
assert.equal(localApiStatus.connected, true);
assert.equal(localMcpStatus.result.structuredContent.connected, true);
assert.equal(signedStatusUpstreamCalls, 0, "expired status checks do not refresh or contact New Relic");
const diagnosticOriginalFetch = globalThis.fetch;
const diagnosticProviderCalls = [];
globalThis.fetch = async (url) => {
  diagnosticProviderCalls.push(new URL(String(url)).pathname);
  if (diagnosticProviderCalls.length === 1) {
    return Response.json({ error: "invalid_grant", error_description: "synthetic-private-token-marker" }, { status: 400 });
  }
  return Response.json({ error: "synthetic-provider-error-marker", error_description: "synthetic-private-token-marker" }, { status: 400 });
};
try {
  const accountFailure = await worker.fetch(new Request("https://example.test/api/accounts", {
    headers: { authorization: "Bearer " + ownerJwt, origin: "https://example.test" },
  }), signedRuntimeEnv);
  assert.equal(accountFailure.status, 401);
  const accountFailureBody = await accountFailure.json();
  assert.equal(accountFailureBody.errorCode, "oauth_invalid_grant");
  assert.equal(JSON.stringify(accountFailureBody).includes("synthetic-private-token-marker"), false);
  const mcpFailure = await worker.fetch(new Request("https://example.test/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer " + ownerJwt, origin: "https://example.test" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 12, method: "tools/call", params: { name: "list_accounts", arguments: {} } }),
  }), signedRuntimeEnv);
  const mcpFailureBody = await mcpFailure.json();
  assert.equal(mcpFailureBody.result.structuredContent.errorCode, "oauth_rejected",
    "provider-supplied error codes are mapped to a fixed safe diagnostic code");
  assert.equal(JSON.stringify(mcpFailureBody).includes("synthetic-private-token-marker"), false);
  assert.equal(JSON.stringify(mcpFailureBody).includes("synthetic-provider-error-marker"), false);
} finally {
  globalThis.fetch = diagnosticOriginalFetch;
}
assert.deepEqual(diagnosticProviderCalls, ["/oauth2/token", "/oauth2/token"],
  "diagnostic code tests use only mocked OAuth refresh endpoints, not MCP read calls");
const signedMutationWithoutOrigin = await worker.fetch(new Request("https://example.test/api/disconnect", {
  method: "POST", headers: { authorization: "Bearer " + ownerJwt },
}), signedRuntimeEnv);
assert.equal(signedMutationWithoutOrigin.status, 403, "browser-facing signed-proxy mutations require the configured Origin");

const unknown = await call("tools/call", { name: "unknown_tool", arguments: {} });
assert.equal(unknown.payload.error.code, -32602);

const pageResponse = await worker.fetch(new Request("https://example.test/"), {});
assert.equal(pageResponse.status, 200);
const page = await pageResponse.text();
assert.match(page, /id="load-accounts"/);
assert.match(page, /id="reconnect-link"/);
assert.match(page, /New Relic接続情報を保存済み（有効性未確認）/);
assert.match(page, /loadAccountsButton\.addEventListener/);
assert.doesNotMatch(page, /await loadAccounts\(state\.selectedAccount\)/, "opening or refreshing status must not automatically fetch a billed account list");
assert.match(page, /lang="ja"/);
assert.match(page, /New Relic公式OAuth/);
assert.match(page, /prefers-color-scheme: dark/);
assert.match(page, /requiresReauthentication/);
const uiElements = new Map();
class FakeElement {
  children = [];
  listeners = {};
  dataset = {};
  classList = { add() {}, remove() {}, toggle() {} };
  disabled = false;
  checked = false;
  hidden = false;
  textContent = "";
  href = "";
  addEventListener(type, callback) { this.listeners[type] = callback; }
  replaceChildren() { this.children = []; }
  append(child) { this.children.push(child); }
}
const fakeDocument = {
  querySelector(selector) {
    if (!uiElements.has(selector)) uiElements.set(selector, new FakeElement());
    return uiElements.get(selector);
  },
  createElement() { return new FakeElement(); },
};
const uiRequests = [];
const uiRequestOptions = [];
let rejectAccountList = false;
let rejectAccountSelection = false;
const fakeFetch = async (path, options = {}) => {
  uiRequests.push(path);
  uiRequestOptions.push(options);
  if (path === "/api/status") return Response.json({
    authenticated: true, connected: true, connectedAt: Date.now(), region: "us",
    selectedAccount: { id: "account-second", name: "Second account" },
    tokenRefreshDue: false, requiresReauthentication: false,
    refreshError: null, providerReachable: null, statusSource: "local_metadata",
  });
  if (path === "/api/usage-consent" && (!options.method || options.method === "GET")) return Response.json({ usageConsents: {
    core_compute: { enabled: true, expiresAt: Date.now() + 100000 },
    advanced_compute: { enabled: false, expiresAt: null },
    preview: { enabled: false, expiresAt: null },
  } });
  if (path === "/api/usage-consent" && options.method === "POST") return Response.json({ usageConsents: {
    core_compute: { enabled: true, expiresAt: Date.now() + 100000 },
    advanced_compute: { enabled: false, expiresAt: null },
    preview: { enabled: false, expiresAt: null },
  } });
  if (path === "/api/accounts") {
    if (rejectAccountList) return Response.json({ error: "New Relic access requires reauthentication", errorCode: "oauth_invalid_grant" }, { status: 401 });
    return Response.json({
      accounts: [{ id: "account-first", name: "First account" }, { id: "account-second", name: "Second account" }],
      selectedAccount: { id: "account-second", name: "Second account" },
    });
  }
  if (path === "/api/select-account" && rejectAccountSelection) {
    return Response.json({ error: "New Relic access requires reauthentication", errorCode: "oauth_invalid_grant" }, { status: 401 });
  }
  throw new Error("Unexpected UI request " + path);
};
runInNewContext(page.match(/<script>([\s\S]*?)<\/script>/)[1], {
  document: fakeDocument, fetch: fakeFetch, Response, Date, URL,
  window: { location: { href: "https://example.test/" } }, setTimeout,
});
await new Promise(resolve => setTimeout(resolve, 0));
assert.deepEqual(uiRequests, ["/api/status", "/api/usage-consent"], "status view may read consent metadata, but must not auto-fetch New Relic account data");
assert.equal(uiElements.get("#consent-core").checked, true);
assert.equal(uiElements.get("#consent-advanced").checked, false, "Advanced remains a separate consent");
assert.equal(uiElements.get("#reconnect-link").href, "/oauth/start?region=us");
assert.match(uiElements.get("#connection-detail").textContent, /有効性・到達性は未確認/);
await uiElements.get("#load-accounts").listeners.click();
assert.deepEqual(uiRequests, ["/api/status", "/api/usage-consent", "/api/accounts"]);
assert.equal(uiElements.get("#account").children[0].selected, false);
assert.equal(uiElements.get("#account").children[1].selected, true,
  "the saved account remains selected even when it is not the first listed account");
assert.equal(uiElements.get("#select-account").disabled, false);
uiElements.get("#consent-advanced").checked = true;
await uiElements.get("#usage-form").listeners.submit({ preventDefault() {} });
assert.equal(uiRequests.at(-1), "/api/usage-consent");
assert.equal(JSON.parse(uiRequestOptions.at(-1).body).advanced_compute, true, "the UI sends the user's explicit Advanced choice");
uiElements.get("#account").value = "account-second";
rejectAccountSelection = true;
await uiElements.get("#select-account").listeners.click();
assert.match(uiElements.get("#account-hint").textContent, /oauth_invalid_grant/,
  "account-selection failures should display only the server's safe diagnostic code");
rejectAccountList = true;
await uiElements.get("#load-accounts").listeners.click();
assert.match(uiElements.get("#account-hint").textContent, /reauthentication/);
assert.match(uiElements.get("#account-hint").textContent, /oauth_invalid_grant/);
assert.equal(uiElements.get("#reconnect-link").href, "/oauth/start?region=us",
  "provider reauthentication errors must leave a reconnect action available without deleting local credentials");
const disconnectedUiElements = new Map();
const disconnectedDocument = {
  querySelector(selector) {
    if (!disconnectedUiElements.has(selector)) disconnectedUiElements.set(selector, new FakeElement());
    return disconnectedUiElements.get(selector);
  },
  createElement() { return new FakeElement(); },
};
const disconnectedRequests = [];
runInNewContext(page.match(/<script>([\s\S]*?)<\/script>/)[1], {
  document: disconnectedDocument,
  fetch: async path => {
    disconnectedRequests.push(path);
    return Response.json({ authenticated: true, connected: false });
  },
  Response, Date, URL,
  window: { location: { href: "https://example.test/?connect_region=jp" } },
  setTimeout,
});
await new Promise(resolve => setTimeout(resolve, 0));
assert.deepEqual(disconnectedRequests, ["/api/status", "/api/usage-consent"]);
assert.equal(disconnectedUiElements.get("#region").value, "jp");
assert.equal(disconnectedUiElements.get("#connect-link").href, "/oauth/start?region=jp",
  "a safe landing URL restores the requested region without starting OAuth automatically");
const statusWithoutIdentity = await worker.fetch(new Request("https://example.test/api/status"), {});
assert.equal(statusWithoutIdentity.status, 200);
assert.equal((await statusWithoutIdentity.json()).authenticated, false);
assert.equal(findNewRelicTool({ tools: [{ name: "unsafe_list_metric_names_extra" }] }, ["list_metric_names"]), null);
for (const path of ["/api/disconnect", "/api/select-account"]) {
  const denied = await worker.fetch(new Request("https://example.test" + path, {
    method: "POST", headers: { "oai-authenticated-user-id": "test-user", origin: "https://attacker.example", "content-type": "application/json" }, body: "{}",
  }), {});
  assert.equal(denied.status, 403);
}

const now = Date.parse("2026-11-04T12:00:00Z");
assert.match(normalizeNrql("SELECT * FROM Metric", now), /SINCE 30 minutes ago LIMIT 100$/);
assert.match(normalizeNrql("SELECT * FROM Metric LIMIT 250 SINCE 1 hour ago", now), /LIMIT 100/);
assert.throws(() => normalizeNrql("DELETE FROM Metric", now), /SELECT/);
assert.throws(() => normalizeNrql("SELECT * FROM Metric SINCE 8 days ago", now), /7日/);
assert.throws(() => normalizeNrql("SELECT * FROM Metric; DELETE FROM Metric", now), /複数文/);
assert.throws(() => normalizeNrql("SELECT * FROM (SELECT * FROM Metric SINCE 100 days ago) SINCE 1 hour ago", now), /入れ子/);
assert.throws(() => normalizeNrql("SELECT * FROM Metric WHERE name = 'SINCE 1 hour ago' SINCE 30 minutes ago", now), /検証できない/);
assert.throws(() => normalizeNrql("SELECT * FROM Metric SINCE 1 hour ago LIMIT MAX", now), /入れ子/);
assert.throws(() => normalizeNrql("SELECT * FROM Metric SINCE 1 hour ago SINCE 8 days ago", now), /入れ子/);
assert.throws(() => normalizeNrql("SELECT * FROM Metric SINCE 1 hour ago\nLIMIT MAX", now), /複数文/);
assert.match(normalizeNrql("SELECT * FROM Log WHERE message = 'a  b'", now), /'a  b'/);
assert.deepEqual(filterMetricNames({ result: { dimensional_metrics: ["cpu", "scylla_stall", "scylla_stall"], timeslice_metrics: ["scylla_read"] } }, "SCYLLA", 1).metrics, ["scylla_stall"]);
assert.equal(filterMetricNames({ result: { dimensional_metrics: ["scylla_a", "scylla_b"], timeslice_metrics: [] } }, "scylla", 1).truncated, true);
assert.throws(() => filterMetricNames({}, "scylla", 1), /形式/);
assert.equal(validateLogWindow("30 minutes"), "30 minutes ago");
assert.throws(() => validateLogWindow("8 days ago"), /7日/);
assert.equal(validateLogFilter("message LIKE '%timeout%'"), "message LIKE '%timeout%'");
assert.throws(() => validateLogFilter("x = 1; DROP TABLE nr_connections"), /NRQLの構文/);
const comparison = buildComparisonNrql(
  "SELECT average(value) FROM Metric FACET rack",
  "2026-11-03T10:00:00Z",
  "2026-11-03T11:00:00Z",
  now,
);
assert.match(comparison, /SINCE '2026-11-03T10:00:00.000Z' UNTIL '2026-11-03T11:00:00.000Z'/);
assert.throws(() => buildComparisonNrql(
  "SELECT * FROM Metric",
  "2026-10-01T00:00:00Z",
  "2026-10-10T00:00:00Z",
  now,
), /7日/);

const key = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString("base64url");
const env = { NEW_RELIC_TOKEN_ENCRYPTION_KEY: key };
const ciphertext = await encryptSecret("token-for-test-only", env);
assert.notEqual(ciphertext, "token-for-test-only");
assert.equal(await decryptSecret(ciphertext, env), "token-for-test-only");
await assert.rejects(() => decryptSecret(ciphertext, { NEW_RELIC_TOKEN_ENCRYPTION_KEY: "incorrect" }));

const identity = "oauth-user-for-test";
const identityRequest = new Request("https://example.test/", { headers: { "oai-authenticated-user-id": identity } });
const userId = await siteUserId(identityRequest);
const database = new MemoryD1();
const oauthEnv = { ...env, DB: database };
const start = await beginNewRelicAuthorization(
  new Request("https://example.test/oauth/start?region=jp"),
  oauthEnv,
  userId,
  "jp",
);
assert.equal(start.status, 302);
const authorizationUrl = new URL(start.headers.get("location"));
const state = authorizationUrl.searchParams.get("state");
const redirectUri = authorizationUrl.searchParams.get("redirect_uri");
assert.match(redirectUri, /^http:\/\/localhost:([4-5]\d{4}|6[0-5]\d{3})\/callback$/);
assert.equal(authorizationUrl.searchParams.get("code_challenge_method"), "S256");
assert.equal(authorizationUrl.searchParams.get("scope"), "observability:read offline offline_access");
const callbackUrl = redirectUri + "?code=one-time-test-code&state=" + encodeURIComponent(state);
const callbackWithWrongPort = new URL(callbackUrl);
callbackWithWrongPort.port = String(Number(callbackWithWrongPort.port) === 65535 ? 49152 : Number(callbackWithWrongPort.port) + 1);

const originalFetch = globalThis.fetch;
let exchangedCode = null;
let exchangedRedirect = null;
globalThis.fetch = async (url, options) => {
  assert.equal(String(url), "https://oauth2.service.newrelic.com/oauth2/token");
  const form = new URLSearchParams(options.body);
  exchangedCode = form.get("code");
  exchangedRedirect = form.get("redirect_uri");
  assert.ok(form.get("code_verifier"));
  return new Response(JSON.stringify({ access_token: "test-access-token", refresh_token: "test-refresh-token", expires_in: 300 }), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
};
try {
  const wrongUser = await worker.fetch(new Request("https://example.test/api/oauth/manual-complete", {
    method: "POST", headers: { "content-type": "application/json", origin: "https://example.test", "oai-authenticated-user-id": "different-user" },
    body: JSON.stringify({ callbackUrl }),
  }), oauthEnv);
  assert.equal(wrongUser.status, 401);
  assert.equal(database.states.size, 1);
  const rejectedOrigin = await worker.fetch(new Request("https://example.test/api/oauth/manual-complete", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://attacker.example",
      "oai-authenticated-user-id": identity,
    },
    body: JSON.stringify({ callbackUrl }),
  }), oauthEnv);
  assert.equal(rejectedOrigin.status, 403);
  assert.equal(database.states.size, 1);

  const rejectedPort = await worker.fetch(new Request("https://example.test/api/oauth/manual-complete", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://example.test",
      "oai-authenticated-user-id": identity,
    },
    body: JSON.stringify({ callbackUrl: callbackWithWrongPort.toString() }),
  }), oauthEnv);
  assert.equal(rejectedPort.status, 401);
  assert.equal(database.states.size, 1);

  const completed = await worker.fetch(new Request("https://example.test/api/oauth/manual-complete", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://example.test",
      "oai-authenticated-user-id": identity,
    },
    body: JSON.stringify({ callbackUrl }),
  }), oauthEnv);
  assert.equal(completed.status, 200);
  assert.deepEqual(await completed.json(), { connected: true, region: "jp" });
  assert.equal(exchangedCode, "one-time-test-code");
  assert.equal(exchangedRedirect, redirectUri);
  assert.equal(database.states.size, 0);
  const connection = database.connections.get(userId);
  assert.ok(connection);
  assert.notEqual(connection.encrypted_access_token, "test-access-token");
  assert.equal(await decryptSecret(connection.encrypted_access_token, env), "test-access-token");
  assert.equal(await decryptSecret(connection.encrypted_refresh_token, env), "test-refresh-token");
  const otherUser = await siteUserId(new Request("https://example.test/", { headers: { "oai-authenticated-user-id": "different-user" } }));
  assert.equal((await getConnectionStatus(oauthEnv, otherUser)).connected, false);

  const replay = await worker.fetch(new Request("https://example.test/api/oauth/manual-complete", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://example.test",
      "oai-authenticated-user-id": identity,
    },
    body: JSON.stringify({ callbackUrl }),
  }), oauthEnv);
  assert.equal(replay.status, 401);
  const replayText = await replay.text();
  assert.equal(replayText.includes("one-time-test-code"), false);

  const readTool = {
    name: "fixture_read",
    inputSchema: { type: "object", properties: {}, required: [], additionalProperties: false },
    outputSchema: {
      type: "object",
      properties: {
        access_token_value: { type: "string" },
        refresh_token_backup: { type: "string" },
        authorization_token: { type: "string" },
      },
      required: ["access_token_value", "refresh_token_backup", "authorization_token"],
      additionalProperties: false,
    },
  };
  let upstreamToolCalls = 0;
  globalThis.fetch = async (_url, options) => {
    const request = JSON.parse(options.body);
    if (request.method === "notifications/initialized") return new Response(null, { status: 202 });
    if (request.method === "initialize") return Response.json({ jsonrpc: "2.0", id: request.id, result: {} });
    if (request.method === "tools/list") return Response.json({ jsonrpc: "2.0", id: request.id, result: { tools: [
      readTool, { name: "list_available_new_relic_accounts", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
    ] } });
    if (request.method === "tools/call") {
      upstreamToolCalls += 1;
      return Response.json({ jsonrpc: "2.0", id: request.id, result: { content: [{ type: "text", text: "fixture" }] } });
    }
    throw new Error("Unexpected MCP method " + request.method);
  };
  const unreviewed = await call("tools/call", { name: "read_official_mcp", arguments: { toolName: "fixture_read", arguments: {} } }, oauthEnv, identity);
  assert.match(unreviewed.payload.result.content[0].text, /policy_not_reviewed/);
  assert.equal(upstreamToolCalls, 0, "unreviewed generic requests must not perform hidden account-list calls");

  const schemaHash = await schemaFingerprint(readTool);
  const reviewedWithoutConsentEnv = { ...oauthEnv, NEW_RELIC_MCP_POLICIES: JSON.stringify({ fixture_read: {
    schemaHash, operation: "read", billing: "core_compute", preview: false, scope: "identity",
  } }) };
  const noConsent = await call("tools/call", { name: "read_official_mcp", arguments: { toolName: "fixture_read", arguments: {} } }, reviewedWithoutConsentEnv, identity);
  assert.match(noConsent.payload.result.content[0].text, /usage_consent_required/);
  assert.equal(noConsent.payload.result.structuredContent.errorCode, "usage_consent_required");
  assert.equal(upstreamToolCalls, 0, "a Core policy cannot run before the user's independent consent");
  await updateUsageConsents(oauthEnv, userId, { core_compute: true, advanced_compute: false, preview: false });
  const reviewedEnv = reviewedWithoutConsentEnv;
  globalThis.fetch = async (_url, options) => {
    const request = JSON.parse(options.body);
    if (request.method === "notifications/initialized") return new Response(null, { status: 202 });
    if (request.method === "initialize") return Response.json({ jsonrpc: "2.0", id: request.id, result: {} });
    if (request.method === "tools/list") {
      await updateUsageConsents(oauthEnv, userId, { core_compute: false, advanced_compute: false, preview: false });
      return Response.json({ jsonrpc: "2.0", id: request.id, result: { tools: [readTool] } });
    }
    if (request.method === "tools/call") {
      upstreamToolCalls += 1;
      return Response.json({ jsonrpc: "2.0", id: request.id, result: { content: [{ type: "text", text: "fixture" }] } });
    }
    throw new Error("Unexpected MCP method " + request.method);
  };
  const revokedDuringDiscovery = await call("tools/call", { name: "read_official_mcp", arguments: { toolName: "fixture_read", arguments: {} } }, reviewedEnv, identity);
  assert.equal(revokedDuringDiscovery.payload.result.structuredContent.errorCode, "usage_consent_required");
  assert.equal(upstreamToolCalls, 0, "generic reads recheck the current grant immediately before dispatch");
  await updateUsageConsents(oauthEnv, userId, { core_compute: true, advanced_compute: false, preview: false });
  globalThis.fetch = async (_url, options) => {
    const request = JSON.parse(options.body);
    if (request.method === "notifications/initialized") return new Response(null, { status: 202 });
    if (request.method === "initialize") return Response.json({ jsonrpc: "2.0", id: request.id, result: {} });
    if (request.method === "tools/list") return Response.json({ jsonrpc: "2.0", id: request.id, result: { tools: [readTool] } });
    if (request.method === "tools/call") {
      upstreamToolCalls += 1;
      return Response.json({ jsonrpc: "2.0", id: request.id, result: {
        content: [{ type: "text", text: "fixture" }],
        structuredContent: {
          access_token_value: "opaque-access-fixture",
          refresh_token_backup: "opaque-refresh-fixture",
          authorization_token: "opaque-auth-fixture",
        },
      } });
    }
    throw new Error("Unexpected MCP method " + request.method);
  };
  const credentialShapedResult = await call("tools/call", { name: "read_official_mcp", arguments: { toolName: "fixture_read", arguments: {} } }, reviewedEnv, identity);
  const safeStructuredResult = credentialShapedResult.payload.result.structuredContent.result.structuredContent;
  assert.equal(safeStructuredResult.access_token_value, "[REDACTED]");
  assert.equal(safeStructuredResult.refresh_token_backup, "[REDACTED]");
  assert.equal(safeStructuredResult.authorization_token, "[REDACTED]");
  assert.equal(upstreamToolCalls, 1);
  globalThis.fetch = async (_url, options) => {
    const request = JSON.parse(options.body);
    if (request.method === "notifications/initialized") return new Response(null, { status: 202 });
    if (request.method === "initialize") return Response.json({ jsonrpc: "2.0", id: request.id, result: {} });
    if (request.method === "tools/list") return Response.json({ jsonrpc: "2.0", id: request.id, result: { tools: [readTool] } });
    if (request.method === "tools/call") {
      upstreamToolCalls += 1;
      return Response.json({ jsonrpc: "2.0", id: request.id, result: {
        content: [{ type: "text", text: "測".repeat(10000) }],
        structuredContent: {
          access_token_value: "opaque-access-fixture",
          refresh_token_backup: "opaque-refresh-fixture",
          authorization_token: "opaque-auth-fixture",
        },
      } });
    }
    throw new Error("Unexpected MCP method " + request.method);
  };
  const bounded = await call("tools/call", { name: "read_official_mcp", arguments: { toolName: "fixture_read", arguments: {} } }, reviewedEnv, identity);
  assert.equal(bounded.payload.result.isError, undefined);
  assert.ok(new TextEncoder().encode(bounded.raw).byteLength <= 10000, "combined MCP result must fit the byte budget");
  assert.equal(upstreamToolCalls, 2);

  const pendingStart = await beginNewRelicAuthorization(
    new Request("https://example.test/oauth/start?region=jp"), oauthEnv, userId, "jp",
  );
  const pendingUrl = new URL(pendingStart.headers.get("location"));
  const pendingCallback = pendingUrl.searchParams.get("redirect_uri") + "?code=pending-test-code&state=" + encodeURIComponent(pendingUrl.searchParams.get("state"));
  let releaseExchange;
  let markExchangeStarted;
  const exchangeStarted = new Promise((resolve) => { markExchangeStarted = resolve; });
  const pendingTokenResponse = new Promise((resolve) => { releaseExchange = resolve; });
  globalThis.fetch = async () => { markExchangeStarted(); return pendingTokenResponse; };
  const completion = completePastedNewRelicAuthorization(pendingCallback, oauthEnv, userId);
  await exchangeStarted;
  let completionFailure;
  database.afterBatchStatement = async (statementNumber) => {
    if (statementNumber !== 1) return;
    // Simulate the precise race window that existed when disconnect used
    // separate awaits: the OAuth completion runs after the state fence but
    // before the connection deletion statement. D1 itself keeps batch atomic.
    releaseExchange(new Response(JSON.stringify({ access_token: "late-access-token", refresh_token: "late-refresh-token", expires_in: 300 }), {
      status: 200, headers: { "content-type": "application/json" },
    }));
    await completionFailure;
  };
  completionFailure = assert.rejects(completion, (error) => error.code === "oauth_connection_cancelled" && error.requiresReauthentication === true);
  await disconnectNewRelic(oauthEnv, userId);
  await completionFailure;
  database.afterBatchStatement = undefined;
  assert.equal(database.connections.has(userId), false, "a callback finishing after disconnect must not recreate credentials");
  assert.equal(database.states.size, 0);
} finally {
  globalThis.fetch = originalFetch;
}

const manualPageResponse = await worker.fetch(new Request("https://example.test/oauth/complete"), {});
assert.equal(manualPageResponse.status, 200);
const manualPageHtml = await manualPageResponse.text();
assert.match(manualPageHtml, /api\/oauth\/manual-complete/);
const completionElements = new Map();
const completionDocument = {
  querySelector(selector) {
    if (!completionElements.has(selector)) completionElements.set(selector, new FakeElement());
    return completionElements.get(selector);
  },
};
completionElements.set("#callback-url", Object.assign(new FakeElement(), { value: "http://localhost:12345/callback?code=synthetic&state=synthetic" }));
runInNewContext(manualPageHtml.match(/<script>([\s\S]*?)<\/script>/)[1], {
  document: completionDocument,
  fetch: async () => Response.json({ error: "New Relic OAuth was rejected", errorCode: "oauth_invalid_grant" }, { status: 401 }),
  Response, setTimeout, location: { replace() {} },
});
await completionElements.get("#complete-form").listeners.submit({ preventDefault() {} });
assert.match(completionElements.get("#status").textContent, /oauth_invalid_grant/,
  "OAuth completion failures should display the safe code while retaining the pasted URL for retry");
assert.equal(completionElements.get("#submit-button").disabled, false);
assert.equal(completionElements.get("#callback-url").value, "http://localhost:12345/callback?code=synthetic&state=synthetic");

// Status uses local metadata only, even when the stored access token is near expiry.
const statusDb = new MemoryD1();
const statusUserId = await siteUserId(new Request("https://example.test/", {
  headers: { "oai-authenticated-user-id": "status-rate-limit-identity" },
}));
statusDb.connections.set(statusUserId, {
  user_id: statusUserId,
  encrypted_access_token: await encryptSecret("expired-access", env),
  encrypted_refresh_token: await encryptSecret("revoked-refresh", env),
  access_expires_at: Date.now() + 1000,
  connected_at: Date.now(),
  region: "jp",
});
const statusEnv = { ...env, DB: statusDb };
let statusRefreshCalls = 0;
globalThis.fetch = async () => { statusRefreshCalls += 1; throw new Error("status must not call the provider"); };
for (let index = 0; index < 25; index += 1) {
  await call("tools/call", { name: "get_connection_status", arguments: {} }, statusEnv, "status-rate-limit-identity");
}
assert.equal(statusRefreshCalls, 0, "status lookups must not refresh tokens or contact the provider");
assert.equal(statusDb.rates.get(statusUserId + ":" + Math.floor(Date.now() / 60000)).call_count, 25);
globalThis.fetch = originalFetch;

const consentDb = new MemoryD1();
const consentIdentity = "usage-consent-owner";
const consentUserId = await siteUserId(new Request("https://example.test/", {
  headers: { "oai-authenticated-user-id": consentIdentity },
}));
const consentChoices = { core_compute: true, advanced_compute: false, preview: false };
const consentRequest = (method = "GET", body, origin = "https://example.test", identity = consentIdentity) => new Request("https://example.test/api/usage-consent", {
  method,
  headers: {
    ...(method === "POST" ? { "content-type": "application/json" } : {}),
    ...(origin ? { origin } : {}),
    "oai-authenticated-user-id": identity,
  },
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
});
const emptyConsentResponse = await worker.fetch(consentRequest(), { ...env, DB: consentDb });
assert.deepEqual((await emptyConsentResponse.json()).usageConsents, {
  core_compute: { enabled: false, expiresAt: null },
  advanced_compute: { enabled: false, expiresAt: null },
  preview: { enabled: false, expiresAt: null },
}, "usage permissions are off for a new user");
assert.equal((await worker.fetch(consentRequest("POST", consentChoices, null), { ...env, DB: consentDb })).status, 403,
  "grant and revoke require a same-origin browser request");
assert.equal((await worker.fetch(consentRequest("POST", { ...consentChoices, extra: true }), { ...env, DB: consentDb })).status, 400,
  "unknown consent fields are rejected");
const grantResponse = await worker.fetch(consentRequest("POST", consentChoices), { ...env, DB: consentDb });
assert.equal(grantResponse.status, 200);
const grantedConsent = (await grantResponse.json()).usageConsents;
assert.equal(grantedConsent.core_compute.enabled, true);
assert.equal(grantedConsent.advanced_compute.enabled, false, "Core consent does not enable Advanced");
assert.ok(grantedConsent.core_compute.expiresAt > Date.now() + 29 * 24 * 60 * 60 * 1000,
  "explicit consent expires in 30 days");
const otherIdentityConsent = await worker.fetch(consentRequest("GET", undefined, "https://example.test", "different-consent-user"), { ...env, DB: consentDb });
assert.equal((await otherIdentityConsent.json()).usageConsents.core_compute.enabled, false,
  "consent is isolated per authenticated user");
const expiredIdentity = "expired-consent-identity";
const expiredUserId = await siteUserId(new Request("https://example.test/", {
  headers: { "oai-authenticated-user-id": expiredIdentity },
}));
consentDb.consents.set(expiredUserId + ":core_compute", {
  user_id: expiredUserId, capability: "core_compute", granted_at: 1, expires_at: Date.now() - 1,
});
const expiredConsentResponse = await worker.fetch(consentRequest("GET", undefined, "https://example.test", expiredIdentity), { ...env, DB: consentDb });
assert.equal((await expiredConsentResponse.json()).usageConsents.core_compute.enabled, false,
  "expired grants are not effective");
const revokeResponse = await worker.fetch(consentRequest("POST", { ...consentChoices, core_compute: false }), { ...env, DB: consentDb });
assert.equal((await revokeResponse.json()).usageConsents.core_compute.enabled, false,
  "the owner can revoke consent from the same UI");
assert.equal(consentDb.consents.has(consentUserId + ":core_compute"), false);

// OAuth and ordinary status/read traffic use separate quota buckets.
const quotaDb = new MemoryD1();
for (let index = 0; index < 5; index += 1) {
  const statusResponse = await worker.fetch(new Request("https://example.test/api/status", {
    headers: { "oai-authenticated-user-id": "quota-separation-identity" },
  }), { ...env, DB: quotaDb });
  assert.equal(statusResponse.status, 200);
}
const oauthStartResponse = await worker.fetch(new Request("https://example.test/oauth/start?region=jp", {
  headers: { "oai-authenticated-user-id": "quota-separation-identity" },
}), { ...env, DB: quotaDb });
assert.equal(oauthStartResponse.status, 302, "ordinary status calls must not exhaust the separate OAuth rate bucket");

const profileDb = new MemoryD1();
const profileIdentity = "large-account-name-identity";
const profileUserId = await siteUserId(new Request("https://example.test/", {
  headers: { "oai-authenticated-user-id": profileIdentity },
}));
profileDb.connections.set(profileUserId, {
  user_id: profileUserId,
  encrypted_access_token: await encryptSecret("profile-access", env),
  encrypted_refresh_token: await encryptSecret("profile-refresh", env),
  access_expires_at: Date.now() + 60000,
  connected_at: Date.now(),
  region: "jp",
});
profileDb.preferences.set(profileUserId, {
  user_id: profileUserId,
  account_id: "123",
  account_name: "A".repeat(20000),
  updated_at: Date.now(),
});
const profileResponse = await worker.fetch(new Request("https://example.test/api/status", {
  headers: { "oai-authenticated-user-id": profileIdentity },
}), { ...env, DB: profileDb });
const profileRaw = await profileResponse.text();
assert.equal(profileResponse.status, 200);
assert.ok(new TextEncoder().encode(profileRaw).byteLength <= 10000, "stored account names must not exceed the API response budget");
assert.equal(JSON.parse(profileRaw).selectedAccount.name.length, 512);

const selectionDb = new MemoryD1();
const selectionIdentity = "large-provider-account-name-identity";
const selectionUserId = await siteUserId(new Request("https://example.test/", {
  headers: { "oai-authenticated-user-id": selectionIdentity },
}));
selectionDb.connections.set(selectionUserId, {
  user_id: selectionUserId,
  encrypted_access_token: await encryptSecret("selection-access", env),
  encrypted_refresh_token: await encryptSecret("selection-refresh", env),
  access_expires_at: Date.now() + 60000,
  connected_at: Date.now(),
  region: "jp",
});
await updateUsageConsents({ ...env, DB: selectionDb }, selectionUserId, { core_compute: true, advanced_compute: false, preview: false });
globalThis.fetch = async (_url, options) => {
  const request = JSON.parse(options.body);
  if (request.method === "notifications/initialized") return new Response(null, { status: 202 });
  if (request.method === "initialize") return Response.json({ jsonrpc: "2.0", id: request.id, result: {} });
  if (request.method === "tools/list") return Response.json({ jsonrpc: "2.0", id: request.id, result: { tools: [
    { name: "list_available_new_relic_accounts", inputSchema: { type: "object", properties: {}, additionalProperties: false } },
  ] } });
  if (request.method === "tools/call") return Response.json({ jsonrpc: "2.0", id: request.id, result: {
    content: [{ type: "text", text: JSON.stringify({ accounts: [{ accountId: "123", accountName: "B".repeat(20000) }] }) }],
  } });
  throw new Error("Unexpected MCP method " + request.method);
};
const selectionResponse = await worker.fetch(new Request("https://example.test/api/select-account", {
  method: "POST",
  headers: {
    "content-type": "application/json",
    origin: "https://example.test",
    "oai-authenticated-user-id": selectionIdentity,
  },
  body: JSON.stringify({ accountId: "123" }),
}), { ...env, DB: selectionDb });
const selectionRaw = await selectionResponse.text();
assert.equal(selectionResponse.status, 200);
assert.ok(new TextEncoder().encode(selectionRaw).byteLength <= 10000, "provider account names must be bounded before selection responses");
assert.equal(JSON.parse(selectionRaw).selectedAccount.name.length, 512);
globalThis.fetch = originalFetch;

// Bounding the object before JSON escaping was insufficient for catalogs with
// repeated backslashes. Verify the complete API response remains within budget.
const capsDb = new MemoryD1();
const capsIdentity = "capabilities-size-identity";
const syntheticSecretName = "NRAK-" + "FAKEFAKEFAKEFAKEFAKE";
const capsUserId = await siteUserId(new Request("https://example.test/", {
  headers: { "oai-authenticated-user-id": capsIdentity },
}));
capsDb.connections.set(capsUserId, {
  user_id: capsUserId,
  encrypted_access_token: await encryptSecret("caps-access", env),
  encrypted_refresh_token: await encryptSecret("caps-refresh", env),
  access_expires_at: Date.now() + 60000,
  connected_at: Date.now(),
  region: "jp",
});
const capsTools = Array.from({ length: 40 }, (_, index) => ({
  name: "fixture" + index,
  description: "\\".repeat(900),
  inputSchema: index === 39
    ? { type: "object", properties: { payload: { type: "string", description: "🙂" + "x".repeat(20000) } }, additionalProperties: false }
    : index === 38
      ? { type: "object", properties: { [syntheticSecretName]: { type: "string" } }, additionalProperties: false }
    : { type: "object", properties: {}, additionalProperties: false },
}));
globalThis.fetch = async (_url, options) => {
  const request = JSON.parse(options.body);
  if (request.method === "notifications/initialized") return new Response(null, { status: 202 });
  if (request.method === "initialize") return Response.json({ jsonrpc: "2.0", id: request.id, result: {} });
  if (request.method === "tools/list") return Response.json({ jsonrpc: "2.0", id: request.id, result: { tools: capsTools } });
  throw new Error("Unexpected MCP method " + request.method);
};
const capsResponse = await worker.fetch(new Request("https://example.test/api/capabilities?offset=0&limit=10", {
  headers: { "oai-authenticated-user-id": capsIdentity },
}), { ...env, DB: capsDb });
const capsRaw = await capsResponse.text();
assert.equal(capsResponse.status, 200);
assert.ok(new TextEncoder().encode(capsRaw).byteLength <= 10000, "summary page stays within the API byte budget");
const capsPage = JSON.parse(capsRaw);
assert.equal(capsPage.discovered, 40);
assert.equal(capsPage.items.length, 10);
assert.equal(capsPage.offset, 0);
assert.equal(capsPage.nextOffset, 10);
assert.match(capsPage.snapshot, /^[a-f0-9]{64}$/);
assert.equal(Object.hasOwn(capsPage.items[0], "inputSchema"), false, "large schemas are not repeated in each catalog page");
const capsNextResponse = await worker.fetch(new Request("https://example.test/api/capabilities?offset=10&limit=10&snapshot=" + capsPage.snapshot, {
  headers: { "oai-authenticated-user-id": capsIdentity },
}), { ...env, DB: capsDb });
assert.equal(capsNextResponse.status, 200);
assert.equal((await capsNextResponse.json()).offset, 10);
const capsDetailResponse = await worker.fetch(new Request("https://example.test/api/capabilities?name=fixture0&schemaHash="
  + capsPage.items[0].schemaHash + "&snapshot=" + capsPage.snapshot, {
  headers: { "oai-authenticated-user-id": capsIdentity },
}), { ...env, DB: capsDb });
assert.equal(capsDetailResponse.status, 200);
assert.equal((await capsDetailResponse.json()).tool.name, "fixture0");

const capsEnv = { ...env, DB: capsDb };
const mcpCapsPage = await call("tools/call", {
  name: "list_mcp_capabilities", arguments: { offset: 0, limit: 10 },
}, capsEnv, capsIdentity);
assert.equal(mcpCapsPage.payload.result.structuredContent.items.length, 10);
assert.equal(Object.hasOwn(mcpCapsPage.payload.result.structuredContent.items[0], "inputSchema"), false);
const mcpCapsNext = await call("tools/call", {
  name: "list_mcp_capabilities", arguments: { offset: 10, limit: 10, snapshot: mcpCapsPage.payload.result.structuredContent.snapshot },
}, capsEnv, capsIdentity);
assert.equal(mcpCapsNext.payload.result.structuredContent.offset, 10);
const mcpHugePage = await call("tools/call", {
  name: "list_mcp_capabilities", arguments: { offset: 30, limit: 10, snapshot: mcpCapsPage.payload.result.structuredContent.snapshot },
}, capsEnv, capsIdentity);
const hugeTool = mcpHugePage.payload.result.structuredContent.items.find(tool => tool.name === "fixture39");
assert.ok(hugeTool);
const schemaChunkOne = await call("tools/call", {
  name: "get_mcp_capability_schema", arguments: {
    toolName: hugeTool.name, snapshot: mcpHugePage.payload.result.structuredContent.snapshot,
    schemaHash: hugeTool.schemaHash, offset: 0, limit: 1000,
  },
}, capsEnv, capsIdentity);
const expectedSchemaJson = canonicalJson(capsTools[39].inputSchema);
assert.equal(schemaChunkOne.payload.result.structuredContent.schemaJsonChunk, expectedSchemaJson.slice(0, 1000));
assert.equal(schemaChunkOne.payload.result.structuredContent.nextOffset, 1000);
capsTools[39].inputSchema = {
  additionalProperties: false,
  properties: { payload: { description: "🙂" + "x".repeat(20000), type: "string" } },
  type: "object",
};
const schemaChunkTwo = await call("tools/call", {
  name: "get_mcp_capability_schema", arguments: {
    toolName: hugeTool.name, snapshot: mcpHugePage.payload.result.structuredContent.snapshot,
    schemaHash: hugeTool.schemaHash, offset: 1000, limit: 1000,
  },
}, capsEnv, capsIdentity);
assert.equal(schemaChunkTwo.payload.result.structuredContent.offset, 1000);
assert.equal(schemaChunkTwo.payload.result.structuredContent.schemaJsonChunk, expectedSchemaJson.slice(1000, 2000),
  "reordering provider object keys between tools/list calls cannot change the canonical chunk stream");
assert.ok(new TextEncoder().encode(schemaChunkOne.payload.result.structuredContent.schemaJsonChunk).byteLength < 10000,
  "a single large provider schema is returned in a bounded MCP result chunk");
const emojiOffset = expectedSchemaJson.indexOf("🙂");
const emojiChunk = await call("tools/call", {
  name: "get_mcp_capability_schema", arguments: {
    toolName: hugeTool.name, snapshot: mcpHugePage.payload.result.structuredContent.snapshot,
    schemaHash: hugeTool.schemaHash, offset: emojiOffset, limit: 1,
  },
}, capsEnv, capsIdentity);
assert.equal(emojiChunk.payload.result.structuredContent.schemaJsonChunk, "🙂",
  "a one-code-unit limit still makes forward progress for a surrogate-pair code point");
assert.equal(emojiChunk.payload.result.structuredContent.nextOffset, emojiOffset + 2);
const oversizedOffset = await call("tools/call", {
  name: "get_mcp_capability_schema", arguments: {
    toolName: hugeTool.name, snapshot: mcpHugePage.payload.result.structuredContent.snapshot,
    schemaHash: hugeTool.schemaHash, offset: 1_000_001, limit: 1000,
  },
}, capsEnv, capsIdentity);
assert.equal(oversizedOffset.payload.result.isError, true);
assert.equal(oversizedOffset.payload.result.structuredContent.errorCode, "invalid_catalog_request",
  "an offset above the old one-million cap reaches the handler's schema-length check");
const escapeHeavyChunk = await call("tools/call", {
  name: "get_mcp_capability_schema", arguments: {
    toolName: hugeTool.name, snapshot: mcpHugePage.payload.result.structuredContent.snapshot,
    schemaHash: hugeTool.schemaHash, offset: 0, limit: 1500,
  },
}, capsEnv, capsIdentity);
assert.ok(escapeHeavyChunk.payload.result.structuredContent.schemaJsonChunk.length > 0,
  "escaping-heavy metadata cannot erase the chunk in generic output truncation");
assert.equal(escapeHeavyChunk.payload.result.structuredContent.nextOffset,
  escapeHeavyChunk.payload.result.structuredContent.schemaJsonChunk.length);
assert.ok(new TextEncoder().encode(escapeHeavyChunk.raw).byteLength <= 10000);
const secretKeyTool = mcpHugePage.payload.result.structuredContent.items.find(tool => tool.name === "fixture38");
const secretKeySchema = await call("tools/call", {
  name: "get_mcp_capability_schema", arguments: {
    toolName: secretKeyTool.name, snapshot: mcpHugePage.payload.result.structuredContent.snapshot,
    schemaHash: secretKeyTool.schemaHash,
  },
}, capsEnv, capsIdentity);
assert.equal(secretKeySchema.payload.result.isError, true);
assert.equal(secretKeySchema.payload.result.structuredContent.errorCode, "schema_redacted_for_safety");
assert.ok(!secretKeySchema.raw.includes(syntheticSecretName),
  "credential-like object keys are rejected rather than leaked in schema details");

const secretApiResponse = await worker.fetch(new Request("https://example.test/api/capabilities?name=fixture38&schemaHash="
  + secretKeyTool.schemaHash + "&snapshot=" + mcpHugePage.payload.result.structuredContent.snapshot, {
  headers: { "oai-authenticated-user-id": capsIdentity },
}), capsEnv);
assert.equal(secretApiResponse.status, 422);
assert.ok(!(await secretApiResponse.clone().text()).includes(syntheticSecretName));

capsTools[0].inputSchema = { type: "object", properties: { changed: { type: "string" } }, additionalProperties: false };
const changedCapsResponse = await worker.fetch(new Request("https://example.test/api/capabilities?offset=20&limit=10&snapshot=" + capsPage.snapshot, {
  headers: { "oai-authenticated-user-id": capsIdentity },
}), { ...env, DB: capsDb });
assert.equal(changedCapsResponse.status, 409, "pagination fails closed if the upstream schema changes mid-review");
assert.equal((await changedCapsResponse.json()).errorCode, "catalog_changed");
globalThis.fetch = originalFetch;

const concurrentDb = new MemoryD1();
concurrentDb.connections.set(userId, { user_id: userId, encrypted_access_token: await encryptSecret("expired-token", env), encrypted_refresh_token: await encryptSecret("refresh-one", env), access_expires_at: 0, connected_at: Date.now(), region: "us" });
let refreshCount = 0;
globalThis.fetch = async () => {
  refreshCount++;
  await new Promise((resolve) => setTimeout(resolve, 40));
  return new Response(JSON.stringify({ access_token: "new-access", refresh_token: "refresh-two", expires_in: 300 }), { status: 200 });
};
try {
  const results = await Promise.all([
    getConnectionStatus({ ...env, DB: concurrentDb }, userId, { refreshIfNeeded: true }),
    getConnectionStatus({ ...env, DB: concurrentDb }, userId, { refreshIfNeeded: true }),
  ]);
  assert.equal(refreshCount, 1);
  assert.ok(results.every((value) => value.connected));
  assert.equal(await decryptSecret(concurrentDb.connections.get(userId).encrypted_refresh_token, env), "refresh-two");
  assert.equal(concurrentDb.locks.size, 0);
} finally { globalThis.fetch = originalFetch; }

globalThis.fetch = async (_url, options) => {
  const request = JSON.parse(options.body);
  if (request.method === "notifications/initialized") return new Response(null, { status: 202 });
  if (request.method === "initialize") return Response.json({ jsonrpc: "2.0", id: request.id, result: {} });
  return new Response("x".repeat(2 * 1024 * 1024 + 1), { status: 200, headers: { "content-type": "application/json" } });
};
try {
  await assert.rejects(() => withNewRelicSession({ ...env, DB: concurrentDb }, userId, async () => null), /上限/);
} finally { globalThis.fetch = originalFetch; }

const pagedDb = new MemoryD1();
pagedDb.connections.set(userId, { user_id: userId, encrypted_access_token: await encryptSecret("paging-access", env), encrypted_refresh_token: await encryptSecret("paging-refresh", env), access_expires_at: Date.now() + 300000, connected_at: Date.now(), region: "us" });
let listRequests = 0;
globalThis.fetch = async (_url, options) => {
  assert.equal(new Headers(options.headers).get("include-tags"), null);
  const request = JSON.parse(options.body);
  if (request.method === "notifications/initialized") return new Response(null, { status: 202 });
  if (request.method === "initialize") return Response.json({ jsonrpc: "2.0", id: request.id, result: {} });
  if (request.method === "tools/list") {
    listRequests++;
    const result = listRequests === 1 ? { tools: [{ name: "first" }], nextCursor: "next" } : { tools: [{ name: "second" }] };
    return Response.json({ jsonrpc: "2.0", id: request.id, result });
  }
  throw new Error("Unexpected MCP method");
};
try {
  const names = await withNewRelicSession({ ...env, DB: pagedDb }, userId, async (session) => session.tools.map((tool) => tool.name));
  assert.deepEqual(names, ["first", "second"]);
  assert.equal(listRequests, 2);
} finally { globalThis.fetch = originalFetch; }

const replacedDb = new MemoryD1();
const oldRefresh = await encryptSecret("old-refresh", env);
const replacementRefresh = await encryptSecret("replacement-refresh", env);
replacedDb.connections.set(userId, { user_id: userId, encrypted_access_token: await encryptSecret("old-access", env), encrypted_refresh_token: oldRefresh, access_expires_at: 0, connected_at: Date.now(), region: "us" });
globalThis.fetch = async () => {
  replacedDb.connections.get(userId).encrypted_refresh_token = replacementRefresh;
  return new Response(JSON.stringify({ access_token: "obsolete-access", refresh_token: "obsolete-refresh", expires_in: 300 }), { status: 200 });
};
try {
  await getConnectionStatus({ ...env, DB: replacedDb }, userId, { refreshIfNeeded: true });
  assert.equal(replacedDb.connections.get(userId).encrypted_refresh_token, replacementRefresh);
  assert.equal(replacedDb.locks.size, 0);
} finally { globalThis.fetch = originalFetch; }

console.log("MCP and security tests passed: mobile UI, loopback OAuth callback paste, PKCE, origin and user binding, one-time state, token encryption, and NRQL limits");
