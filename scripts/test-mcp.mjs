import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

globalThis.crypto ||= webcrypto;
const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const workerPath = resolve(root, "dist/server/index.js");
const worker = (await import(pathToFileURL(workerPath).href + "?test=" + Date.now())).default;
const { normalizeNrql, buildComparisonNrql, validateLogFilter, validateLogWindow, filterMetricNames } =
  await import(pathToFileURL(resolve(root, "worker/nrql.js")).href + "?test=" + Date.now());
const { beginNewRelicAuthorization, decryptSecret, encryptSecret, siteUserId, getConnectionStatus, withNewRelicSession, findNewRelicTool } =
  await import(pathToFileURL(resolve(root, "worker/newrelic.js")).href + "?test=" + Date.now());

class MemoryD1 {
  states = new Map();
  connections = new Map();
  rates = new Map();
  locks = new Map();

  prepare(query) {
    const normalized = query.replace(/\s+/g, " ").trim().toUpperCase();
    const database = this;
    return {
      values: [],
      bind(...values) { this.values = values; return this; },
      async run() { return database.run(normalized, this.values); },
      async first() { return database.first(normalized, this.values); },
    };
  }

  async run(query, values) {
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
      this.states.set(state_hash, { state_hash, user_id, encrypted_verifier, redirect_uri, region, expires_at });
      return { meta: { changes: 1 } };
    }
    if (query.startsWith("DELETE FROM NR_OAUTH_STATES WHERE STATE_HASH = ? AND USER_ID = ?")) {
      const [stateHash, userId] = values;
      const row = this.states.get(stateHash);
      if (row?.user_id === userId) this.states.delete(stateHash);
      return { meta: { changes: row?.user_id === userId ? 1 : 0 } };
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
      const [user_id, encrypted_access_token, encrypted_refresh_token, access_expires_at, connected_at, region] = values;
      this.connections.set(user_id, { user_id, encrypted_access_token, encrypted_refresh_token, access_expires_at, connected_at, region });
      return { meta: { changes: 1 } };
    }
    throw new Error("Unexpected mock D1 run query: " + query);
  }

  async first(query, values) {
    if (query.includes("FROM NR_CONNECTIONS WHERE USER_ID = ?")) { const row = this.connections.get(values[0]); return row ? { ...row } : null; }
    if (query.includes("FROM NR_PREFERENCES WHERE USER_ID = ?")) return null;
    if (query.startsWith("SELECT USER_ID, ENCRYPTED_VERIFIER")) return this.states.get(values[0]) || null;
    if (query.startsWith("SELECT CALL_COUNT FROM NR_RATE_LIMITS")) {
      const [userId, windowStart] = values;
      return this.rates.get(userId + ":" + windowStart) || null;
    }
    throw new Error("Unexpected mock D1 first query: " + query);
  }
}

async function call(method, params = {}) {
  const request = new Request("https://example.test/mcp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const response = await worker.fetch(request, {});
  return { response, payload: await response.json() };
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
assert.equal(listed.payload.result.tools.find((tool) => tool.name === "disconnect_new_relic").annotations.readOnlyHint, false);
assert.equal(listed.payload.result.tools.find((tool) => tool.name === "disconnect_new_relic").annotations.destructiveHint, true);
assert.equal(listed.payload.result.tools.find((tool) => tool.name === "execute_nrql").annotations.readOnlyHint, true);

const pong = await call("tools/call", { name: "ping", arguments: {} });
assert.equal(pong.payload.result.content[0].text, "pong");
assert.equal(pong.payload.result.structuredContent.ok, true);
const unknown = await call("tools/call", { name: "unknown_tool", arguments: {} });
assert.equal(unknown.payload.error.code, -32602);

const pageResponse = await worker.fetch(new Request("https://example.test/"), {});
assert.equal(pageResponse.status, 200);
const page = await pageResponse.text();
assert.match(page, /lang="ja"/);
assert.match(page, /New Relic公式OAuth/);
assert.match(page, /prefers-color-scheme: dark/);
assert.match(page, /requiresReauthentication/);
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
} finally {
  globalThis.fetch = originalFetch;
}

const manualPageResponse = await worker.fetch(new Request("https://example.test/oauth/complete"), {});
assert.equal(manualPageResponse.status, 200);
assert.match(await manualPageResponse.text(), /api\/oauth\/manual-complete/);

const concurrentDb = new MemoryD1();
concurrentDb.connections.set(userId, { user_id: userId, encrypted_access_token: await encryptSecret("expired-token", env), encrypted_refresh_token: await encryptSecret("refresh-one", env), access_expires_at: 0, connected_at: Date.now(), region: "us" });
let refreshCount = 0;
globalThis.fetch = async () => {
  refreshCount++;
  await new Promise((resolve) => setTimeout(resolve, 40));
  return new Response(JSON.stringify({ access_token: "new-access", refresh_token: "refresh-two", expires_in: 300 }), { status: 200 });
};
try {
  const results = await Promise.all([getConnectionStatus({ ...env, DB: concurrentDb }, userId), getConnectionStatus({ ...env, DB: concurrentDb }, userId)]);
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
  assert.equal(new Headers(options.headers).get("include-tags"), "discovery,data-access,alerting");
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
  await getConnectionStatus({ ...env, DB: replacedDb }, userId);
  assert.equal(replacedDb.connections.get(userId).encrypted_refresh_token, replacementRefresh);
  assert.equal(replacedDb.locks.size, 0);
} finally { globalThis.fetch = originalFetch; }

console.log("MCP and security tests passed: mobile UI, loopback OAuth callback paste, PKCE, origin and user binding, one-time state, token encryption, and NRQL limits");
