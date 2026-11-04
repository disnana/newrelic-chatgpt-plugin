const CLIENT_ID = "pUWGgnjsQ0bydqCbavTPpw==";
const AUTHORIZATION_ENDPOINT = "https://oauth2.service.newrelic.com/oauth2/auth";
const TOKEN_ENDPOINT = "https://oauth2.service.newrelic.com/oauth2/token";
const MCP_ENDPOINTS = {
  us: "https://mcp.newrelic.com/mcp/",
  eu: "https://mcp.eu.newrelic.com/mcp/",
  jp: "https://mcp.jp.newrelic.com/mcp/",
};
const MCP_PROTOCOL_VERSION = "2025-03-26";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class NewRelicAuthError extends Error {
  constructor(message = "New Relicへの再認証が必要です。接続ページから再接続してください。") {
    super(message);
    this.name = "NewRelicAuthError";
  }
}

export class NewRelicRemoteError extends Error {
  constructor(message = "New Relic公式MCPから正常な応答を取得できませんでした。") {
    super(message);
    this.name = "NewRelicRemoteError";
  }
}

function database(env) {
  if (!env?.DB || typeof env.DB.prepare !== "function") {
    throw new Error("SiteのD1データベースが利用できません。");
  }
  return env.DB;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const output = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) output[index] = binary.charCodeAt(index);
  return output;
}

async function hash(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

export async function siteUserId(request) {
  const identity = request.headers.get("oai-authenticated-user-id");
  if (!identity || identity.length > 512) return null;
  return bytesToBase64Url(await hash(identity));
}

async function encryptionKey(env) {
  const encoded = env?.NEW_RELIC_TOKEN_ENCRYPTION_KEY;
  if (typeof encoded !== "string" || !encoded) {
    throw new Error("Siteのトークン暗号化キーが設定されていません。");
  }
  let raw;
  try {
    raw = base64UrlToBytes(encoded);
  } catch {
    throw new Error("Siteのトークン暗号化キーが正しく設定されていません。");
  }
  if (raw.byteLength !== 32) throw new Error("Siteのトークン暗号化キーが正しく設定されていません。");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptSecret(value, env) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await encryptionKey(env);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(value));
  return bytesToBase64Url(iv) + "." + bytesToBase64Url(new Uint8Array(ciphertext));
}

export async function decryptSecret(value, env) {
  const [ivPart, ciphertextPart] = String(value || "").split(".");
  if (!ivPart || !ciphertextPart) throw new Error("保存済み認証情報を復号できません。");
  const key = await encryptionKey(env);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlToBytes(ivPart) },
    key,
    base64UrlToBytes(ciphertextPart),
  );
  return decoder.decode(plaintext);
}

function validRegion(region) {
  return Object.hasOwn(MCP_ENDPOINTS, region) ? region : "us";
}

function randomToken(size = 32) {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(size)));
}

function randomLoopbackRedirectUri() {
  const random = crypto.getRandomValues(new Uint16Array(1))[0];
  const port = 49152 + (random % 16384);
  return "http://localhost:" + port + "/callback";
}

export async function beginNewRelicAuthorization(request, env, userId, requestedRegion) {
  if (!userId) throw new Error("ChatGPTのSiteセッションを確認できません。Siteを開き直してから接続してください。");
  const region = validRegion(requestedRegion);
  const state = randomToken();
  const verifier = randomToken(48);
  const challenge = bytesToBase64Url(await hash(verifier));
  const redirectUri = randomLoopbackRedirectUri();
  const encryptedVerifier = await encryptSecret(verifier, env);
  const expiresAt = Math.floor(Date.now() / 1000) + 600;
  const stateHash = bytesToBase64Url(await hash(state));
  const db = database(env);

  await db.prepare("DELETE FROM nr_oauth_states WHERE expires_at < ?")
    .bind(Math.floor(Date.now() / 1000)).run();
  await db.prepare(
    "INSERT INTO nr_oauth_states (state_hash, user_id, encrypted_verifier, redirect_uri, region, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
  ).bind(stateHash, userId, encryptedVerifier, redirectUri, region, expiresAt).run();

  const authorization = new URL(AUTHORIZATION_ENDPOINT);
  authorization.searchParams.set("client_id", CLIENT_ID);
  authorization.searchParams.set("redirect_uri", redirectUri);
  authorization.searchParams.set("response_type", "code");
  authorization.searchParams.set("scope", "observability:read offline offline_access");
  authorization.searchParams.set("state", state);
  authorization.searchParams.set("code_challenge", challenge);
  authorization.searchParams.set("code_challenge_method", "S256");
  return Response.redirect(authorization.toString(), 302);
}

async function tokenRequest(form) {
  let response;
  try {
    response = await fetch(TOKEN_ENDPOINT, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
        "cache-control": "no-store",
      },
      body: new URLSearchParams(form),
      signal: AbortSignal.timeout(12000),
    });
  } catch {
    throw new NewRelicRemoteError("New Relic OAuthトークンエンドポイントへ接続できませんでした。");
  }

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new NewRelicRemoteError("New Relic OAuthからJSON以外の応答が返りました。");
  }
  if (!response.ok || payload?.error) {
    const error = String(payload?.error || "");
    if (["invalid_grant", "access_denied", "invalid_client"].includes(error)) {
      throw new NewRelicAuthError("New Relicの認証が期限切れか、このOAuthクライアントで認証できません。接続をやり直してください。");
    }
    throw new NewRelicRemoteError("New Relic OAuthのトークン交換に失敗しました。");
  }
  return payload;
}

async function exchangeAuthorizationResponse({ state, code, error, redirectUri }, env, expectedUserId) {
  if (!expectedUserId) throw new NewRelicAuthError("ChatGPTのSiteセッションを確認できません。Siteを開き直してください。");
  if (!state || state.length > 256 || (!code && !error) || (code && code.length > 4096)) {
    throw new Error("OAuth応答を読み取れません。認証URL全体を貼り付けてください。");
  }
  const db = database(env);
  const stateHash = bytesToBase64Url(await hash(state));
  const flow = await db.prepare(
    "SELECT user_id, encrypted_verifier, redirect_uri, region, expires_at FROM nr_oauth_states WHERE state_hash = ?",
  ).bind(stateHash).first();
  if (!flow || flow.user_id !== expectedUserId) {
    throw new NewRelicAuthError("この認証URLは現在のChatGPTアカウントの接続操作と一致しません。接続をやり直してください。");
  }
  if (flow.redirect_uri !== redirectUri) {
    throw new NewRelicAuthError("認証URLの戻り先が接続開始時と一致しません。localhostのURL全体を貼り付けてください。");
  }
  if (Number(flow.expires_at) < Math.floor(Date.now() / 1000)) {
    await db.prepare("DELETE FROM nr_oauth_states WHERE state_hash = ? AND user_id = ?")
      .bind(stateHash, expectedUserId).run();
    throw new Error("OAuthの確認状態が期限切れです。接続をやり直してください。");
  }
  const consumeResult = await db.prepare(
    "DELETE FROM nr_oauth_states WHERE state_hash = ? AND user_id = ?",
  ).bind(stateHash, expectedUserId).run();
  if (Number(consumeResult?.meta?.changes || 0) !== 1) {
    throw new Error("OAuthの確認状態はすでに使用済みです。接続をやり直してください。");
  }
  const consumed = flow;
  if (error) throw new NewRelicAuthError("New Relicへの接続が完了しませんでした。接続をやり直してください。");

  const verifier = await decryptSecret(consumed.encrypted_verifier, env);
  const token = await tokenRequest({
    grant_type: "authorization_code",
    client_id: CLIENT_ID,
    code,
    redirect_uri: consumed.redirect_uri,
    code_verifier: verifier,
  });
  if (typeof token.access_token !== "string" || typeof token.refresh_token !== "string") {
    throw new NewRelicRemoteError("New Relic OAuthから必要なトークンが発行されませんでした。offline_accessを含めて再接続してください。");
  }

  const now = Date.now();
  const accessExpiresAt = now + Math.max(30, Number(token.expires_in) || 300) * 1000;
  const encryptedAccess = await encryptSecret(token.access_token, env);
  const encryptedRefresh = await encryptSecret(token.refresh_token, env);
  await db.prepare(
    "INSERT INTO nr_connections (user_id, encrypted_access_token, encrypted_refresh_token, access_expires_at, connected_at, region) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET encrypted_access_token = excluded.encrypted_access_token, encrypted_refresh_token = excluded.encrypted_refresh_token, access_expires_at = excluded.access_expires_at, connected_at = excluded.connected_at, region = excluded.region",
  ).bind(consumed.user_id, encryptedAccess, encryptedRefresh, accessExpiresAt, now, validRegion(consumed.region)).run();
  return { connected: true, region: validRegion(consumed.region) };
}

export async function completeNewRelicAuthorization(request, env, expectedUserId) {
  const url = new URL(request.url);
  const result = await exchangeAuthorizationResponse({
    state: url.searchParams.get("state"),
    code: url.searchParams.get("code"),
    error: url.searchParams.get("error"),
    redirectUri: url.origin + url.pathname,
  }, env, expectedUserId);
  const destination = new URL("/", url.origin);
  destination.searchParams.set("connection", result.connected ? "connected" : "failed");
  return Response.redirect(destination.toString(), 303);
}

export async function completePastedNewRelicAuthorization(callbackUrl, env, expectedUserId) {
  if (typeof callbackUrl !== "string" || callbackUrl.length > 8192) {
    throw new Error("localhostから戻ったURLを貼り付けてください。");
  }
  let url;
  try {
    url = new URL(callbackUrl.trim());
  } catch {
    throw new Error("localhostから戻ったURLをそのまま貼り付けてください。");
  }
  if (url.protocol !== "http:" || url.hostname !== "localhost" || !url.port
    || url.pathname !== "/callback" || url.username || url.password || url.hash) {
    throw new Error("http://localhost:<port>/callback で始まる認証後のURLを貼り付けてください。");
  }
  if (url.searchParams.getAll("state").length !== 1
    || url.searchParams.getAll("code").length > 1
    || url.searchParams.getAll("error").length > 1) {
    throw new Error("認証URLの形式が正しくありません。URL全体をコピーしてください。");
  }
  return exchangeAuthorizationResponse({
    state: url.searchParams.get("state"),
    code: url.searchParams.get("code"),
    error: url.searchParams.get("error"),
    redirectUri: url.origin + url.pathname,
  }, env, expectedUserId);
}

export async function getConnectionStatus(env, userId) {
  if (!userId) return { authenticated: false, connected: false, requiresSiteAuthentication: true };
  const connection = await database(env).prepare(
    "SELECT connected_at, access_expires_at, region FROM nr_connections WHERE user_id = ?",
  ).bind(userId).first();
  if (!connection) return { authenticated: true, connected: false, selectedAccount: null };

  let requiresReauthentication = false;
  let currentConnection = connection;
  if (Number(connection.access_expires_at) <= Date.now() + 30000) {
    try {
      await accessToken(env, userId);
      currentConnection = await database(env).prepare(
        "SELECT connected_at, access_expires_at, region FROM nr_connections WHERE user_id = ?",
      ).bind(userId).first() || connection;
    } catch (error) {
      if (error instanceof NewRelicAuthError) requiresReauthentication = true;
      else throw error;
    }
  }
  return {
    authenticated: true,
    connected: true,
    connectedAt: Number(connection.connected_at),
    accessTokenExpiresAt: Number(currentConnection.access_expires_at),
    region: validRegion(currentConnection.region),
    selectedAccount: await getSelectedAccount(env, userId),
    requiresReauthentication,
  };
}

export async function getSelectedAccount(env, userId) {
  if (!userId) return null;
  const row = await database(env).prepare(
    "SELECT account_id, account_name, updated_at FROM nr_preferences WHERE user_id = ?",
  ).bind(userId).first();
  if (!row) return null;
  return {
    id: String(row.account_id),
    name: row.account_name ? String(row.account_name) : "",
    updatedAt: Number(row.updated_at),
  };
}

export async function saveSelectedAccount(env, userId, account) {
  if (!userId) throw new Error("ChatGPTのSiteセッションを確認できません。");
  await database(env).prepare(
    "INSERT INTO nr_preferences (user_id, account_id, account_name, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET account_id = excluded.account_id, account_name = excluded.account_name, updated_at = excluded.updated_at",
  ).bind(userId, String(account.id), String(account.name || ""), Date.now()).run();
}

export async function disconnectNewRelic(env, userId) {
  if (!userId) throw new Error("ChatGPTのSiteセッションを確認できません。");
  const db = database(env);
  await db.prepare("DELETE FROM nr_connections WHERE user_id = ?").bind(userId).run();
  await db.prepare("DELETE FROM nr_preferences WHERE user_id = ?").bind(userId).run();
  await db.prepare("DELETE FROM nr_oauth_states WHERE user_id = ?").bind(userId).run();
  return { connected: false, localConnectionRemoved: true, providerGrantRevoked: false };
}

export async function consumeRateLimit(env, userId, limit = 20) {
  if (!userId) throw new NewRelicAuthError("ChatGPTのSiteセッションを確認できません。");
  const db = database(env);
  const windowStart = Math.floor(Date.now() / 60000);
  await db.prepare("DELETE FROM nr_rate_limits WHERE user_id = ? AND window_start < ?")
    .bind(userId, windowStart - 120).run();
  await db.prepare(
    "INSERT INTO nr_rate_limits (user_id, window_start, call_count) VALUES (?, ?, 1) ON CONFLICT(user_id, window_start) DO UPDATE SET call_count = call_count + 1",
  ).bind(userId, windowStart).run();
  const row = await db.prepare(
    "SELECT call_count FROM nr_rate_limits WHERE user_id = ? AND window_start = ?",
  ).bind(userId, windowStart).first();
  if (Number(row?.call_count || 0) > limit) {
    throw new NewRelicRemoteError("呼び出し回数の上限に達しました。1分ほど待ってから再試行してください。");
  }
}

async function fetchConnection(env, userId) {
  return database(env).prepare(
    "SELECT encrypted_access_token, encrypted_refresh_token, access_expires_at, connected_at, region FROM nr_connections WHERE user_id = ?",
  ).bind(userId).first();
}

async function refreshAccessToken(env, userId, connection, lockOwner) {
  let refreshToken;
  try {
    refreshToken = await decryptSecret(connection.encrypted_refresh_token, env);
  } catch {
    throw new NewRelicAuthError();
  }
  const payload = await tokenRequest({
    grant_type: "refresh_token",
    client_id: CLIENT_ID,
    refresh_token: refreshToken,
  });
  if (typeof payload.access_token !== "string") throw new NewRelicAuthError();
  const nextRefresh = typeof payload.refresh_token === "string" ? payload.refresh_token : refreshToken;
  const encryptedAccess = await encryptSecret(payload.access_token, env);
  const encryptedRefresh = await encryptSecret(nextRefresh, env);
  const accessExpiresAt = Date.now() + Math.max(30, Number(payload.expires_in) || 300) * 1000;
  const saved = await database(env).prepare(
    "UPDATE nr_connections SET encrypted_access_token = ?, encrypted_refresh_token = ?, access_expires_at = ? WHERE user_id = ? AND encrypted_refresh_token = ? AND EXISTS (SELECT 1 FROM nr_refresh_locks WHERE user_id = ? AND owner = ? AND expires_at > ?)",
  ).bind(encryptedAccess, encryptedRefresh, accessExpiresAt, userId, connection.encrypted_refresh_token, userId, lockOwner, Date.now()).run();
  if (Number(saved?.meta?.changes || 0) !== 1) throw new NewRelicAuthError("接続状態が更新されました。もう一度お試しください。");
  return payload.access_token;
}

async function accessToken(env, userId, forceRefresh = false, failedToken = null) {
  let connection = await fetchConnection(env, userId);
  if (!connection) {
    throw new NewRelicAuthError("New Relicに接続されていません。Siteの接続ページからログインしてください。");
  }
  if (!forceRefresh && Number(connection.access_expires_at) > Date.now() + 30000) {
    try {
      return {
        token: await decryptSecret(connection.encrypted_access_token, env),
        region: validRegion(connection.region),
      };
    } catch {
      throw new NewRelicAuthError();
    }
  }
  const db = database(env);
  const owner = randomToken();
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    const now = Date.now();
    const acquired = await db.prepare(
      "INSERT INTO nr_refresh_locks (user_id, owner, expires_at) VALUES (?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET owner = excluded.owner, expires_at = excluded.expires_at WHERE nr_refresh_locks.expires_at < ?",
    ).bind(userId, owner, now + 60000, now).run();
    if (Number(acquired?.meta?.changes || 0) === 1) {
      try {
        connection = await fetchConnection(env, userId);
        if (!connection) throw new NewRelicAuthError();
        const current = await decryptSecret(connection.encrypted_access_token, env);
        if ((!forceRefresh && Number(connection.access_expires_at) > Date.now() + 30000)
          || (forceRefresh && failedToken && current !== failedToken)) {
          return { token: current, region: validRegion(connection.region) };
        }
        return { token: await refreshAccessToken(env, userId, connection, owner), region: validRegion(connection.region) };
      } finally {
        await db.prepare("DELETE FROM nr_refresh_locks WHERE user_id = ? AND owner = ?").bind(userId, owner).run();
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
  }
  throw new NewRelicRemoteError("認証情報を更新中です。少し待ってから再試行してください。");
}

async function readMcpResponse(response, maxBytes) {
  if (response.status === 401 || response.status === 403) throw new NewRelicAuthError();
  if (response.status === 429) {
    throw new NewRelicRemoteError("New Relic公式MCPの呼び出し上限に達しました。少し待ってから再試行してください。");
  }
  const reader = response.body?.getReader();
  const chunks = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new NewRelicRemoteError("New Relic公式MCPの応答が上限を超えました。取得内容を減らして再試行してください。");
      }
      chunks.push(value);
    }
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const body = decoder.decode(bytes);
  if (!response.ok) {
    throw new NewRelicRemoteError("New Relic公式MCPへのリクエストに失敗しました。HTTP " + response.status + "。");
  }
  if (!body) return null;
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("text/event-stream")) {
    const events = body.split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim());
    for (let index = events.length - 1; index >= 0; index -= 1) {
      if (events[index] === "[DONE]") continue;
      try { return JSON.parse(events[index]); } catch { /* try the preceding event */ }
    }
    throw new NewRelicRemoteError("New Relic公式MCPからJSON-RPCイベントを読み取れませんでした。");
  }
  try {
    return JSON.parse(body);
  } catch {
    throw new NewRelicRemoteError("New Relic公式MCPからJSON-RPC以外の応答が返りました。");
  }
}

async function postMcp(endpoint, token, sessionId, payload) {
  const headers = new Headers({
    authorization: "Bearer " + token,
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    "mcp-protocol-version": MCP_PROTOCOL_VERSION,
    "include-tags": "discovery,data-access,alerting",
    "cache-control": "no-store",
  });
  if (sessionId) headers.set("mcp-session-id", sessionId);
  let response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(12000),
    });
  } catch {
    throw new NewRelicRemoteError("New Relic公式MCPに接続できませんでした。");
  }
  const nextSessionId = response.headers.get("mcp-session-id") || sessionId || null;
  const parsed = await readMcpResponse(response, payload.method === "tools/list" ? 2 * 1024 * 1024 : 256 * 1024);
  if (parsed?.error) {
    if (parsed.error.code === -32001 || /auth|token|unauthorized/i.test(String(parsed.error.message || ""))) {
      throw new NewRelicAuthError();
    }
    throw new NewRelicRemoteError("New Relic公式MCPがリクエストを拒否しました。");
  }
  return { payload: parsed, sessionId: nextSessionId };
}

async function startRemoteSession(endpoint, token) {
  const initialized = await postMcp(endpoint, token, null, {
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "newrelic-chatgpt-sites", version: "0.2.0" },
    },
  });
  if (!initialized.payload?.result) {
    throw new NewRelicRemoteError("New Relic公式MCPの初期化に失敗しました。");
  }
  let sessionId = initialized.sessionId;
  const notified = await postMcp(endpoint, token, sessionId, {
    jsonrpc: "2.0",
    method: "notifications/initialized",
  });
  sessionId = notified.sessionId || sessionId;
  const tools = [];
  const seenCursors = new Set();
  let cursor;
  for (let page = 0; page < 10; page++) {
    const listed = await postMcp(endpoint, token, sessionId, {
      jsonrpc: "2.0", id: 2 + page, method: "tools/list", params: cursor ? { cursor } : {},
    });
    sessionId = listed.sessionId || sessionId;
    const batch = listed.payload?.result?.tools;
    if (!Array.isArray(batch) || tools.length + batch.length > 500) {
      throw new NewRelicRemoteError("New Relic公式MCPのツール一覧を取得できませんでした。");
    }
    tools.push(...batch);
    const next = listed.payload?.result?.nextCursor;
    if (!next) break;
    if (typeof next !== "string" || next.length > 2048 || seenCursors.has(next) || page === 9) {
      throw new NewRelicRemoteError("New Relic公式MCPのツール一覧が上限を超えました。");
    }
    seenCursors.add(next);
    cursor = next;
  }
  return {
    endpoint,
    token,
    sessionId,
    tools,
    requestId: 20,
    callCount: 0,
  };
}

function normalizedName(value) {
  return String(value).replace(/[^a-z0-9]/gi, "").toLowerCase();
}

function upstreamArgumentValue(name, schema, values) {
  const field = normalizedName(name);
  const type = schema?.type;
  if (field.includes("account")) return values.accountId;
  if (field.includes("nrql") || field.includes("query")) return values.nrql ?? values.query;
  if (field.includes("metric")) return values.metricName ?? values.search;
  if (field.includes("entity") && field.includes("guid")) return values.entityGuid;
  if (field.includes("since") || field.includes("timerange") || field.includes("timewindow")) {
    return type === "number" || type === "integer" ? values.sinceMinutes : values.since;
  }
  if (field.includes("starttime") || field.includes("startdate")) return values.startTime;
  if (field.includes("endtime") || field.includes("enddate")) return values.endTime;
  if (field.includes("limit") || field.includes("maxresults") || field.includes("pagesize")) return values.limit;
  if (field.includes("search") || field.includes("pattern") || field.includes("filter")) return values.search ?? values.filter;
  if (field.includes("status")) return values.status;
  if (field.includes("incident")) return values.incidentId;
  if (field.includes("issue")) return values.issueId;
  return undefined;
}

function buildUpstreamArguments(tool, values) {
  const schema = tool?.inputSchema || {};
  const properties = schema.properties || {};
  const args = {};
  for (const [key, property] of Object.entries(properties)) {
    const value = upstreamArgumentValue(key, property, values);
    if (value === undefined || value === null || value === "") continue;
    args[key] = property?.type === "integer" || property?.type === "number" ? Number(value) : value;
  }
  const missing = (schema.required || []).filter((key) => args[key] === undefined || Number.isNaN(args[key]));
  if (missing.length) {
    throw new NewRelicRemoteError("New Relic公式MCPの必須引数に未対応の項目があります: " + missing.join(", ") + "。");
  }
  return args;
}

async function callRemoteTool(session, toolName, values = {}) {
  session.callCount += 1;
  if (session.callCount > 8) {
    throw new NewRelicRemoteError("1回の調査で実行できるNew Relic呼び出し数の上限に達しました。");
  }
  const definition = session.tools.find((tool) => tool.name === toolName);
  if (!definition) {
    throw new NewRelicRemoteError("New Relic公式MCPで必要なツールが見つかりません: " + toolName + "。");
  }
  const response = await postMcp(session.endpoint, session.token, session.sessionId, {
    jsonrpc: "2.0",
    id: session.requestId++,
    method: "tools/call",
    params: {
      name: toolName,
      arguments: buildUpstreamArguments(definition, values),
    },
  });
  session.sessionId = response.sessionId || session.sessionId;
  const result = response.payload?.result;
  if (!result) throw new NewRelicRemoteError("New Relic公式MCPからツール結果が返りませんでした。");
  if (result.isError) {
    const message = Array.isArray(result.content)
      ? result.content.filter((item) => item.type === "text").map((item) => item.text).join("\n")
      : "";
    if (/auth|token|unauthorized/i.test(message)) throw new NewRelicAuthError();
    throw new NewRelicRemoteError("New Relic公式MCPのツール呼び出しが失敗しました。権限と入力を確認してください。");
  }
  return result;
}

export async function withNewRelicSession(env, userId, callback) {
  let lastError;
  let failedToken = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const auth = await accessToken(env, userId, attempt === 1, failedToken);
    const endpoint = MCP_ENDPOINTS[auth.region];
    try {
      const session = await startRemoteSession(endpoint, auth.token);
      return await callback(session);
    } catch (error) {
      lastError = error;
      if (!(error instanceof NewRelicAuthError) || attempt === 1) throw error;
      failedToken = auth.token;
    }
  }
  throw lastError || new NewRelicAuthError();
}

export async function callNewRelicTool(session, toolName, values = {}) {
  return callRemoteTool(session, toolName, values);
}

export function findNewRelicTool(session, candidates) {
  const names = candidates.map(normalizedName);
  return session.tools.find((tool) => names.includes(normalizedName(tool.name))) || null;
}

export function newRelicRegionEndpoint(region) {
  return MCP_ENDPOINTS[validRegion(region)];
}

export const NEW_RELIC_OAUTH_CLIENT_ID = CLIENT_ID;
