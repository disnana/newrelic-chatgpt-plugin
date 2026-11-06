const CLIENT_ID = "pUWGgnjsQ0bydqCbavTPpw==";
const AUTHORIZATION_ENDPOINT = "https://oauth2.service.newrelic.com/oauth2/auth";
const TOKEN_ENDPOINT = "https://oauth2.service.newrelic.com/oauth2/token";
const MCP_ENDPOINTS = {
  us: "https://mcp.newrelic.com/mcp/",
  eu: "https://mcp.eu.newrelic.com/mcp/",
  jp: "https://mcp.jp.newrelic.com/mcp/",
};
const MCP_PROTOCOL_VERSION = "2025-03-26";
import { getUsageConsents } from "./usage-consent.js";
const LEGACY_CORE_COMPUTE_TOOLS = new Set([
  "list_available_new_relic_accounts", "list_new_relic_accounts", "list_accounts",
  "list_metric_names", "search_metric_names",
  "execute_nrql_query", "execute_nrql", "run_nrql_query",
  "list_recent_issues", "search_incident", "list_alert_policies",
]);
const LEGACY_ADVANCED_COMPUTE_TOOLS = new Set([
  "natural_language_to_nrql_query", "analyze_deployment_impact",
  "generate_alert_insights_report", "generate_user_impact_report",
]);
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class NewRelicAuthError extends Error {
  constructor(message = "New Relicへの再認証が必要です。接続ページから再接続してください。", code = "reauthentication_required", refreshable = false) {
    super(message);
    this.name = "NewRelicAuthError";
    this.code = code;
    this.requiresReauthentication = !refreshable;
    this.refreshable = refreshable;
  }
}

export class NewRelicRemoteError extends Error {
  constructor(message = "New Relic公式MCPから正常な応答を取得できませんでした。", code = "provider_error", retryable = false) {
    super(message);
    this.name = "NewRelicRemoteError";
    this.code = code;
    this.retryable = retryable;
    this.requiresReauthentication = false;
  }
}

function credentialError() {
  return new NewRelicRemoteError("保存済み認証情報を復号できません。暗号鍵と保存設定を確認してください。認証情報は保持されています。", "credential_storage_error");
}

function tokenExpiry(payload) {
  const seconds = payload.expires_in === undefined ? 300 : Number(payload.expires_in);
  if (!Number.isFinite(seconds) || seconds <= 0 || seconds > 86400) {
    throw new NewRelicRemoteError("OAuth応答の有効期限が不正です。", "invalid_token_response");
  }
  return Date.now() + seconds * 1000;
}

function validToken(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 16384 && !/[\r\n\u0000]/.test(value);
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

export function authenticationMode(env = {}) {
  const mode = env?.NEW_RELIC_AUTH_MODE === undefined ? "sites" : env.NEW_RELIC_AUTH_MODE;
  return mode === "sites" || mode === "signed_proxy" ? mode : "invalid";
}

function configuredSelfHostOrigin(env) {
  const value = env?.NEW_RELIC_AUTH_ALLOWED_ORIGIN;
  if (typeof value !== "string" || !value || value.length > 512) return null;
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

export function isRequestOriginAllowed(request, env = {}, requireOrigin = false) {
  const mode = authenticationMode(env);
  if (mode === "signed_proxy") {
    if (request.headers.get("sec-fetch-site") === "cross-site") return false;
    const origin = request.headers.get("origin");
    return origin ? origin === configuredSelfHostOrigin(env) : !requireOrigin;
  }
  if (mode !== "sites") return false;
  try { return request.headers.get("origin") === new URL(request.url).origin; }
  catch { return false; }
}

export function publicAppOrigin(request, env = {}) {
  const mode = authenticationMode(env);
  if (mode === "signed_proxy") return configuredSelfHostOrigin(env);
  if (mode !== "sites") return null;
  try { return new URL(request.url).origin; }
  catch { return null; }
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

function decodeJwtJson(segment, maxBytes) {
  if (typeof segment !== "string" || !segment || segment.length > maxBytes * 2
    || !/^[A-Za-z0-9_-]+$/.test(segment)) return null;
  try {
    const bytes = base64UrlToBytes(segment);
    if (bytes.byteLength > maxBytes) return null;
    const value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return plainObject(value) ? value : null;
  } catch { return null; }
}

function selfHostAllowedSubjects(env) {
  const configured = env?.NEW_RELIC_AUTH_ALLOWED_SUBJECTS;
  if (typeof configured !== "string" || configured.length > 32768) return null;
  try {
    const values = JSON.parse(configured);
    if (!Array.isArray(values) || values.length < 1 || values.length > 100
      || values.some(value => typeof value !== "string" || !value || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value))) return null;
    return new Set(values);
  } catch { return null; }
}

async function signedProxyPrincipal(request, env) {
  const issuer = env?.NEW_RELIC_AUTH_ISSUER;
  const audience = env?.NEW_RELIC_AUTH_AUDIENCE;
  const encodedKey = env?.NEW_RELIC_AUTH_JWT_PUBLIC_KEY;
  const allowedSubjects = selfHostAllowedSubjects(env);
  if (!secureIssuer(issuer)
    || typeof audience !== "string" || !audience || audience.length > 256
    || !configuredSelfHostOrigin(env)
    || typeof encodedKey !== "string" || encodedKey.length > 8192 || !/^[A-Za-z0-9_-]+$/.test(encodedKey)
    || !allowedSubjects) return null;

  const authorization = request.headers.get("authorization") || "";
  if (authorization.length > 8192) return null;
  const match = /^Bearer ([A-Za-z0-9._-]+)$/.exec(authorization);
  if (!match || match[1].length > 4096) return null;
  const parts = match[1].split(".");
  if (parts.length !== 3) return null;
  const header = decodeJwtJson(parts[0], 1024);
  const claims = decodeJwtJson(parts[1], 4096);
  if (!header || !claims || header.alg !== "RS256"
    || (header.typ !== undefined && header.typ !== "JWT")
    || ["jku", "jwk", "x5u", "crit", "b64"].some(name => Object.hasOwn(header, name))) return null;
  const expectedKid = env?.NEW_RELIC_AUTH_JWT_KID;
  if (expectedKid && header.kid !== expectedKid) return null;
  if (!expectedKid && header.kid !== undefined && (typeof header.kid !== "string" || header.kid.length > 128)) return null;

  const subject = claims.sub;
  if (claims.iss !== issuer || !(claims.aud === audience || Array.isArray(claims.aud) && claims.aud.length <= 8 && claims.aud.includes(audience))
    || typeof subject !== "string" || !allowedSubjects.has(subject)) return null;
  if ([subject, claims.iss, issuer, audience].some(value => /[\u0000-\u001f\u007f]/.test(value))) return null;
  const now = Math.floor(Date.now() / 1000);
  const { exp, iat, nbf } = claims;
  if (!Number.isSafeInteger(exp) || !Number.isSafeInteger(iat) || exp <= now - 30 || iat > now + 30
    || iat < now - 900 || exp <= iat || exp - iat > 900
    || nbf !== undefined && (!Number.isSafeInteger(nbf) || nbf > now + 30 || nbf > exp)) return null;
  if (!/^[A-Za-z0-9_-]+$/.test(parts[2]) || parts[2].length > 1024) return null;

  let publicKeyBytes;
  let signature;
  try {
    publicKeyBytes = base64UrlToBytes(encodedKey);
    signature = base64UrlToBytes(parts[2]);
    if (publicKeyBytes.byteLength > 4096 || signature.byteLength > 512) return null;
    const key = await crypto.subtle.importKey("spki", publicKeyBytes,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    const rsaAlgorithm = /** @type {RsaHashedKeyAlgorithm} */ (key.algorithm);
    if (rsaAlgorithm.modulusLength < 2048 || rsaAlgorithm.modulusLength > 4096) return null;
    const verified = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, signature, encoder.encode(parts[0] + "." + parts[1]));
    if (!verified) return null;
  } catch { return null; }
  return { issuer, audience, subject };
}

export async function siteUserId(request, env = {}) {
  const mode = authenticationMode(env);
  if (mode === "signed_proxy") {
    const principal = await signedProxyPrincipal(request, env);
    if (!principal) return null;
    return bytesToBase64Url(await hash("signed_proxy\0" + principal.issuer + "\0" + principal.audience + "\0" + principal.subject));
  }
  if (mode !== "sites") return null;
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
  // Refresh rotation can commit upstream before a timeout/5xx reaches us. Never
  // blindly replay those ambiguous exchanges. A rejected 429 is retried once.
  for (let attempt = 0; attempt < 2; attempt++) {
    let response;
    try {
      response = await fetch(TOKEN_ENDPOINT, {
        method: "POST", redirect: "error",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json", "cache-control": "no-store" },
        body: new URLSearchParams(form), signal: AbortSignal.timeout(12000),
      });
    } catch {
      throw new NewRelicRemoteError("New Relic OAuthへの接続が一時的に失敗しました。認証情報は保持されています。", "oauth_network_error", true);
    }
    if (response.status === 429) {
      const retryAfter = Number(response.headers.get("retry-after") || 0);
      await response.body?.cancel();
      if (attempt === 0 && retryAfter >= 0 && retryAfter <= 1) {
        await new Promise((resolve) => setTimeout(resolve, Math.max(100, retryAfter * 1000)));
        continue;
      }
      throw new NewRelicRemoteError("New Relic OAuthの呼び出し上限です。時間を置いて再試行してください。", "oauth_rate_limited", true);
    }
    if (response.status >= 500) {
      await response.body?.cancel();
      throw new NewRelicRemoteError("New Relic OAuthで一時的な障害が発生しています。認証情報は保持されています。", "oauth_unavailable", true);
    }
    let payload;
    try { payload = JSON.parse(await readBoundedBody(response, 64 * 1024)); }
    catch { throw new NewRelicRemoteError("New Relic OAuthの応答形式が不正です。", "invalid_token_response"); }
    if (!response.ok || payload?.error) {
      const error = payload?.error;
      if (error === "invalid_grant" || error === "access_denied") {
        throw new NewRelicAuthError("New Relicの認可が失効または拒否されました。再接続してください。", "oauth_" + error);
      }
      if (error === "invalid_client" || error === "unauthorized_client" || error === "invalid_scope") {
        throw new NewRelicRemoteError("New Relic OAuthクライアント設定を確認してください。再ログインだけでは解決しない可能性があります。", "oauth_configuration_error");
      }
      throw new NewRelicRemoteError("New Relic OAuthのトークン交換が拒否されました。", "oauth_rejected");
    }
    if (!payload || Array.isArray(payload) || !validToken(payload.access_token)
      || (payload.refresh_token !== undefined && !validToken(payload.refresh_token))
      || (payload.token_type !== undefined && String(payload.token_type).toLowerCase() !== "bearer")) {
      throw new NewRelicRemoteError("New Relic OAuthから有効なトークン応答を取得できませんでした。", "invalid_token_response");
    }
    tokenExpiry(payload);
    return payload;
  }
}

async function exchangeAuthorizationResponse({ state, code, error, redirectUri }, env, expectedUserId) {
  if (!expectedUserId) throw new NewRelicAuthError("ChatGPTのSiteセッションを確認できません。Siteを開き直してください。");
  if (!state || state.length > 256 || (!code && !error) || (code && code.length > 4096)) {
    throw new Error("OAuth応答を読み取れません。認証URL全体を貼り付けてください。");
  }
  const db = database(env);
  const stateHash = bytesToBase64Url(await hash(state));
  const flow = await db.prepare(
    "SELECT user_id, encrypted_verifier, redirect_uri, region, expires_at, consumed_at FROM nr_oauth_states WHERE state_hash = ?",
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
  if (flow.consumed_at !== null && flow.consumed_at !== undefined) {
    throw new Error("OAuthの確認状態はすでに使用済みです。接続をやり直してください。");
  }
  const claimedAt = Date.now();
  const consumeResult = await db.prepare(
    "UPDATE nr_oauth_states SET consumed_at = ? WHERE state_hash = ? AND user_id = ? AND consumed_at IS NULL AND expires_at >= ?",
  ).bind(claimedAt, stateHash, expectedUserId, Math.floor(claimedAt / 1000)).run();
  if (Number(consumeResult?.meta?.changes || 0) !== 1) {
    throw new Error("OAuthの確認状態はすでに使用済みです。接続をやり直してください。");
  }
  const consumed = flow;
  if (error) {
    await db.prepare("DELETE FROM nr_oauth_states WHERE state_hash = ? AND user_id = ? AND consumed_at = ?")
      .bind(stateHash, expectedUserId, claimedAt).run();
    throw new NewRelicAuthError("New Relicへの接続が完了しませんでした。接続をやり直してください。");
  }

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
  const accessExpiresAt = tokenExpiry(token);
  const encryptedAccess = await encryptSecret(token.access_token, env);
  const encryptedRefresh = await encryptSecret(token.refresh_token, env);
  const saved = await db.prepare(
    "INSERT INTO nr_connections (user_id, encrypted_access_token, encrypted_refresh_token, access_expires_at, connected_at, region) SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM nr_oauth_states WHERE state_hash = ? AND user_id = ? AND consumed_at = ? AND expires_at >= ?) ON CONFLICT(user_id) DO UPDATE SET encrypted_access_token = excluded.encrypted_access_token, encrypted_refresh_token = excluded.encrypted_refresh_token, access_expires_at = excluded.access_expires_at, connected_at = excluded.connected_at, region = excluded.region",
  ).bind(consumed.user_id, encryptedAccess, encryptedRefresh, accessExpiresAt, now,
    validRegion(consumed.region), stateHash, expectedUserId, claimedAt, Math.floor(now / 1000)).run();
  if (Number(saved?.meta?.changes || 0) !== 1) {
    throw new NewRelicAuthError("接続解除または認証フローの変更を確認したため、新しい認証情報は保存しませんでした。接続をやり直してください。", "oauth_connection_cancelled");
  }
  await db.prepare("DELETE FROM nr_oauth_states WHERE state_hash = ? AND user_id = ? AND consumed_at = ?")
    .bind(stateHash, expectedUserId, claimedAt).run();
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

export async function getConnectionStatus(env, userId, { refreshIfNeeded = false } = {}) {
  if (!userId) return { authenticated: false, connected: false, requiresSiteAuthentication: true };
  const connection = await database(env).prepare(
    "SELECT connected_at, access_expires_at, region FROM nr_connections WHERE user_id = ?",
  ).bind(userId).first();
  if (!connection) return { authenticated: true, connected: false, selectedAccount: null };

  let currentConnection = connection;
  let requiresReauthentication = false;
  let refreshError = null;
  if (refreshIfNeeded && Number(connection.access_expires_at) <= Date.now() + 30000) {
    try {
      await accessToken(env, userId);
      currentConnection = await database(env).prepare(
        "SELECT connected_at, access_expires_at, region FROM nr_connections WHERE user_id = ?",
      ).bind(userId).first() || connection;
    } catch (error) {
      requiresReauthentication = error instanceof NewRelicAuthError && error.requiresReauthentication;
      refreshError = { code: error.code || "storage_error", retryable: Boolean(error.retryable), message: error instanceof NewRelicAuthError || error instanceof NewRelicRemoteError ? error.message : "認証情報の保存処理を確認してください。" };
    }
  }
  const accessTokenExpiresAt = Number(currentConnection.access_expires_at);
  return {
    authenticated: true,
    connected: true,
    connectedAt: Number(connection.connected_at),
    accessTokenExpiresAt: Number.isFinite(accessTokenExpiresAt) ? accessTokenExpiresAt : null,
    region: validRegion(currentConnection.region),
    selectedAccount: await getSelectedAccount(env, userId),
    tokenRefreshDue: !Number.isFinite(accessTokenExpiresAt) || accessTokenExpiresAt <= Date.now() + 30000,
    requiresReauthentication,
    refreshError,
    providerReachable: null,
    statusSource: refreshIfNeeded ? "token_refresh_probe" : "local_metadata",
    refreshPolicy: { proactiveWindowSeconds: 30, providerReauthenticationHours: 24 },
  };
}

export async function getSelectedAccount(env, userId) {
  if (!userId) return null;
  const row = await database(env).prepare(
    "SELECT account_id, account_name, updated_at FROM nr_preferences WHERE user_id = ?",
  ).bind(userId).first();
  if (!row) return null;
  const id = String(row.account_id);
  if (!id || id.length > 128) return null;
  return {
    id,
    name: row.account_name ? String(row.account_name).slice(0, 512) : "",
    updatedAt: Number(row.updated_at),
  };
}

export async function saveSelectedAccount(env, userId, account) {
  if (!userId) throw new Error("ChatGPTのSiteセッションを確認できません。");
  const accountId = String(account?.id ?? "");
  if (!accountId || accountId.length > 128) throw new Error("New RelicアカウントIDが不正です。");
  await database(env).prepare(
    "INSERT INTO nr_preferences (user_id, account_id, account_name, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET account_id = excluded.account_id, account_name = excluded.account_name, updated_at = excluded.updated_at",
  ).bind(userId, accountId, String(account.name || "").slice(0, 512), Date.now()).run();
}

export async function disconnectNewRelic(env, userId) {
  if (!userId) throw new Error("ChatGPTのSiteセッションを確認できません。");
  const db = database(env);
  // D1 batch is atomic. Remove the OAuth completion fence first so an in-flight
  // callback cannot pass its state-row check and recreate credentials while
  // disconnect is deleting the saved connection.
  await db.batch([
    db.prepare("DELETE FROM nr_oauth_states WHERE user_id = ?").bind(userId),
    db.prepare("DELETE FROM nr_connections WHERE user_id = ?").bind(userId),
    db.prepare("DELETE FROM nr_preferences WHERE user_id = ?").bind(userId),
  ]);
  return { connected: false, localConnectionRemoved: true, providerGrantRevoked: false };
}

export async function consumeRateLimit(env, userId, limit = 20, bucket = "default") {
  if (!userId) throw new NewRelicAuthError("ChatGPTのSiteセッションを確認できません。");
  const db = database(env);
  if (!/^[a-z0-9_-]{1,32}$/i.test(bucket)) throw new Error("レート制限区分が不正です。");
  const rateLimitUserId = bucket === "default" ? userId : `${userId}:${bucket}`;
  const windowStart = Math.floor(Date.now() / 60000);
  await db.prepare("DELETE FROM nr_rate_limits WHERE user_id = ? AND window_start < ?")
    .bind(rateLimitUserId, windowStart - 120).run();
  await db.prepare(
    "INSERT INTO nr_rate_limits (user_id, window_start, call_count) VALUES (?, ?, 1) ON CONFLICT(user_id, window_start) DO UPDATE SET call_count = call_count + 1",
  ).bind(rateLimitUserId, windowStart).run();
  const row = await db.prepare(
    "SELECT call_count FROM nr_rate_limits WHERE user_id = ? AND window_start = ?",
  ).bind(rateLimitUserId, windowStart).first();
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
    throw credentialError();
  }
  const payload = await tokenRequest({
    grant_type: "refresh_token",
    client_id: CLIENT_ID,
    refresh_token: refreshToken,
  });
  if (!validToken(payload.access_token)) throw new NewRelicRemoteError("OAuth応答が不正です。", "invalid_token_response");
  const nextRefresh = typeof payload.refresh_token === "string" ? payload.refresh_token : refreshToken;
  const encryptedAccess = await encryptSecret(payload.access_token, env);
  const encryptedRefresh = await encryptSecret(nextRefresh, env);
  const accessExpiresAt = tokenExpiry(payload);
  const saved = await database(env).prepare(
    "UPDATE nr_connections SET encrypted_access_token = ?, encrypted_refresh_token = ?, access_expires_at = ? WHERE user_id = ? AND encrypted_refresh_token = ? AND EXISTS (SELECT 1 FROM nr_refresh_locks WHERE user_id = ? AND owner = ? AND expires_at > ?)",
  ).bind(encryptedAccess, encryptedRefresh, accessExpiresAt, userId, connection.encrypted_refresh_token, userId, lockOwner, Date.now()).run();
  if (Number(saved?.meta?.changes || 0) !== 1) throw new NewRelicRemoteError("接続状態が変更されたため更新結果を保存しませんでした。再試行してください。", "connection_changed", true);
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
      throw credentialError();
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
        let current;
        try { current = await decryptSecret(connection.encrypted_access_token, env); } catch { throw credentialError(); }
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
  throw new NewRelicRemoteError("認証情報を更新中です。少し待ってから再試行してください。", "refresh_busy", true);
}

async function readBoundedBody(response, maxBytes) {
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
  return body;
}

async function readMcpResponse(response, maxBytes) {
  if (response.status === 401) throw new NewRelicAuthError("New Relicのアクセストークンが拒否されました。", "access_token_rejected", true);
  if (response.status === 403) throw new NewRelicRemoteError("New Relicの権限または組織のMCP設定によって拒否されました。", "permission_denied");
  if (response.status === 429) throw new NewRelicRemoteError("New Relic公式MCPの呼び出し上限です。時間を置いて再試行してください。", "provider_rate_limited", true);
  const body = await readBoundedBody(response, maxBytes);
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
    "cache-control": "no-store",
  });
  if (sessionId) headers.set("mcp-session-id", sessionId);
  let response;
  try {
    response = await fetch(endpoint, {
      method: "POST",
      redirect: "error",
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
    throw new NewRelicRemoteError("New Relic公式MCPがリクエストを拒否しました。");
  }
  if (payload.id !== undefined && (!parsed || parsed.jsonrpc !== "2.0" || parsed.id !== payload.id || typeof parsed.result !== "object" || parsed.result === null)) {
    throw new NewRelicRemoteError("New Relic公式MCPの応答IDまたは形式が一致しません。", "invalid_mcp_response");
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
      clientInfo: { name: "newrelic-chatgpt-sites", version: "0.4.0" },
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

/** @param {any} session @param {string} toolName @param {Record<string, any>} values @param {boolean} raw @param {{operation: string, billing: string, preview: boolean} | null} rawPolicy */
async function callRemoteTool(session, toolName, values = {}, raw = false, rawPolicy = null) {
  if (!raw) {
    if (LEGACY_CORE_COMPUTE_TOOLS.has(toolName)) {
      if (!(await hasActiveUsageConsent(session, "core_compute"))) {
        throw new NewRelicRemoteError(
          "Core Compute (CCU) の利用が記録される可能性があるため、この読み取りを送信していません。CCU計測だけでは追加料金の有無は分かりません。含まれるか別料金かはNew Relicの契約・料金モデルによりますが、この連携では確認できません。接続ページでCore Compute読み取りを明示的に許可してください。",
          "usage_consent_required",
        );
      }
    } else if (LEGACY_ADVANCED_COMPUTE_TOOLS.has(toolName)) {
      if (!(await hasActiveUsageConsent(session, "advanced_compute"))) {
        throw new NewRelicRemoteError(
          "このAI分析はAdvanced Compute (aCCU) 用です。利用には対応する契約または試用枠が必要です。利用権と料金条件はこの連携では確認できません。接続ページでAdvanced Computeの利用を明示的に許可してください。",
          "advanced_compute_consent_required",
        );
      }
    } else {
      throw new NewRelicRemoteError(
        "この高レベル経路の課金区分が確認できず停止しています。スキーマ審査済みの汎用ポリシーを使用してください。",
        "legacy_tool_billing_unverified",
      );
    }
  } else {
    if (!rawPolicy || rawPolicy.operation !== "read"
      || !["core_compute", "advanced_compute"].includes(rawPolicy.billing)
      || typeof rawPolicy.preview !== "boolean") {
      throw new NewRelicRemoteError(
        "汎用MCPの送信には課金区分・Preview区分を含む審査済み読み取りポリシーが必要です。",
        "legacy_tool_billing_unverified",
      );
    }
    await assertActivePolicyConsent(session, rawPolicy);
  }
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
      arguments: raw ? values : buildUpstreamArguments(definition, values),
    },
  });
  session.sessionId = response.sessionId || session.sessionId;
  const result = response.payload?.result;
  if (!result || !Array.isArray(result.content) || result.content.some((item) => !item || typeof item.type !== "string") || (result.isError !== undefined && typeof result.isError !== "boolean")) throw new NewRelicRemoteError("New Relic公式MCPからツール結果が返りませんでした。");
  if (result.isError) {
    throw new NewRelicRemoteError("New Relic公式MCPのツール呼び出しが失敗しました。権限と入力を確認してください。");
  }
  return result;
}

async function currentUsageConsentState(session) {
  const state = typeof session.loadUsageConsentState === "function"
    ? await session.loadUsageConsentState()
    : (session.usageConsentState || {});
  session.usageConsentState = state;
  session.usageConsents = Object.fromEntries(Object.entries(state).map(([capability, consent]) => [capability, consent.enabled]));
  return state;
}

async function hasActiveUsageConsent(session, capability) {
  const consent = (await currentUsageConsentState(session))?.[capability];
  return consent?.enabled === true && Number.isSafeInteger(consent.expiresAt) && consent.expiresAt > Date.now();
}

async function assertActivePolicyConsent(session, policy) {
  const state = await currentUsageConsentState(session);
  const active = (capability) => {
    const consent = state?.[capability];
    return consent?.enabled === true && Number.isSafeInteger(consent.expiresAt) && consent.expiresAt > Date.now();
  };
  if (policy?.billing === "core_compute" && !active("core_compute")) {
    throw new NewRelicRemoteError(
      "Core Compute利用許可が未設定か期限切れのため、この読み取りを送信していません。接続ページで許可を保存してください。",
      "usage_consent_required",
    );
  }
  if (policy?.billing === "advanced_compute" && !active("advanced_compute")) {
    throw new NewRelicRemoteError(
      "Advanced Compute利用許可が未設定か期限切れのため、この読み取りを送信していません。接続ページで個別に許可してください。",
      "advanced_compute_consent_required",
    );
  }
  if (policy?.preview === true && !active("preview")) {
    throw new NewRelicRemoteError(
      "Preview利用許可が未設定か期限切れのため、この読み取りを送信していません。接続ページで個別に許可してください。",
      "preview_consent_required",
    );
  }
}

export async function withNewRelicSession(env, userId, callback, options = {}) {
  let lastError;
  let failedToken = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const auth = await accessToken(env, userId, attempt === 1, failedToken);
    const endpoint = MCP_ENDPOINTS[auth.region];
    try {
      const usageConsentState = await getUsageConsents(env, userId);
      const usageConsents = Object.fromEntries(Object.entries(usageConsentState)
        .map(([capability, consent]) => [capability, consent.enabled]));
      const session = await startRemoteSession(endpoint, auth.token);
      session.usageConsents = usageConsents;
      session.usageConsentState = usageConsentState;
      session.loadUsageConsentState = () => getUsageConsents(env, userId);
      return await callback(session);
    } catch (error) {
      lastError = error;
      if (!(error instanceof NewRelicAuthError) || !error.refreshable || options.readOnly === false) throw error;
      if (attempt === 1) {
        throw new NewRelicAuthError(
          "New Relicは更新後のアクセストークンも拒否しました。自動更新を試したため、New Relicへの再接続が必要です。",
          "access_token_rejected_after_refresh",
        );
      }
      failedToken = auth.token;
    }
  }
  throw lastError || new NewRelicAuthError();
}

export async function callNewRelicTool(session, toolName, values = {}) {
  return callRemoteTool(session, toolName, values);
}

// Only callers that have performed schema, policy, account and approval checks
// may use this exact-argument transport. It is not exposed as an MCP tool.
export async function callNewRelicRawTool(session, toolName, validatedArgs = {}, policy = null) {
  return callRemoteTool(session, toolName, validatedArgs, true, policy);
}

export function findNewRelicTool(session, candidates) {
  const names = candidates.map(normalizedName);
  return session.tools.find((tool) => names.includes(normalizedName(tool.name))) || null;
}

export function newRelicRegionEndpoint(region) {
  return MCP_ENDPOINTS[validRegion(region)];
}

export const NEW_RELIC_OAUTH_CLIENT_ID = CLIENT_ID;
