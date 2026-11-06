const encoder = new TextEncoder();
const SESSION_TTL_MS = 15 * 60 * 1000;
const PROPOSAL_TTL_MS = 5 * 60 * 1000;
const CHALLENGE_TTL_MS = 90 * 1000;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const HEX_HASH_PATTERN = /^[a-f0-9]{64}$/;
const REGIONS = new Set(["us", "eu", "jp"]);

export class OperationApprovalError extends Error {
  constructor(code, status = 409) {
    super(code);
    this.name = "OperationApprovalError";
    this.code = code;
    this.status = status;
  }
}

/** @returns {never} */
function fail(code, status) {
  throw new OperationApprovalError(code, status);
}

function randomToken(byteLength = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hash(value) {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

/** Canonical JSON for parsed JSON values only. Accessors, cycles, and non-JSON values fail. */
export function canonicalApprovalJson(value) {
  const active = new Set();
  let nodes = 0;
  function visit(item, depth) {
    nodes += 1;
    if (nodes > 4096 || depth > 16) fail("proposal_too_complex", 400);
    if (item === null || typeof item === "boolean" || typeof item === "string") return JSON.stringify(item);
    if (typeof item === "number") {
      if (!Number.isFinite(item)) fail("invalid_json_number", 400);
      return JSON.stringify(item);
    }
    if (typeof item !== "object" || active.has(item)) fail("invalid_json_value", 400);
    active.add(item);
    let result;
    if (Array.isArray(item)) {
      if (Object.getPrototypeOf(item) !== Array.prototype || item.length > 100) fail("invalid_json_array", 400);
      const keys = Reflect.ownKeys(item);
      if (keys.length !== item.length + 1 || !keys.includes("length")) fail("invalid_json_array", 400);
      result = "[" + item.map((child, index) => {
        const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail("invalid_json_array", 400);
        return visit(descriptor.value, depth + 1);
      }).join(",") + "]";
    } else {
      if (!plainObject(item)) fail("invalid_json_object", 400);
      const keys = Reflect.ownKeys(item);
      if (keys.length > 100 || keys.some(key => typeof key !== "string" || ["__proto__", "prototype", "constructor"].includes(key))) {
        fail("invalid_json_object", 400);
      }
      result = "{" + keys.sort().map(key => {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) fail("invalid_json_object", 400);
        return JSON.stringify(key) + ":" + visit(descriptor.value, depth + 1);
      }).join(",") + "}";
    }
    active.delete(item);
    return result;
  }
  const result = visit(value, 0);
  if (encoder.encode(result).byteLength > 32 * 1024) fail("proposal_too_large", 400);
  return result;
}

function validIdentity(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 128
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validateContext(context) {
  if (!plainObject(context) || !validIdentity(context.accountId) || !REGIONS.has(context.region)
    || typeof context.connectionGeneration !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(context.connectionGeneration)
    || typeof context.selectionGeneration !== "string" || !/^[A-Za-z0-9_-]{16,128}$/.test(context.selectionGeneration)) {
    fail("approval_context_unavailable", 409);
  }
}

function snapshotContext(context) {
  const json = canonicalApprovalJson(context);
  const snapshot = JSON.parse(json);
  if (Object.keys(snapshot).sort().join(",") !== "accountId,connectionGeneration,region,selectionGeneration") {
    fail("approval_context_unavailable", 409);
  }
  validateContext(snapshot);
  return snapshot;
}

function sameContext(row, context) {
  return row.account_id === context.accountId
    && row.region === context.region
    && row.connection_generation === context.connectionGeneration
    && row.selection_generation === context.selectionGeneration;
}

async function reviewPolicyHash(policy, schemaHash, effectSummary) {
  return hash(canonicalApprovalJson({
    policyId: policy.policyId,
    operation: policy.operation,
    billing: policy.billing,
    effectSummaryId: policy.effectSummaryId,
    effectSummary,
    schemaHash,
  }));
}

function validProposalId(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{24}$/.test(value);
}

function readSessionCookie(request) {
  const header = request.headers.get("cookie") || "";
  if (header.length > 4096) return null;
  const matches = [];
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === "__Host-nr-approval") matches.push(part.slice(separator + 1).trim());
  }
  if (matches.length !== 1 || !TOKEN_PATTERN.test(matches[0])) return null;
  return matches[0];
}

function validNow(now) {
  if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER - SESSION_TTL_MS) fail("invalid_clock", 500);
}

function assertMode(authMode) {
  if (authMode !== "sites" && authMode !== "signed_proxy") fail("approval_auth_unavailable", 401);
}

function assertFirstPartyJsonPost(request) {
  if (!(request instanceof Request) || request.method !== "POST") fail("approval_method_not_allowed", 405);
  const contentType = (request.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") fail("approval_json_required", 415);
  if (request.headers.get("sec-fetch-site") === "cross-site") fail("approval_origin_invalid", 403);
  try {
    const url = new URL(request.url);
    if (url.protocol !== "https:" || request.headers.get("origin") !== url.origin) fail("approval_origin_invalid", 403);
  } catch (error) {
    if (error instanceof OperationApprovalError) throw error;
    fail("approval_origin_invalid", 403);
  }
}

/** @param {{authMode: string, userId: string, cookieToken?: string|null, browserBinding?: string|null}} options */
async function deriveSessionHashes({ authMode, userId, cookieToken, browserBinding = null }) {
  if (!validIdentity(userId)) fail("approval_identity_unavailable", 401);
  if (authMode === "sites") {
    if (!TOKEN_PATTERN.test(cookieToken || "")) fail("approval_session_required", 401);
    return {
      sessionKeyHash: await hash("nr-approval-session\0sites\0" + userId + "\0" + cookieToken),
      browserBindingHash: await hash("nr-approval-binding\0sites\0" + userId + "\0" + cookieToken),
    };
  }
  if (typeof browserBinding !== "string" || !/^[A-Za-z0-9_-]{22,256}$/.test(browserBinding)) {
    fail("approval_browser_session_unavailable", 401);
  }
  return {
    sessionKeyHash: await hash("nr-approval-session\0signed_proxy\0" + userId + "\0" + browserBinding),
    browserBindingHash: await hash("nr-approval-binding\0signed_proxy\0" + userId + "\0" + browserBinding),
  };
}

function listPublicProposal(row) {
  return {
    proposalId: row.proposal_id,
    status: row.status,
    toolName: row.tool_name,
    operation: row.operation,
    billing: row.billing,
    account: { id: row.account_id, region: row.region },
    effectSummary: row.effect_summary,
    createdAt: Number(row.created_at),
    expiresAt: Number(row.expires_at),
  };
}

/**
 * Create the durable approval state machine. Production must use the default
 * empty policy registry until each upstream mutation schema/effect is reviewed.
 * `policies` exists for isolated unit tests and is never sourced from requests.
 */
/**
 * @param {{db: {prepare: Function}, encryptArguments?: (value: string) => Promise<string>,
 * decryptArguments?: (value: string) => Promise<string>, policies?: Map<string, any>, enabled?: boolean,
 * now?: () => number, token?: (byteLength?: number) => string}} options
 * @returns {Readonly<Record<string, any>>}
 */
export function createOperationApprovalService({ db, encryptArguments, decryptArguments, policies = new Map(), enabled = false, now = () => Date.now(), token = randomToken }) {
  if (!db || typeof db.prepare !== "function") throw new TypeError("D1 binding is required.");
  const policyRegistry = policies instanceof Map ? policies : new Map();

  function requireEnabled() {
    if (enabled !== true) fail("operation_approval_disabled", 404);
  }

  function getPolicy(toolName) {
    const policy = policyRegistry.get(toolName);
    if (!policy || policy.enabled !== true || !["write", "destructive"].includes(policy.operation)
      || !["none", "core_compute", "advanced_compute"].includes(policy.billing)
      || typeof policy.policyId !== "string" || !policy.policyId
      || typeof policy.effectSummaryId !== "string" || !policy.effectSummaryId
      || typeof policy.validateArguments !== "function" || typeof policy.effectSummary !== "function") {
      fail("operation_policy_unavailable", 409);
    }
    return policy;
  }

  /** @param {{request: Request, userId: string, authMode: string, browserBinding?: string|null}} options */
  async function ensureSession({ request, userId, authMode, browserBinding = null }) {
    requireEnabled();
    assertMode(authMode);
    validNow(now());
    assertFirstPartyJsonPost(request);
    const cookieToken = authMode === "sites" ? readSessionCookie(request) : null;
    const hashes = authMode === "sites" && !cookieToken
      ? null
      : await deriveSessionHashes({ authMode, userId, cookieToken, browserBinding });
    const currentNow = now();
    const existing = hashes && await db.prepare(
      "SELECT session_key_hash, user_id, auth_mode, browser_binding_hash, csrf_hash, created_at, expires_at, revoked_at FROM nr_approval_sessions WHERE session_key_hash = ?",
    ).bind(hashes.sessionKeyHash).first();
    if (existing && (existing.user_id !== userId || existing.auth_mode !== authMode
      || !constantTimeEqual(existing.browser_binding_hash, hashes.browserBindingHash))) {
      fail("approval_session_mismatch", 401);
    }
    if (existing && existing.revoked_at === null && Number(existing.expires_at) > currentNow
      && Number(existing.created_at) + SESSION_TTL_MS > currentNow) {
      const csrfToken = token(32);
      const csrfHash = await hash("nr-approval-csrf\0" + csrfToken);
      const updated = await db.prepare(
        "UPDATE nr_approval_sessions SET csrf_hash = ? WHERE session_key_hash = ? AND user_id = ? AND auth_mode = ? AND browser_binding_hash = ? AND revoked_at IS NULL AND expires_at > ? AND created_at + ? > ?",
      ).bind(csrfHash, hashes.sessionKeyHash, userId, authMode, hashes.browserBindingHash,
        currentNow, SESSION_TTL_MS, currentNow).run();
      if (Number(updated?.meta?.changes || 0) !== 1) fail("approval_session_changed", 409);
      return {
        sessionKeyHash: hashes.sessionKeyHash,
        csrfToken,
        cookieToken,
        expiresAt: Number(existing.created_at) + SESSION_TTL_MS,
        created: false,
      };
    }
    if (authMode === "signed_proxy" && existing) {
      await db.prepare(
        "UPDATE nr_approval_sessions SET revoked_at = ? WHERE session_key_hash = ? AND user_id = ? AND revoked_at IS NULL",
      ).bind(currentNow, hashes.sessionKeyHash, userId).run();
      fail("approval_session_expired", 401);
    }
    if (existing) {
      await db.prepare(
        "UPDATE nr_approval_sessions SET revoked_at = ? WHERE session_key_hash = ? AND user_id = ? AND revoked_at IS NULL",
      ).bind(currentNow, hashes.sessionKeyHash, userId).run();
    }
    const newCookieToken = authMode === "sites" ? token(32) : null;
    const activeHashes = authMode === "sites"
      ? await deriveSessionHashes({ authMode, userId, cookieToken: newCookieToken })
      : hashes;
    if (activeHashes === null) throw new OperationApprovalError("approval_identity_unavailable", 401);
    const csrfToken = token(32);
    const csrfHash = await hash("nr-approval-csrf\0" + csrfToken);
    const expiresAt = currentNow + SESSION_TTL_MS;
    await db.prepare(
      "INSERT INTO nr_approval_sessions (session_key_hash, user_id, auth_mode, browser_binding_hash, csrf_hash, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
    ).bind(activeHashes.sessionKeyHash, userId, authMode, activeHashes.browserBindingHash,
      csrfHash, currentNow, expiresAt).run();
    return {
      sessionKeyHash: activeHashes.sessionKeyHash,
      csrfToken,
      cookieToken: newCookieToken,
      expiresAt,
      created: true,
    };
  }

  /** @param {{request: Request, userId: string, authMode: string, browserBinding?: string|null, csrfToken?: string|null}} options */
  async function requireSession({ request, userId, authMode, browserBinding = null, csrfToken }) {
    requireEnabled();
    assertMode(authMode);
    assertFirstPartyJsonPost(request);
    const cookieToken = authMode === "sites" ? readSessionCookie(request) : null;
    const hashes = await deriveSessionHashes({ authMode, userId, cookieToken, browserBinding });
    const row = await db.prepare(
      "SELECT session_key_hash, user_id, auth_mode, browser_binding_hash, csrf_hash, created_at, expires_at, revoked_at FROM nr_approval_sessions WHERE session_key_hash = ?",
    ).bind(hashes.sessionKeyHash).first();
    const currentNow = now();
    if (!row || row.user_id !== userId || row.auth_mode !== authMode || row.revoked_at !== null
      || Number(row.expires_at) <= currentNow || Number(row.created_at) + SESSION_TTL_MS <= currentNow
      || !constantTimeEqual(row.browser_binding_hash, hashes.browserBindingHash)) {
      fail("approval_session_required", 401);
    }
    if (!TOKEN_PATTERN.test(csrfToken || "")) fail("approval_csrf_invalid", 403);
    const csrfHash = await hash("nr-approval-csrf\0" + csrfToken);
    if (!constantTimeEqual(row.csrf_hash, csrfHash)) fail("approval_csrf_invalid", 403);
    return { sessionKeyHash: hashes.sessionKeyHash, userId, authMode, expiresAt: Number(row.expires_at) };
  }

  async function assertActiveSession(sessionKeyHash, userId, currentNow) {
    const row = await db.prepare(
      "SELECT session_key_hash FROM nr_approval_sessions WHERE session_key_hash = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > ? AND created_at + ? > ?",
    ).bind(sessionKeyHash, userId, currentNow, SESSION_TTL_MS, currentNow).first();
    if (!row) fail("approval_session_required", 401);
  }

  async function createProposal({ userId, toolName, args, context, billing, sessionKeyHash = null }) {
    requireEnabled();
    validNow(now());
    if (!validIdentity(userId) || sessionKeyHash !== null && !HEX_HASH_PATTERN.test(sessionKeyHash)) {
      fail("approval_identity_unavailable", 401);
    }
    const policy = getPolicy(toolName);
    if (billing !== policy.billing) fail("proposal_billing_changed", 409);
    const contextSnapshot = snapshotContext(context);
    const argumentsJson = canonicalApprovalJson(args);
    if (policy.validateArguments(JSON.parse(argumentsJson)) !== true) fail("proposal_arguments_rejected", 400);
    if (typeof encryptArguments !== "function") fail("proposal_encryption_unavailable", 503);
    const effectSummary = policy.effectSummary(JSON.parse(argumentsJson), contextSnapshot);
    if (typeof effectSummary !== "string" || !effectSummary.trim() || effectSummary.length > 1000
      || /[\u0000-\u001f\u007f]/.test(effectSummary)) fail("proposal_effect_unavailable", 409);
    if (typeof decryptArguments !== "function") fail("proposal_decryption_unavailable", 503);
    const schemaJson = canonicalApprovalJson(policy.schema);
    const schemaHash = await hash(schemaJson);
    const policyHash = await reviewPolicyHash(policy, schemaHash, effectSummary);
    const argumentsHash = await hash(argumentsJson);
    const encrypted = await encryptArguments(argumentsJson);
    if (typeof encrypted !== "string" || encrypted.length > 64 * 1024 || !encrypted.includes(".")) {
      fail("proposal_encryption_unavailable", 503);
    }
    const proposalId = token(18);
    if (!validProposalId(proposalId)) fail("proposal_randomness_unavailable", 503);
    const currentNow = now();
    const expiresAt = currentNow + PROPOSAL_TTL_MS;
    const inserted = await db.prepare(
      "INSERT INTO nr_operation_proposals (proposal_id, user_id, session_key_hash, status, tool_name, operation, billing, region, account_id, connection_generation, selection_generation, schema_hash, policy_hash, arguments_hash, encrypted_arguments, effect_summary, approval_nonce_hash, challenge_expires_at, claim_id, created_at, expires_at, approved_at, claimed_at, finished_at, result_code) SELECT ?, ?, ?, 'pending', ?, ?, ?, c.region, p.account_id, c.connection_generation, p.selection_generation, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?, NULL, NULL, NULL, NULL FROM nr_connections c INNER JOIN nr_preferences p ON p.user_id = c.user_id WHERE c.user_id = ? AND c.region = ? AND c.connection_generation = ? AND p.account_id = ? AND p.selection_generation = ?",
    ).bind(proposalId, userId, sessionKeyHash, toolName, policy.operation, policy.billing,
      schemaHash, policyHash, argumentsHash, encrypted, effectSummary, currentNow, expiresAt,
      userId, contextSnapshot.region, contextSnapshot.connectionGeneration, contextSnapshot.accountId,
      contextSnapshot.selectionGeneration).run();
    if (Number(inserted?.meta?.changes || 0) !== 1) fail("proposal_context_changed", 409);
    return { proposalId, status: "pending", effectSummary, expiresAt };
  }

  async function loadProposal(proposalId, userId) {
    if (!validProposalId(proposalId) || !validIdentity(userId)) fail("proposal_not_found", 404);
    return db.prepare(
      "SELECT proposal_id, user_id, session_key_hash, status, tool_name, operation, billing, region, account_id, connection_generation, selection_generation, schema_hash, policy_hash, arguments_hash, encrypted_arguments, effect_summary, approval_nonce_hash, challenge_expires_at, claim_id, created_at, expires_at, approved_at, claimed_at, finished_at, result_code FROM nr_operation_proposals WHERE proposal_id = ? AND user_id = ?",
    ).bind(proposalId, userId).first();
  }

  async function assertProposalStillReviewed(row, context) {
    const policy = getPolicy(row.tool_name);
    if (!sameContext(row, context) || row.operation !== policy.operation || row.billing !== policy.billing) {
      fail("proposal_context_changed", 409);
    }
    if (typeof decryptArguments !== "function") fail("proposal_decryption_unavailable", 503);
    const schemaHash = await hash(canonicalApprovalJson(policy.schema));
    if (schemaHash !== row.schema_hash) fail("proposal_schema_changed", 409);
    let argumentsJson;
    try { argumentsJson = await decryptArguments(row.encrypted_arguments); }
    catch { fail("proposal_arguments_unavailable", 409); }
    if (typeof argumentsJson !== "string" || argumentsJson.length > 32 * 1024) fail("proposal_arguments_unavailable", 409);
    let args;
    try {
      args = JSON.parse(argumentsJson);
      if (canonicalApprovalJson(args) !== argumentsJson) fail("proposal_arguments_changed", 409);
    } catch (error) {
      if (error instanceof OperationApprovalError) throw error;
      fail("proposal_arguments_unavailable", 409);
    }
    if (await hash(argumentsJson) !== row.arguments_hash) fail("proposal_arguments_changed", 409);
    try {
      if (policy.validateArguments(args) !== true) fail("proposal_arguments_rejected", 409);
    } catch (error) {
      if (error instanceof OperationApprovalError) throw error;
      fail("proposal_policy_changed", 409);
    }
    let effectSummary;
    try { effectSummary = policy.effectSummary(args, context); }
    catch { fail("proposal_effect_unavailable", 409); }
    if (typeof effectSummary !== "string" || effectSummary !== row.effect_summary) fail("proposal_effect_changed", 409);
    const policyHash = await reviewPolicyHash(policy, schemaHash, effectSummary);
    if (policyHash !== row.policy_hash) fail("proposal_policy_changed", 409);
    return { policy, schemaHash, policyHash, args, effectSummary };
  }

  async function listPending({ userId, context, now: listTime = now() }) {
    requireEnabled();
    validNow(listTime);
    if (!validIdentity(userId)) fail("approval_identity_unavailable", 401);
    const contextSnapshot = snapshotContext(context);
    const rows = await db.prepare(
      "SELECT proposal_id, user_id, session_key_hash, status, tool_name, operation, billing, region, account_id, connection_generation, selection_generation, schema_hash, policy_hash, arguments_hash, encrypted_arguments, effect_summary, approval_nonce_hash, challenge_expires_at, claim_id, created_at, expires_at, approved_at, claimed_at, finished_at, result_code FROM nr_operation_proposals WHERE user_id = ? AND status = 'pending' AND expires_at > ? ORDER BY created_at ASC LIMIT 20",
    ).bind(userId, listTime).all();
    const items = [];
    for (const row of rows?.results || []) {
      if (!sameContext(row, contextSnapshot)) continue;
      const reviewed = await assertProposalStillReviewed(row, contextSnapshot);
      if (reviewed.policyHash !== row.policy_hash) continue;
      items.push(listPublicProposal(row));
    }
    return { enabled: true, items };
  }

  async function issueChallenge({ userId, sessionKeyHash, proposalId, context }) {
    requireEnabled();
    validNow(now());
    if (!validIdentity(userId) || !HEX_HASH_PATTERN.test(sessionKeyHash || "")) fail("approval_session_required", 401);
    const contextSnapshot = snapshotContext(context);
    await assertActiveSession(sessionKeyHash, userId, now());
    const row = await loadProposal(proposalId, userId);
    if (!row || row.status !== "pending" || Number(row.expires_at) <= now()) fail("proposal_not_pending", 409);
    const reviewed = await assertProposalStillReviewed(row, contextSnapshot);
    const nonce = token(32);
    if (!TOKEN_PATTERN.test(nonce)) fail("proposal_randomness_unavailable", 503);
    const nonceHash = await hash("nr-operation-approval\0" + nonce);
    const challengeExpiresAt = Math.min(now() + CHALLENGE_TTL_MS, Number(row.expires_at));
    const result = await db.prepare(
      "UPDATE nr_operation_proposals SET session_key_hash = ?, approval_nonce_hash = ?, challenge_expires_at = ? WHERE proposal_id = ? AND user_id = ? AND status = 'pending' AND expires_at > ? AND (session_key_hash IS NULL OR session_key_hash = ?) AND (approval_nonce_hash IS NULL OR challenge_expires_at <= ?) AND schema_hash = ? AND policy_hash = ? AND arguments_hash = ? AND encrypted_arguments = ? AND operation = ? AND billing = ? AND EXISTS (SELECT 1 FROM nr_approval_sessions s WHERE s.session_key_hash = ? AND s.user_id = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND s.created_at + ? > ?) AND EXISTS (SELECT 1 FROM nr_connections c INNER JOIN nr_preferences p ON p.user_id = c.user_id WHERE c.user_id = ? AND c.region = ? AND c.connection_generation = ? AND p.account_id = ? AND p.selection_generation = ?)",
    ).bind(sessionKeyHash, nonceHash, challengeExpiresAt, proposalId, userId, now(), sessionKeyHash, now(),
      reviewed.schemaHash, reviewed.policyHash, row.arguments_hash, row.encrypted_arguments,
      reviewed.policy.operation, reviewed.policy.billing, sessionKeyHash, userId, now(), SESSION_TTL_MS,
      now(), userId, contextSnapshot.region, contextSnapshot.connectionGeneration, contextSnapshot.accountId,
      contextSnapshot.selectionGeneration).run();
    if (Number(result?.meta?.changes || 0) !== 1) fail("proposal_challenge_unavailable", 409);
    return { proposalId, approvalNonce: nonce, challengeExpiresAt, effectSummary: reviewed.effectSummary };
  }

  async function approve({ userId, sessionKeyHash, proposalId, approvalNonce, context }) {
    requireEnabled();
    validNow(now());
    if (!validIdentity(userId) || !HEX_HASH_PATTERN.test(sessionKeyHash || "")) fail("approval_session_required", 401);
    const contextSnapshot = snapshotContext(context);
    await assertActiveSession(sessionKeyHash, userId, now());
    if (!TOKEN_PATTERN.test(approvalNonce || "")) fail("approval_nonce_invalid", 403);
    const row = await loadProposal(proposalId, userId);
    if (!row || row.status !== "pending") fail("proposal_not_pending", 409);
    const reviewed = await assertProposalStillReviewed(row, contextSnapshot);
    const nonceHash = await hash("nr-operation-approval\0" + approvalNonce);
    const currentNow = now();
    const result = await db.prepare(
      "UPDATE nr_operation_proposals SET status = 'approved', approved_at = ?, approval_nonce_hash = NULL, challenge_expires_at = NULL WHERE proposal_id = ? AND user_id = ? AND session_key_hash = ? AND status = 'pending' AND expires_at > ? AND challenge_expires_at > ? AND approval_nonce_hash = ? AND account_id = ? AND region = ? AND connection_generation = ? AND selection_generation = ? AND schema_hash = ? AND policy_hash = ? AND arguments_hash = ? AND encrypted_arguments = ? AND operation = ? AND billing = ? AND EXISTS (SELECT 1 FROM nr_approval_sessions s WHERE s.session_key_hash = ? AND s.user_id = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND s.created_at + ? > ?) AND EXISTS (SELECT 1 FROM nr_connections c INNER JOIN nr_preferences p ON p.user_id = c.user_id WHERE c.user_id = ? AND c.region = ? AND c.connection_generation = ? AND p.account_id = ? AND p.selection_generation = ?)",
    ).bind(currentNow, proposalId, userId, sessionKeyHash, currentNow, currentNow, nonceHash,
      contextSnapshot.accountId, contextSnapshot.region, contextSnapshot.connectionGeneration,
      contextSnapshot.selectionGeneration, reviewed.schemaHash, reviewed.policyHash, row.arguments_hash,
      row.encrypted_arguments,
      reviewed.policy.operation, reviewed.policy.billing, sessionKeyHash, userId, currentNow, SESSION_TTL_MS,
      currentNow, userId, contextSnapshot.region, contextSnapshot.connectionGeneration,
      contextSnapshot.accountId, contextSnapshot.selectionGeneration).run();
    if (Number(result?.meta?.changes || 0) !== 1) fail("proposal_stale_or_replayed", 409);
    return { proposalId, status: "approved", approvedAt: currentNow };
  }

  async function cancel({ userId, sessionKeyHash, proposalId, context }) {
    requireEnabled();
    validNow(now());
    if (!validIdentity(userId) || !HEX_HASH_PATTERN.test(sessionKeyHash || "")) fail("approval_session_required", 401);
    const contextSnapshot = snapshotContext(context);
    await assertActiveSession(sessionKeyHash, userId, now());
    const currentNow = now();
    const result = await db.prepare(
      "UPDATE nr_operation_proposals SET status = 'cancelled', approval_nonce_hash = NULL, challenge_expires_at = NULL, encrypted_arguments = '', finished_at = ?, result_code = 'owner_cancelled' WHERE proposal_id = ? AND user_id = ? AND session_key_hash = ? AND status IN ('pending', 'approved') AND account_id = ? AND region = ? AND connection_generation = ? AND selection_generation = ?",
    ).bind(currentNow, proposalId, userId, sessionKeyHash, contextSnapshot.accountId,
      contextSnapshot.region, contextSnapshot.connectionGeneration, contextSnapshot.selectionGeneration).run();
    if (Number(result?.meta?.changes || 0) !== 1) fail("proposal_not_cancellable", 409);
    return { proposalId, status: "cancelled" };
  }

  async function claim({ userId, sessionKeyHash, proposalId, context }) {
    requireEnabled();
    validNow(now());
    if (!validIdentity(userId) || !HEX_HASH_PATTERN.test(sessionKeyHash || "")) fail("approval_session_required", 401);
    const contextSnapshot = snapshotContext(context);
    const row = await loadProposal(proposalId, userId);
    if (!row || row.status !== "approved") fail("proposal_not_claimable", 409);
    const reviewed = await assertProposalStillReviewed(row, contextSnapshot);
    await assertActiveSession(sessionKeyHash, userId, now());
    const currentNow = now();
    const claimId = token(18);
    if (typeof claimId !== "string" || !/^[A-Za-z0-9_-]{24}$/.test(claimId)) fail("proposal_randomness_unavailable", 503);
    const result = await db.prepare(
      "UPDATE nr_operation_proposals SET status = 'claimed', claim_id = ?, claimed_at = ? WHERE proposal_id = ? AND user_id = ? AND session_key_hash = ? AND status = 'approved' AND expires_at > ? AND account_id = ? AND region = ? AND connection_generation = ? AND selection_generation = ? AND schema_hash = ? AND policy_hash = ? AND arguments_hash = ? AND encrypted_arguments = ? AND operation = ? AND billing = ? AND EXISTS (SELECT 1 FROM nr_approval_sessions s WHERE s.session_key_hash = ? AND s.user_id = ? AND s.revoked_at IS NULL AND s.expires_at > ? AND s.created_at + ? > ?) AND EXISTS (SELECT 1 FROM nr_connections c INNER JOIN nr_preferences p ON p.user_id = c.user_id WHERE c.user_id = ? AND c.region = ? AND c.connection_generation = ? AND p.account_id = ? AND p.selection_generation = ?)",
    ).bind(claimId, currentNow, proposalId, userId, sessionKeyHash, currentNow, contextSnapshot.accountId,
      contextSnapshot.region, contextSnapshot.connectionGeneration, contextSnapshot.selectionGeneration,
      reviewed.schemaHash, reviewed.policyHash, row.arguments_hash, row.encrypted_arguments,
      reviewed.policy.operation, reviewed.policy.billing,
      sessionKeyHash, userId, currentNow, SESSION_TTL_MS, currentNow, userId, contextSnapshot.region,
      contextSnapshot.connectionGeneration, contextSnapshot.accountId, contextSnapshot.selectionGeneration).run();
    if (Number(result?.meta?.changes || 0) !== 1) fail("proposal_stale_or_claimed", 409);
    return { proposalId, claimId, toolName: row.tool_name, encryptedArguments: row.encrypted_arguments };
  }

  async function markOutcomeUnknown({ userId, proposalId, claimId, code = "provider_outcome_unknown" }) {
    requireEnabled();
    validNow(now());
    if (!validIdentity(userId)) fail("approval_identity_unavailable", 401);
    if (!validProposalId(proposalId) || !/^[A-Za-z0-9_-]{24}$/.test(claimId || "")) fail("proposal_claim_invalid", 400);
    const currentNow = now();
    const result = await db.prepare(
      "UPDATE nr_operation_proposals SET status = 'outcome_unknown', encrypted_arguments = '', finished_at = ?, result_code = ? WHERE proposal_id = ? AND user_id = ? AND status = 'claimed' AND claim_id = ?",
    ).bind(currentNow, String(code).slice(0, 64), proposalId, userId, claimId).run();
    if (Number(result?.meta?.changes || 0) !== 1) fail("proposal_claim_changed", 409);
    return { proposalId, status: "outcome_unknown", retryAllowed: false };
  }

  return Object.freeze({ ensureSession, requireSession, createProposal, listPending, issueChallenge, approve, cancel, claim, markOutcomeUnknown });
}

export function approvalCookieHeader(token, maxAgeSeconds = SESSION_TTL_MS / 1000) {
  if (!TOKEN_PATTERN.test(token || "") || !Number.isSafeInteger(maxAgeSeconds) || maxAgeSeconds < 1 || maxAgeSeconds > 900) {
    fail("approval_cookie_invalid", 500);
  }
  return "__Host-nr-approval=" + token + "; Max-Age=" + maxAgeSeconds + "; Path=/; Secure; HttpOnly; SameSite=Strict";
}

export const OPERATION_APPROVAL_LIMITS = Object.freeze({ sessionTtlMs: SESSION_TTL_MS, proposalTtlMs: PROPOSAL_TTL_MS, challengeTtlMs: CHALLENGE_TTL_MS });
