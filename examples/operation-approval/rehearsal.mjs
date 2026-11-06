// Synthetic, in-memory rehearsal only. This module is deliberately disconnected
// from the Worker, D1, OAuth credentials, and every New Relic transport.
const encoder = new TextEncoder();
const MAX_DEPTH = 16;
const MAX_NODES = 4096;
const MAX_JSON_BYTES = 32 * 1024;
export const PROPOSAL_TTL_MS = 5 * 60 * 1000;

export const DEMO_TOOL = deepFreeze({
  name: "demo_set_alert_threshold",
  inputSchema: {
    type: "object",
    required: ["accountId", "conditionGuid", "threshold"],
    additionalProperties: false,
    properties: {
      accountId: { type: "string", const: "demo-account-01" },
      conditionGuid: { type: "string", const: "demo-condition-01" },
      threshold: { type: "number", minimum: 0.1, maximum: 10 },
    },
  },
});

export const DEMO_POLICY = deepFreeze({
  policyId: "synthetic-alert-threshold-v1",
  operation: "write",
  billing: "core_compute",
  preview: false,
  effect: "Would change the threshold on one synthetic alert condition.",
});

export class MockApprovalError extends Error {
  constructor(code) {
    super(code);
    this.name = "MockApprovalError";
    this.code = code;
  }
}

function deepFreeze(value) {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function fail(code) {
  throw new MockApprovalError(code);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && [Object.prototype, null].includes(Object.getPrototypeOf(value));
}

function append(value, state) {
  state.bytes += encoder.encode(value).byteLength;
  if (state.bytes > MAX_JSON_BYTES) fail("proposal_too_large");
  return value;
}

/** Strict JSON canonicalizer for the rehearsal; accessors, cycles and non-JSON values fail. */
export function canonicalJson(value) {
  const state = { nodes: 0, bytes: 0, active: new Set() };
  function visit(item, depth) {
    state.nodes += 1;
    if (depth > MAX_DEPTH || state.nodes > MAX_NODES) fail("proposal_too_complex");
    if (item === null) return append("null", state);
    if (typeof item === "string" || typeof item === "boolean") return append(JSON.stringify(item), state);
    if (typeof item === "number") {
      if (!Number.isFinite(item)) fail("invalid_json_number");
      return append(JSON.stringify(item), state);
    }
    if (typeof item !== "object") fail("non_json_value");
    if (state.active.has(item)) fail("cyclic_value");
    state.active.add(item);
    let result;
    if (Array.isArray(item)) {
      if (Object.getPrototypeOf(item) !== Array.prototype || item.length > 100) fail("invalid_json_array");
      const ownKeys = Reflect.ownKeys(item);
      if (ownKeys.length !== item.length + 1 || !ownKeys.includes("length")) fail("invalid_json_array");
      result = append("[", state);
      for (let index = 0; index < item.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
        if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, "value")) fail("invalid_json_array");
        if (index) result += append(",", state);
        result += visit(descriptor.value, depth + 1);
      }
      result += append("]", state);
    } else {
      if (!isRecord(item)) fail("invalid_json_object");
      const keys = Reflect.ownKeys(item);
      if (keys.length > 100 || keys.some(key => typeof key !== "string"
        || ["__proto__", "prototype", "constructor"].includes(key))) fail("invalid_json_object");
      result = append("{", state);
      for (const [index, key] of keys.sort().entries()) {
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) fail("invalid_json_object");
        if (index) result += append(",", state);
        result += append(JSON.stringify(key), state) + append(":", state) + visit(descriptor.value, depth + 1);
      }
      result += append("}", state);
    }
    state.active.delete(item);
    return result;
  }
  return visit(value, 0);
}

async function sha256(value) {
  const bytes = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}

function randomToken(byteLength = 24) {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function constantTimeEqual(left, right) {
  if (typeof left !== "string" || typeof right !== "string" || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function validIdentity(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 128
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validateDemoArguments(args) {
  if (!isRecord(args) || Object.keys(args).length !== 3
    || args.accountId !== "demo-account-01"
    || args.conditionGuid !== "demo-condition-01"
    || typeof args.threshold !== "number" || !Number.isFinite(args.threshold)
    || args.threshold < 0.1 || args.threshold > 10) fail("unreviewed_arguments");
}

async function fingerprints(tool = DEMO_TOOL, policy = DEMO_POLICY) {
  // Snapshot both inputs before the first await so callers cannot change what
  // is fingerprinted while WebCrypto is running.
  const toolJson = canonicalJson(tool);
  const policyJson = canonicalJson(policy);
  const schemaHash = await sha256(toolJson);
  const policyHash = await sha256(canonicalJson({ schemaHash, policy: JSON.parse(policyJson) }));
  return { schemaHash, policyHash };
}

function validateContext(context) {
  if (!isRecord(context) || !validIdentity(context.ownerId) || !validIdentity(context.sessionBinding)
    || !validIdentity(context.accountId) || !["us", "eu", "jp"].includes(context.region)
    || !Number.isSafeInteger(context.connectionGeneration) || context.connectionGeneration < 1) {
    fail("invalid_rehearsal_context");
  }
}

function snapshotContext(context) {
  const snapshot = JSON.parse(canonicalJson(context));
  const keys = Object.keys(snapshot).sort();
  if (keys.join(",") !== "accountId,connectionGeneration,ownerId,region,sessionBinding") fail("invalid_rehearsal_context");
  validateContext(snapshot);
  return Object.freeze(snapshot);
}

function snapshotDemoArguments(args) {
  const json = canonicalJson(args);
  const snapshot = JSON.parse(json);
  validateDemoArguments(snapshot);
  return { json, value: deepFreeze(snapshot) };
}

function assertProposalId(proposalId) {
  if (typeof proposalId !== "string" || !/^[A-Za-z0-9_-]{24}$/.test(proposalId)) fail("invalid_proposal_id");
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

/** An atomic-in-process store for tests and UI rehearsal. It is not durable or production-safe. */
export class MockApprovalStore {
  #rows = new Map();

  async insert(row) {
    if (this.#rows.has(row.proposalId)) return false;
    this.#rows.set(row.proposalId, clone(row));
    return true;
  }

  async read(proposalId) {
    const row = this.#rows.get(proposalId);
    return row ? clone(row) : null;
  }

  async compareAndSwap(proposalId, expectedState, updates) {
    const current = this.#rows.get(proposalId);
    if (!current || current.state !== expectedState) return false;
    this.#rows.set(proposalId, clone({ ...current, ...updates }));
    return true;
  }
}

function assertMockStore(store) {
  if (!(store instanceof MockApprovalStore)) fail("mock_store_required");
}

async function invalidateApprovalWhenDisabled(store, proposalId, context, now) {
  if (typeof proposalId !== "string" || !isRecord(context)) return;
  const row = await store.read(proposalId);
  if (!row || row.ownerId !== context.ownerId || row.sessionBinding !== context.sessionBinding
    || !["pending", "approved"].includes(row.state)) return;
  await store.compareAndSwap(proposalId, row.state, {
    state: "stale", nonceHash: null, invalidatedAt: now,
  });
}

function validNow(now) {
  if (!Number.isSafeInteger(now) || now < 0 || now > Number.MAX_SAFE_INTEGER - PROPOSAL_TTL_MS) fail("invalid_clock");
}

/**
 * Create a synthetic proposal for the standalone demo. The nonce returned here
 * is for the rehearsal's browser-only memory and must never be sent through MCP.
 */
export async function createSyntheticProposal({ store, context, args, enabled = false, now = Date.now() }) {
  assertMockStore(store);
  validNow(now);
  context = snapshotContext(context);
  const argsSnapshot = snapshotDemoArguments(args);
  if (enabled !== true) fail("approval_rehearsal_disabled");
  if (context.accountId !== argsSnapshot.value.accountId) fail("account_mismatch");
  const { schemaHash, policyHash } = await fingerprints();
  const proposalId = randomToken(18);
  const approvalNonce = randomToken(32);
  const summary = `Would set synthetic condition ${argsSnapshot.value.conditionGuid} threshold to ${String(argsSnapshot.value.threshold)}% in ${argsSnapshot.value.accountId} (${context.region}).`;
  const inserted = await store.insert({
    proposalId,
    ownerId: context.ownerId,
    sessionBinding: context.sessionBinding,
    accountId: context.accountId,
    region: context.region,
    connectionGeneration: context.connectionGeneration,
    toolName: DEMO_TOOL.name,
    operation: DEMO_POLICY.operation,
    billing: DEMO_POLICY.billing,
    effect: DEMO_POLICY.effect,
    schemaHash,
    policyHash,
    argumentsHash: await sha256(argsSnapshot.json),
    nonceHash: await sha256(approvalNonce),
    state: "pending",
    createdAt: now,
    expiresAt: now + PROPOSAL_TTL_MS,
    summary,
  });
  if (!inserted) fail("proposal_collision");
  return { proposalId, approvalNonce, summary, expiresAt: now + PROPOSAL_TTL_MS,
    operation: DEMO_POLICY.operation, billing: DEMO_POLICY.billing, preview: DEMO_POLICY.preview };
}

/** Strip the browser-only nonce before any model/tool-facing serialization. */
export function mockToolProposalResponse(proposal) {
  return {
    proposalId: proposal.proposalId,
    summary: proposal.summary,
    expiresAt: proposal.expiresAt,
    approvalRequired: true,
    simulationOnly: true,
  };
}

export async function readSyntheticProposal({ store, proposalId, context }) {
  assertMockStore(store);
  context = snapshotContext(context);
  const row = await store.read(proposalId);
  if (!row || row.ownerId !== context.ownerId || row.sessionBinding !== context.sessionBinding) return null;
  return {
    proposalId: row.proposalId,
    accountId: row.accountId,
    region: row.region,
    toolName: row.toolName,
    operation: row.operation,
    billing: row.billing,
    effect: row.effect,
    summary: row.summary,
    state: row.state,
    expiresAt: row.expiresAt,
  };
}

export async function approveSyntheticProposal({ store, proposalId, context, approvalNonce,
  enabled = false, method, sameOrigin, csrfValid, action, now = Date.now() }) {
  assertMockStore(store);
  validNow(now);
  assertProposalId(proposalId);
  context = snapshotContext(context);
  if (enabled !== true) {
    await invalidateApprovalWhenDisabled(store, proposalId, context, now);
    fail("approval_rehearsal_disabled");
  }
  if (method !== "POST" || sameOrigin !== true || csrfValid !== true || action !== "approve_once") {
    fail("browser_confirmation_required");
  }
  const row = await store.read(proposalId);
  if (!row || row.ownerId !== context.ownerId || row.sessionBinding !== context.sessionBinding) fail("proposal_not_found");
  if (row.state !== "pending") fail("proposal_not_pending");
  if (row.expiresAt <= now) {
    await store.compareAndSwap(proposalId, "pending", { state: "expired", nonceHash: null });
    fail("proposal_expired");
  }
  if (row.accountId !== context.accountId || row.region !== context.region
    || row.connectionGeneration !== context.connectionGeneration) {
    await store.compareAndSwap(proposalId, "pending", { state: "stale", nonceHash: null });
    fail("proposal_context_changed");
  }
  const nonceHash = typeof approvalNonce === "string" && /^[A-Za-z0-9_-]{40,60}$/.test(approvalNonce)
    ? await sha256(approvalNonce) : "";
  if (!constantTimeEqual(nonceHash, row.nonceHash || "")) fail("invalid_or_replayed_nonce");
  const changed = await store.compareAndSwap(proposalId, "pending", {
    state: "approved", nonceHash: null, approvedAt: now,
  });
  if (!changed) fail("proposal_not_pending");
  return { proposalId, state: "approved" };
}

export async function cancelSyntheticProposal({ store, proposalId, context, now = Date.now() }) {
  assertMockStore(store);
  validNow(now);
  assertProposalId(proposalId);
  context = snapshotContext(context);
  const row = await store.read(proposalId);
  if (!row || row.ownerId !== context.ownerId || row.sessionBinding !== context.sessionBinding) fail("proposal_not_found");
  if (!["pending", "approved"].includes(row.state)) fail("proposal_not_cancellable");
  const changed = await store.compareAndSwap(proposalId, row.state, {
    state: "cancelled", nonceHash: null, cancelledAt: now,
  });
  if (!changed) fail("proposal_not_cancellable");
  return { proposalId, state: "cancelled" };
}

export async function claimSyntheticProposal({ store, proposalId, context, args, enabled = false,
  currentTool = DEMO_TOOL, currentPolicy = DEMO_POLICY, now = Date.now() }) {
  assertMockStore(store);
  validNow(now);
  assertProposalId(proposalId);
  context = snapshotContext(context);
  let argumentSnapshot = null;
  let fingerprintPromise = null;
  try {
    argumentSnapshot = snapshotDemoArguments(args);
    fingerprintPromise = fingerprints(currentTool, currentPolicy).then(
      value => ({ value }),
      () => ({ value: null }),
    );
  } catch {
    // Malformed or unreviewed values cannot match an approved proposal.
  }
  if (enabled !== true) {
    await invalidateApprovalWhenDisabled(store, proposalId, context, now);
    fail("approval_rehearsal_disabled");
  }
  const row = await store.read(proposalId);
  if (!row || row.ownerId !== context.ownerId || row.sessionBinding !== context.sessionBinding) fail("proposal_not_found");
  if (row.state !== "approved") fail(row.state === "outcome_unknown" ? "outcome_unknown_no_retry" : "proposal_not_approved");
  if (row.expiresAt <= now) {
    await store.compareAndSwap(proposalId, "approved", { state: "expired" });
    fail("proposal_expired");
  }
  let currentArgumentsHash = "";
  let currentFingerprints = { schemaHash: "", policyHash: "" };
  if (argumentSnapshot && fingerprintPromise) {
    currentArgumentsHash = await sha256(argumentSnapshot.json);
    const resolvedFingerprint = await fingerprintPromise;
    if (resolvedFingerprint.value) currentFingerprints = resolvedFingerprint.value;
  }
  const contextMatches = row.accountId === context.accountId && row.region === context.region
    && row.connectionGeneration === context.connectionGeneration;
  const bindingMatches = row.schemaHash === currentFingerprints.schemaHash
    && row.policyHash === currentFingerprints.policyHash
    && row.argumentsHash === currentArgumentsHash;
  if (!contextMatches || !bindingMatches || row.operation !== "write" || row.billing === "unknown") {
    await store.compareAndSwap(proposalId, "approved", { state: "stale", nonceHash: null });
    fail("proposal_stale");
  }
  const changed = await store.compareAndSwap(proposalId, "approved", { state: "claimed", claimedAt: now });
  if (!changed) fail("proposal_not_claimable");
  // No dispatch function exists in this module. A claim is only a local rehearsal.
  return { proposalId, state: "claimed", dispatch: "disabled", providerContacted: false };
}

export async function markSyntheticOutcomeUnknown({ store, proposalId, context, now = Date.now() }) {
  assertMockStore(store);
  validNow(now);
  assertProposalId(proposalId);
  context = snapshotContext(context);
  const row = await store.read(proposalId);
  if (!row || row.ownerId !== context.ownerId || row.sessionBinding !== context.sessionBinding) fail("proposal_not_found");
  const changed = await store.compareAndSwap(proposalId, "claimed", { state: "outcome_unknown", outcomeUnknownAt: now });
  if (!changed) fail("proposal_not_claimed");
  return { proposalId, state: "outcome_unknown", retryAllowed: false, providerContacted: false };
}
