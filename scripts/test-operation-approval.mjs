import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  DEMO_POLICY,
  DEMO_TOOL,
  MockApprovalStore,
  PROPOSAL_TTL_MS,
  MockApprovalError,
  approveSyntheticProposal,
  cancelSyntheticProposal,
  canonicalJson,
  claimSyntheticProposal,
  createSyntheticProposal,
  markSyntheticOutcomeUnknown,
  mockToolProposalResponse,
  readSyntheticProposal,
} from "../examples/operation-approval/rehearsal.mjs";
import { capabilityCatalog, schemaFingerprint } from "../worker/mcp-policy.js";
import { callNewRelicRawTool } from "../worker/newrelic.js";

const BASE_NOW = 2_000_000_000_000;
const OWNER = Object.freeze({
  ownerId: "synthetic-owner-a",
  sessionBinding: "synthetic-session-a",
  accountId: "demo-account-01",
  region: "us",
  connectionGeneration: 7,
});
const OTHER_OWNER = Object.freeze({
  ownerId: "synthetic-owner-b",
  sessionBinding: "synthetic-session-b",
  accountId: "demo-account-01",
  region: "us",
  connectionGeneration: 7,
});
const ARGS = Object.freeze({
  accountId: "demo-account-01",
  conditionGuid: "demo-condition-01",
  threshold: 0.75,
});

function errorCode(code) {
  return error => error instanceof MockApprovalError && error.code === code;
}

function approveParams(store, proposal, overrides = {}) {
  return {
    store,
    proposalId: proposal.proposalId,
    context: OWNER,
    approvalNonce: proposal.approvalNonce,
    enabled: true,
    method: "POST",
    sameOrigin: true,
    csrfValid: true,
    action: "approve_once",
    now: BASE_NOW + 1,
    ...overrides,
  };
}

async function create(store, context = OWNER, args = ARGS, overrides = {}) {
  return createSyntheticProposal({ store, context, args, enabled: true, now: BASE_NOW, ...overrides });
}

async function approve(store, proposal, overrides = {}) {
  return approveSyntheticProposal(approveParams(store, proposal, overrides));
}

async function claim(store, proposal, context = OWNER, args = ARGS, overrides = {}) {
  return claimSyntheticProposal({ store, proposalId: proposal.proposalId, context, args,
    enabled: true, now: BASE_NOW + 2, ...overrides });
}

const fetchBefore = globalThis.fetch;
let networkCalls = 0;
globalThis.fetch = async () => {
  networkCalls += 1;
  throw new Error("network disabled in approval rehearsal tests");
};

try {
  await assert.rejects(createSyntheticProposal({ store: new MockApprovalStore(), context: OWNER, args: ARGS }),
    errorCode("approval_rehearsal_disabled"));

  const store = new MockApprovalStore();
  const pending = await create(store);
  assert.equal(pending.operation, "write");
  assert.equal(pending.billing, "core_compute");
  assert.equal(pending.preview, false);
  assert.equal(pending.expiresAt, BASE_NOW + PROPOSAL_TTL_MS);
  assert.match(pending.approvalNonce, /^[A-Za-z0-9_-]{40,60}$/);

  const toolSafe = mockToolProposalResponse(pending);
  assert.equal(toolSafe.approvalRequired, true);
  assert.equal(toolSafe.simulationOnly, true);
  assert.equal(Object.hasOwn(toolSafe, "approvalNonce"), false);
  assert.equal(JSON.stringify(toolSafe).includes(pending.approvalNonce), false,
    "the browser-only nonce must not be exposed through model/tool serialization");
  assert.equal(Object.hasOwn(await readSyntheticProposal({ store, proposalId: pending.proposalId, context: OWNER }), "approvalNonce"), false);
  assert.equal(await readSyntheticProposal({ store, proposalId: pending.proposalId, context: OTHER_OWNER }), null,
    "another owner/session cannot inspect the proposal");

  await assert.rejects(approve(store, pending, { context: OTHER_OWNER }), errorCode("proposal_not_found"));
  await assert.rejects(approve(store, pending, { context: { ...OWNER, sessionBinding: "other-session" } }), errorCode("proposal_not_found"));
  await assert.rejects(approve(store, pending, { method: "GET" }), errorCode("browser_confirmation_required"));
  await assert.rejects(approve(store, pending, { sameOrigin: false }), errorCode("browser_confirmation_required"));
  await assert.rejects(approve(store, pending, { csrfValid: false }), errorCode("browser_confirmation_required"));
  await assert.rejects(approve(store, pending, { action: "approve_many" }), errorCode("browser_confirmation_required"));
  await assert.rejects(approve(store, pending, { approvalNonce: "wrong-nonce" }), errorCode("invalid_or_replayed_nonce"));
  assert.equal((await readSyntheticProposal({ store, proposalId: pending.proposalId, context: OWNER })).state, "pending");

  const savedApproval = await approve(store, pending);
  assert.deepEqual(savedApproval, { proposalId: pending.proposalId, state: "approved" });
  await assert.rejects(approve(store, pending), errorCode("proposal_not_pending"),
    "duplicate approval cannot reuse the nonce or transition again");

  const concurrentClaims = await Promise.allSettled([
    claim(store, pending),
    claim(store, pending),
  ]);
  assert.equal(concurrentClaims.filter(result => result.status === "fulfilled").length, 1,
    "atomic compare-and-swap permits only one claim");
  const winningClaim = concurrentClaims.find(result => result.status === "fulfilled").value;
  assert.equal(winningClaim.state, "claimed");
  assert.equal(winningClaim.dispatch, "disabled");
  assert.equal(winningClaim.providerContacted, false);
  await assert.rejects(cancelSyntheticProposal({ store, proposalId: pending.proposalId, context: OWNER, now: BASE_NOW + 3 }),
    errorCode("proposal_not_cancellable"), "a claimed proposal is not rewritable or cancellable");

  const uncertain = await markSyntheticOutcomeUnknown({ store, proposalId: pending.proposalId, context: OWNER, now: BASE_NOW + 4 });
  assert.deepEqual(uncertain, { proposalId: pending.proposalId, state: "outcome_unknown", retryAllowed: false, providerContacted: false });
  await assert.rejects(claim(store, pending), errorCode("outcome_unknown_no_retry"),
    "an uncertain result must not be retried");
  console.log("PASS single-use approval, atomic claim, owner/session binding, and unknown-outcome stop");

  const expiredStore = new MockApprovalStore();
  const expired = await create(expiredStore);
  await assert.rejects(approve(expiredStore, expired, { now: expired.expiresAt }), errorCode("proposal_expired"));
  assert.equal((await readSyntheticProposal({ store: expiredStore, proposalId: expired.proposalId, context: OWNER })).state, "expired");
  const approvedThenExpiredStore = new MockApprovalStore();
  const approvedThenExpired = await create(approvedThenExpiredStore);
  await approve(approvedThenExpiredStore, approvedThenExpired);
  await assert.rejects(claim(approvedThenExpiredStore, approvedThenExpired, OWNER, ARGS, { now: approvedThenExpired.expiresAt }),
    errorCode("proposal_expired"));
  assert.equal((await readSyntheticProposal({ store: approvedThenExpiredStore, proposalId: approvedThenExpired.proposalId, context: OWNER })).state, "expired");
  console.log("PASS proposal expiry is enforced before approval");

  const disabledApprovalStore = new MockApprovalStore();
  const disabledApproval = await create(disabledApprovalStore);
  await assert.rejects(approve(disabledApprovalStore, disabledApproval, { enabled: false }), errorCode("approval_rehearsal_disabled"));
  assert.equal((await readSyntheticProposal({ store: disabledApprovalStore, proposalId: disabledApproval.proposalId, context: OWNER })).state, "stale",
    "turning the explicit rehearsal flag off invalidates a pending proposal");
  const disabledClaimStore = new MockApprovalStore();
  const disabledClaim = await create(disabledClaimStore);
  await approve(disabledClaimStore, disabledClaim);
  await assert.rejects(claim(disabledClaimStore, disabledClaim, OWNER, ARGS, { enabled: false }), errorCode("approval_rehearsal_disabled"));
  assert.equal((await readSyntheticProposal({ store: disabledClaimStore, proposalId: disabledClaim.proposalId, context: OWNER })).state, "stale",
    "turning the explicit rehearsal flag off invalidates an approved proposal");
  console.log("PASS disabling the rehearsal invalidates pending and approved proposals");

  const unhandledRejections = [];
  const captureUnhandled = reason => unhandledRejections.push(reason);
  process.on("unhandledRejection", captureUnhandled);
  const invalidDefinition = { name: "malformed", inputSchema: undefined };
  await assert.rejects(claimSyntheticProposal({ store: disabledApprovalStore,
    proposalId: disabledApproval.proposalId, context: OWNER, args: ARGS, enabled: false,
    currentTool: invalidDefinition, now: BASE_NOW + 2 }), errorCode("approval_rehearsal_disabled"));
  await assert.rejects(claimSyntheticProposal({ store: new MockApprovalStore(),
    proposalId: pending.proposalId, context: OWNER, args: ARGS, enabled: true,
    currentTool: invalidDefinition, now: BASE_NOW + 2 }), errorCode("proposal_not_found"));
  const unapprovedStore = new MockApprovalStore();
  const unapproved = await create(unapprovedStore);
  await assert.rejects(claimSyntheticProposal({ store: unapprovedStore,
    proposalId: unapproved.proposalId, context: OWNER, args: ARGS, enabled: true,
    currentTool: invalidDefinition, now: BASE_NOW + 2 }), errorCode("proposal_not_approved"));
  const malformedApprovedStore = new MockApprovalStore();
  const malformedApproved = await create(malformedApprovedStore);
  await approve(malformedApprovedStore, malformedApproved);
  await assert.rejects(claim(malformedApprovedStore, malformedApproved, OWNER, ARGS, { currentTool: invalidDefinition }),
    errorCode("proposal_stale"));
  await new Promise(resolve => setImmediate(resolve));
  process.off("unhandledRejection", captureUnhandled);
  assert.equal(unhandledRejections.length, 0, "malformed fingerprints are handled even when earlier claim checks reject");
  console.log("PASS malformed fingerprint work cannot create unhandled rejections on early claim failures");

  const cancelledStore = new MockApprovalStore();
  const cancelled = await create(cancelledStore);
  assert.deepEqual(await cancelSyntheticProposal({ store: cancelledStore, proposalId: cancelled.proposalId, context: OWNER, now: BASE_NOW + 1 }),
    { proposalId: cancelled.proposalId, state: "cancelled" });
  await assert.rejects(approve(cancelledStore, cancelled), errorCode("proposal_not_pending"));
  await assert.rejects(cancelSyntheticProposal({ store: cancelledStore, proposalId: cancelled.proposalId, context: OTHER_OWNER, now: BASE_NOW + 2 }),
    errorCode("proposal_not_found"));
  console.log("PASS cancellation and cross-owner mutation are blocked");

  async function assertStale(label, context = OWNER, args = ARGS, overrides = {}) {
    const staleStore = new MockApprovalStore();
    const proposal = await create(staleStore);
    await approve(staleStore, proposal);
    await assert.rejects(claim(staleStore, proposal, context, args, overrides), errorCode("proposal_stale"), label);
    assert.equal((await readSyntheticProposal({ store: staleStore, proposalId: proposal.proposalId, context: OWNER })).state, "stale");
    await assert.rejects(claim(staleStore, proposal, OWNER, ARGS), errorCode("proposal_not_approved"),
      "restoring the old account or connection context cannot resurrect a stale approval");
  }

  await assertStale("changed target/account invalidates approval", { ...OWNER, accountId: "demo-account-02" });
  await assertStale("changed region invalidates approval", { ...OWNER, region: "eu" });
  await assertStale("reconnect generation invalidates approval", { ...OWNER, connectionGeneration: OWNER.connectionGeneration + 1 });
  await assertStale("changed exact arguments invalidate approval", OWNER, { ...ARGS, threshold: 1.25 });
  await assertStale("changed schema fingerprint invalidates approval", OWNER, ARGS, {
    currentTool: { ...DEMO_TOOL, inputSchema: { ...DEMO_TOOL.inputSchema, properties: {
      ...DEMO_TOOL.inputSchema.properties, threshold: { ...DEMO_TOOL.inputSchema.properties.threshold, maximum: 9 },
    } } },
  });
  await assertStale("changed policy/effect/billing invalidates approval", OWNER, ARGS, {
    currentPolicy: { ...DEMO_POLICY, billing: "unknown", effect: "different synthetic effect" },
  });
  const isolationStore = new MockApprovalStore();
  const isolated = await create(isolationStore);
  await approve(isolationStore, isolated);
  await assert.rejects(claim(isolationStore, isolated, OTHER_OWNER), errorCode("proposal_not_found"));
  await assert.rejects(claim(isolationStore, isolated, { ...OWNER, sessionBinding: "different-session" }), errorCode("proposal_not_found"));
  assert.equal((await readSyntheticProposal({ store: isolationStore, proposalId: isolated.proposalId, context: OWNER })).state, "approved",
    "another subject or browser session cannot claim or invalidate it");
  console.log("PASS account, region, generation, argument, schema, and policy drift invalidate approval");

  assert.throws(() => canonicalJson({ value: undefined }), errorCode("non_json_value"));
  assert.equal(canonicalJson({ z: 2, a: [true, null] }), '{"a":[true,null],"z":2}');
  const getter = {};
  Object.defineProperty(getter, "value", { enumerable: true, get() { throw new Error("getter must not execute"); } });
  assert.throws(() => canonicalJson(getter), errorCode("invalid_json_object"));
  let contextGetterRan = false;
  const contextWithGetter = { ...OWNER };
  Object.defineProperty(contextWithGetter, "ownerId", { enumerable: true, get() {
    contextGetterRan = true;
    throw new Error("context getter must not execute");
  } });
  await assert.rejects(create(new MockApprovalStore(), contextWithGetter, ARGS), errorCode("invalid_json_object"));
  assert.equal(contextGetterRan, false, "context accessors are rejected without executing user code");
  const cycle = {}; cycle.self = cycle;
  assert.throws(() => canonicalJson(cycle), errorCode("cyclic_value"));
  assert.throws(() => canonicalJson(JSON.parse('{"__proto__":{"polluted":true}}')), errorCode("invalid_json_object"));
  await assert.rejects(create(store, OWNER, { ...ARGS, conditionGuid: "other-condition" }), errorCode("unreviewed_arguments"));
  console.log("PASS strict JSON and fixed synthetic target/effects validation");

  const snapshotStore = new MockApprovalStore();
  const mutableArgs = { ...ARGS };
  const mutableContext = { ...OWNER };
  const createInFlight = createSyntheticProposal({ store: snapshotStore, context: mutableContext,
    args: mutableArgs, enabled: true, now: BASE_NOW });
  mutableArgs.threshold = 9.25;
  mutableContext.region = "eu";
  mutableContext.connectionGeneration = 99;
  const snapshottedProposal = await createInFlight;
  assert.match(snapshottedProposal.summary, /0\.75% in demo-account-01 \(us\)/,
    "display text and stored binding use pre-await immutable snapshots");
  await approve(snapshotStore, snapshottedProposal);
  assert.equal((await claim(snapshotStore, snapshottedProposal, OWNER, ARGS)).providerContacted, false);
  console.log("PASS caller mutation during proposal hashing cannot change the reviewed target or arguments");

  const schemaHash = await schemaFingerprint(DEMO_TOOL);
  const policies = JSON.stringify({ [DEMO_TOOL.name]: {
    schemaHash,
    operation: "write",
    billing: "core_compute",
    preview: false,
    scope: "identity",
  } });
  const catalog = await capabilityCatalog([DEMO_TOOL], { NEW_RELIC_MCP_POLICIES: policies }, {
    core_compute: true,
    advanced_compute: true,
    preview: true,
  });
  assert.equal(catalog[0].available, false, "all consent switches do not enable writes");
  assert.equal(catalog[0].reason, "operation_approval_not_implemented");
  const flaggedCatalog = await capabilityCatalog([DEMO_TOOL], {
    NEW_RELIC_MCP_POLICIES: policies,
    NEW_RELIC_ENABLE_WRITE_APPROVALS: "true",
    NEW_RELIC_ENABLE_DESTRUCTIVE_APPROVALS: "true",
  }, { core_compute: true, advanced_compute: true, preview: true });
  assert.equal(flaggedCatalog[0].available, false, "unrecognized future flags cannot enable writes");

  await assert.rejects(callNewRelicRawTool({
    endpoint: "https://mcp.newrelic.invalid/mcp/",
    token: "synthetic-only",
    sessionId: "synthetic-session",
    tools: [DEMO_TOOL],
    requestId: 1,
    callCount: 0,
  }, DEMO_TOOL.name, ARGS, { operation: "write", billing: "core_compute", preview: false }),
  error => error?.code === "operation_approval_not_implemented");
  await assert.rejects(callNewRelicRawTool({
    endpoint: "https://mcp.newrelic.invalid/mcp/",
    token: "synthetic-only",
    sessionId: "synthetic-session",
    tools: [DEMO_TOOL],
    requestId: 1,
    callCount: 0,
  }, DEMO_TOOL.name, ARGS, { operation: "unreviewed", billing: "core_compute", preview: false }),
  error => error?.code === "legacy_tool_billing_unverified");
  assert.equal(networkCalls, 0, "write transport rejection happens before fetch");

  const workerSource = await readFile(new URL("../worker/index.js", import.meta.url), "utf8");
  const pageSource = await readFile(new URL("../worker/page.html", import.meta.url), "utf8");
  const demoSource = await readFile(new URL("../examples/operation-approval/demo.mjs", import.meta.url), "utf8");
  const rehearsalSource = await readFile(new URL("../examples/operation-approval/rehearsal.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(workerSource, /\/api\/operation-approval|write_official_mcp|execute_write_operation/);
  assert.match(workerSource, /"operation_approval_not_implemented"/);
  assert.match(pageSource, /書き込み・破壊的操作/);
  assert.match(pageSource, /書き込みの承認にはなりません/);
  assert.doesNotMatch(demoSource + rehearsalSource, /\bfetch\s*\(|XMLHttpRequest|WebSocket|https:\/\/mcp\.newrelic\.com/);
  assert.match(demoSource, /textContent/);
  assert.doesNotMatch(demoSource, /innerHTML/);
  assert.equal(networkCalls, 0);
  console.log("PASS production write gates remain closed and rehearsal performs zero network calls");
} finally {
  if (fetchBefore === undefined) delete globalThis.fetch;
  else globalThis.fetch = fetchBefore;
}

console.log("Synthetic operation-approval rehearsal tests passed; no provider call was made");
