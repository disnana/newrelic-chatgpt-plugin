import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import { webcrypto } from "node:crypto";
import { fileURLToPath, pathToFileURL } from "node:url";
import { resolve } from "node:path";
import {
  cleanupOperationApprovalStore,
  createOperationApprovalService,
  OperationApprovalError,
  OPERATION_APPROVAL_LIMITS,
} from "../worker/operation-approval.js";
import { approvalBrowserBinding, getOperationApprovalContext, saveSelectedAccount } from "../worker/newrelic.js";
import { createSelfHostGateway } from "../examples/self-host-gateway/gateway.mjs";

globalThis.crypto ||= webcrypto;
const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const sqlite = new DatabaseSync(":memory:");
const migrationFiles = [
  "0000_newrelic_mcp.sql", "0001_refresh_locks.sql", "0002_oauth_completion_fence.sql",
  "0003_usage_consents.sql", "0004_operation_approval_store.sql", "0005_approval_retention_indexes.sql",
];
for (const migration of migrationFiles) {
  sqlite.exec(await readFile(resolve(root, "drizzle", migration), "utf8"));
}

class SQLiteD1 {
  constructor(database = sqlite) { this.sqlite = database; this.beforeNextRun = null; }
  prepare(query) {
    const database = this;
    const statement = database.sqlite.prepare(query);
    let values = [];
    return {
      bind(...next) { values = next; return this; },
      async run() {
        const hook = database.beforeNextRun;
        database.beforeNextRun = null;
        if (hook) hook(query, values);
        return { meta: { changes: Number(statement.run(...values).changes) } };
      },
      async first() { return statement.get(...values) || null; },
      async all() { return { results: statement.all(...values) }; },
    };
  }
  async batch(statements) {
    this.sqlite.exec("BEGIN IMMEDIATE");
    try {
      const results = [];
      for (const statement of statements) results.push(await statement.run());
      this.sqlite.exec("COMMIT");
      return results;
    } catch (error) {
      this.sqlite.exec("ROLLBACK");
      throw error;
    }
  }
}

const db = new SQLiteD1();
const userId = "synthetic-owner";
const context = {
  accountId: "synthetic-account",
  region: "us",
  connectionGeneration: "connection-generation-000000000001",
  selectionGeneration: "selection-generation-000000000001",
};
let currentTime = 1_800_000_000_000;
let randomCounter = 0;
const token = (bytes = 32) => {
  randomCounter += 1;
  return Buffer.alloc(bytes, randomCounter).toString("base64url");
};
const reviewedPolicy = Object.freeze({
  enabled: true,
  policyId: "synthetic-write-policy-v1",
  operation: "write",
  billing: "core_compute",
  effectSummaryId: "synthetic-effect-v1",
  schema: {
    type: "object", additionalProperties: false,
    required: ["accountId", "conditionGuid", "threshold"],
    properties: {
      accountId: { type: "string", const: "synthetic-account" },
      conditionGuid: { type: "string", const: "synthetic-condition" },
      threshold: { type: "number", minimum: 0.1, maximum: 10 },
    },
  },
  validateArguments(args) {
    return args.accountId === "synthetic-account" && args.conditionGuid === "synthetic-condition"
      && typeof args.threshold === "number" && args.threshold >= 0.1 && args.threshold <= 10;
  },
  effectSummary(args, snapshot) {
    return `Would set synthetic condition ${args.conditionGuid} to ${args.threshold}% in ${snapshot.accountId} (${snapshot.region}).`;
  },
});

const encryption = async (value) => "synthetic-iv." + Buffer.from(value).toString("base64url");
let beforeDecrypt = null;
const decrypt = async (value) => {
  const plaintext = Buffer.from(value.split(".")[1], "base64url").toString("utf8");
  const hook = beforeDecrypt;
  beforeDecrypt = null;
  if (hook) hook();
  return plaintext;
};
const service = createOperationApprovalService({
  db,
  encryptArguments: encryption,
  decryptArguments: decrypt,
  policies: new Map([["demo_set_alert_threshold", reviewedPolicy]]),
  enabled: true,
  now: () => currentTime,
  token,
});

const createSession = async (request, owner = userId) => service.ensureSession({
  request, userId: owner, authMode: "sites",
});
const sessionRequest = () => new Request("https://monitor.example.test/api/operation-approvals/session", {
  method: "POST", headers: { origin: "https://monitor.example.test", "content-type": "application/json" },
});

// Sites approval sessions are independent, random, owner-bound browser cookies.
const session = await createSession(sessionRequest());
assert.equal(session.created, true);
assert.match(session.cookieToken, /^[A-Za-z0-9_-]{43}$/);
assert.match(session.csrfToken, /^[A-Za-z0-9_-]{43}$/);
assert.equal(session.sessionKeyHash.includes(session.cookieToken), false);
assert.equal(session.sessionKeyHash.length, 64);
const cookie = `__Host-nr-approval=${session.cookieToken}`;
const cookieRequest = () => new Request("https://monitor.example.test/api/operation-approvals/list", {
  method: "POST", headers: { origin: "https://monitor.example.test", cookie, "content-type": "application/json" },
});
const browserSession = await service.requireSession({
  request: cookieRequest(), userId, authMode: "sites", csrfToken: session.csrfToken,
});
assert.equal(browserSession.sessionKeyHash, session.sessionKeyHash);
assert.equal((await service.listPending({ userId, context })).items.length, 0);
await assert.rejects(() => service.requireSession({
  request: cookieRequest(), userId: "different-owner", authMode: "sites", csrfToken: session.csrfToken,
}), error => error instanceof OperationApprovalError && error.code === "approval_session_required");

// The durable proposal insert snapshots only a currently connected, selected account.
sqlite.prepare("INSERT INTO nr_connections (user_id, encrypted_access_token, encrypted_refresh_token, access_expires_at, connected_at, region, connection_generation) VALUES (?, ?, ?, ?, ?, ?, ?)")
  .run(userId, "ciphertext-a", "ciphertext-r", currentTime + 3600_000, currentTime, "us", context.connectionGeneration);
sqlite.prepare("INSERT INTO nr_preferences (user_id, account_id, account_name, updated_at, selection_generation) VALUES (?, ?, ?, ?, ?)")
  .run(userId, context.accountId, "synthetic", currentTime, context.selectionGeneration);
await assert.rejects(() => service.requireSession({
  request: cookieRequest(), userId, authMode: "sites", csrfToken: token(),
}), error => error instanceof OperationApprovalError && error.code === "approval_csrf_invalid");
await assert.rejects(() => service.requireSession({
  request: cookieRequest(), userId, authMode: "sites",
}), error => error instanceof OperationApprovalError && error.code === "approval_csrf_invalid");
await assert.rejects(() => service.requireSession({
  request: new Request("https://monitor.example.test/api/operation-approvals/list", {
    method: "POST", headers: { origin: "https://monitor.example.test", "content-type": "application/json", cookie: cookie + "; __Host-nr-approval=" + session.cookieToken },
  }), userId, authMode: "sites", csrfToken: session.csrfToken,
}), error => error instanceof OperationApprovalError && error.code === "approval_session_required");

// Rotating the connection or account generation invalidates pending proposals.
const syntheticArgs = { accountId: context.accountId, conditionGuid: "synthetic-condition", threshold: 2.5 };
const created = await service.createProposal({
  userId, toolName: "demo_set_alert_threshold", args: syntheticArgs,
  context, billing: "core_compute",
});
assert.equal(created.status, "pending");
assert.match(created.effectSummary, /synthetic-condition/);
assert.equal(JSON.stringify(created).includes(JSON.stringify(syntheticArgs)), false, "MCP-safe proposal response excludes raw arguments");
assert.equal((await service.listPending({ userId, context })).items[0].proposalId, created.proposalId);
await assert.rejects(() => service.issueChallenge({
  userId, sessionKeyHash: browserSession.sessionKeyHash, proposalId: created.proposalId,
  context: { ...context, selectionGeneration: "selection-generation-000000000002" },
}), error => error instanceof OperationApprovalError && error.code === "proposal_context_changed");

// The UI lists proposals before binding them to a browser. Cancellation must
// bind this first browser atomically, while a different browser cannot cancel
// a proposal after challenge issuance.
const unboundCancelProposal = await service.createProposal({
  userId, toolName: "demo_set_alert_threshold", args: syntheticArgs, context, billing: "core_compute",
});
assert.equal((await db.prepare("SELECT session_key_hash FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(unboundCancelProposal.proposalId).first()).session_key_hash, null);
assert.deepEqual(await service.cancel({ userId, sessionKeyHash: browserSession.sessionKeyHash,
  proposalId: unboundCancelProposal.proposalId, context }),
{ proposalId: unboundCancelProposal.proposalId, status: "cancelled" });
const cancelledUnboundRow = await db.prepare("SELECT status, session_key_hash, encrypted_arguments FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(unboundCancelProposal.proposalId).first();
assert.equal(cancelledUnboundRow.status, "cancelled");
assert.equal(cancelledUnboundRow.session_key_hash, browserSession.sessionKeyHash);
assert.equal(cancelledUnboundRow.encrypted_arguments, "", "cancel clears encrypted arguments immediately");

const sessionBoundCancelProposal = await service.createProposal({
  userId, toolName: "demo_set_alert_threshold", args: syntheticArgs, context, billing: "core_compute",
});
const boundChallenge = await service.issueChallenge({ userId, sessionKeyHash: browserSession.sessionKeyHash,
  proposalId: sessionBoundCancelProposal.proposalId, context });
const otherBrowserSession = await createSession(sessionRequest());
await assert.rejects(() => service.cancel({ userId, sessionKeyHash: otherBrowserSession.sessionKeyHash,
  proposalId: sessionBoundCancelProposal.proposalId, context }),
error => error instanceof OperationApprovalError && error.code === "proposal_not_cancellable");
assert.deepEqual(await service.cancel({ userId, sessionKeyHash: browserSession.sessionKeyHash,
  proposalId: sessionBoundCancelProposal.proposalId, context }),
{ proposalId: sessionBoundCancelProposal.proposalId, status: "cancelled" });
await assert.rejects(() => service.approve({ userId, sessionKeyHash: browserSession.sessionKeyHash,
  proposalId: sessionBoundCancelProposal.proposalId, approvalNonce: boundChallenge.approvalNonce, context }),
error => error instanceof OperationApprovalError && error.code === "proposal_not_pending");

const revokeDuringCancelSession = await createSession(sessionRequest());
const cancelRaceProposal = await service.createProposal({
  userId, toolName: "demo_set_alert_threshold", args: syntheticArgs, context, billing: "core_compute",
});
db.beforeNextRun = query => {
  assert.match(query, /SET session_key_hash = \?, status = 'cancelled'/);
  sqlite.prepare("UPDATE nr_approval_sessions SET revoked_at = ? WHERE session_key_hash = ?")
    .run(currentTime, revokeDuringCancelSession.sessionKeyHash);
};
await assert.rejects(() => service.cancel({ userId, sessionKeyHash: revokeDuringCancelSession.sessionKeyHash,
  proposalId: cancelRaceProposal.proposalId, context }),
error => error instanceof OperationApprovalError && error.code === "proposal_not_cancellable");
assert.equal((await db.prepare("SELECT status FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(cancelRaceProposal.proposalId).first()).status, "pending",
"session revocation racing cancellation prevents the state change");

const challenge = await service.issueChallenge({
  userId, sessionKeyHash: browserSession.sessionKeyHash, proposalId: created.proposalId, context,
});
assert.match(challenge.approvalNonce, /^[A-Za-z0-9_-]{43}$/);
const storedAfterChallenge = await db.prepare(
  "SELECT approval_nonce_hash FROM nr_operation_proposals WHERE proposal_id = ?",
).bind(created.proposalId).first();
assert.equal(storedAfterChallenge.approval_nonce_hash.includes(challenge.approvalNonce), false, "D1 stores only a nonce hash");

// Conditional SQL turns approval into a one-time transition. Parallel replays cannot win twice.
const approvalAttempts = await Promise.allSettled([
  service.approve({ userId, sessionKeyHash: browserSession.sessionKeyHash, proposalId: created.proposalId, approvalNonce: challenge.approvalNonce, context }),
  service.approve({ userId, sessionKeyHash: browserSession.sessionKeyHash, proposalId: created.proposalId, approvalNonce: challenge.approvalNonce, context }),
]);
assert.equal(approvalAttempts.filter(item => item.status === "fulfilled").length, 1);
assert.equal(approvalAttempts.filter(item => item.status === "rejected").length, 1);
const approvedRow = await db.prepare("SELECT status, approval_nonce_hash FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(created.proposalId).first();
assert.equal(approvedRow.status, "approved");
assert.equal(approvedRow.approval_nonce_hash, null, "approval atomically consumes the nonce");
const claim = await service.claim({ userId, sessionKeyHash: browserSession.sessionKeyHash, proposalId: created.proposalId, context });
assert.equal(claim.toolName, "demo_set_alert_threshold");
assert.deepEqual(JSON.parse(await decrypt(claim.encryptedArguments)), syntheticArgs);
await assert.rejects(() => service.claim({ userId, sessionKeyHash: browserSession.sessionKeyHash, proposalId: created.proposalId, context }),
  error => error instanceof OperationApprovalError && error.code === "proposal_not_claimable");
const uncertain = await service.markOutcomeUnknown({ userId, proposalId: created.proposalId, claimId: claim.claimId });
assert.deepEqual(uncertain, { proposalId: created.proposalId, status: "outcome_unknown", retryAllowed: false });
await assert.rejects(() => service.markOutcomeUnknown({ userId, proposalId: created.proposalId, claimId: claim.claimId }),
  error => error instanceof OperationApprovalError && error.code === "proposal_claim_changed");
const uncertainRow = await db.prepare("SELECT status, encrypted_arguments FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(created.proposalId).first();
assert.equal(uncertainRow.status, "outcome_unknown");
assert.equal(uncertainRow.encrypted_arguments, "", "uncertain outcomes cannot be retried from the stored proposal");

// Default production policy registry is empty, even when the feature flag is explicitly enabled.
const noReviewedPolicies = createOperationApprovalService({ db, enabled: true, now: () => currentTime });
await assert.rejects(() => noReviewedPolicies.createProposal({
  userId, toolName: "demo_set_alert_threshold", args: syntheticArgs, context, billing: "core_compute",
}), error => error instanceof OperationApprovalError && error.code === "operation_policy_unavailable");
const disabledService = createOperationApprovalService({ db, enabled: false, now: () => currentTime });
await assert.rejects(() => disabledService.ensureSession({ request: sessionRequest(), userId, authMode: "sites" }),
  error => error instanceof OperationApprovalError && error.code === "operation_approval_disabled");

// Site UI identity and account/connection generations are read locally only.
assert.deepEqual(await getOperationApprovalContext({ DB: db }, userId), context);
await saveSelectedAccount({ DB: db }, userId, { id: context.accountId, name: "renamed" });
assert.equal((await getOperationApprovalContext({ DB: db }, userId)).selectionGeneration, context.selectionGeneration,
  "renaming the same selected account does not invalidate a proposal");
await saveSelectedAccount({ DB: db }, userId, { id: "different-account", name: "other" });
assert.notEqual((await getOperationApprovalContext({ DB: db }, userId)).selectionGeneration, context.selectionGeneration,
  "changing the selected account rotates its generation");

function setLiveContext(nextContext) {
  sqlite.prepare("INSERT INTO nr_connections (user_id, encrypted_access_token, encrypted_refresh_token, access_expires_at, connected_at, region, connection_generation) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET access_expires_at = excluded.access_expires_at, connected_at = excluded.connected_at, region = excluded.region, connection_generation = excluded.connection_generation")
    .run(userId, "synthetic-access", "synthetic-refresh", currentTime + 3600_000, currentTime,
      nextContext.region, nextContext.connectionGeneration);
  sqlite.prepare("UPDATE nr_preferences SET account_id = ?, selection_generation = ?, updated_at = ? WHERE user_id = ?")
    .run(nextContext.accountId, nextContext.selectionGeneration, currentTime, userId);
}

async function prepareApprovedProposal(nextContext) {
  setLiveContext(nextContext);
  const browser = await createSession(sessionRequest());
  const proposal = await service.createProposal({
    userId, toolName: "demo_set_alert_threshold", args: syntheticArgs,
    context: nextContext, billing: "core_compute",
  });
  const challenge = await service.issueChallenge({
    userId, sessionKeyHash: browser.sessionKeyHash, proposalId: proposal.proposalId, context: nextContext,
  });
  await service.approve({
    userId, sessionKeyHash: browser.sessionKeyHash, proposalId: proposal.proposalId,
    approvalNonce: challenge.approvalNonce, context: nextContext,
  });
  return { browser, proposal };
}

const context2 = {
  ...context,
  connectionGeneration: "connection-generation-000000000002",
  selectionGeneration: "selection-generation-000000000002",
};
setLiveContext(context2);
const approvalRaceSession = await createSession(sessionRequest());
const approvalRaceProposal = await service.createProposal({
  userId, toolName: "demo_set_alert_threshold", args: syntheticArgs, context: context2, billing: "core_compute",
});
const approvalRaceChallenge = await service.issueChallenge({
  userId, sessionKeyHash: approvalRaceSession.sessionKeyHash, proposalId: approvalRaceProposal.proposalId, context: context2,
});
db.beforeNextRun = query => {
  assert.match(query, /SET status = 'approved'/);
  sqlite.prepare("UPDATE nr_preferences SET account_id = ?, selection_generation = ? WHERE user_id = ?")
    .run("switched-account", "selection-generation-000000000099", userId);
};
await assert.rejects(() => service.approve({
  userId, sessionKeyHash: approvalRaceSession.sessionKeyHash, proposalId: approvalRaceProposal.proposalId,
  approvalNonce: approvalRaceChallenge.approvalNonce, context: context2,
}), error => error instanceof OperationApprovalError && error.code === "proposal_stale_or_replayed");
assert.equal((await db.prepare("SELECT status FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(approvalRaceProposal.proposalId).first()).status, "pending",
"live account drift immediately before approval cannot win the CAS");

const context3 = {
  ...context,
  connectionGeneration: "connection-generation-000000000003",
  selectionGeneration: "selection-generation-000000000003",
};
const disconnectRace = await prepareApprovedProposal(context3);
db.beforeNextRun = query => {
  assert.match(query, /SET status = 'claimed'/);
  sqlite.prepare("DELETE FROM nr_connections WHERE user_id = ?").run(userId);
};
await assert.rejects(() => service.claim({
  userId, sessionKeyHash: disconnectRace.browser.sessionKeyHash,
  proposalId: disconnectRace.proposal.proposalId, context: context3,
}), error => error instanceof OperationApprovalError && error.code === "proposal_stale_or_claimed");
assert.equal((await db.prepare("SELECT status FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(disconnectRace.proposal.proposalId).first()).status, "approved",
"disconnect immediately before claim cannot win the claim CAS");

const context4 = {
  ...context,
  connectionGeneration: "connection-generation-000000000004",
  selectionGeneration: "selection-generation-000000000004",
};
const revokeRace = await prepareApprovedProposal(context4);
db.beforeNextRun = query => {
  assert.match(query, /SET status = 'claimed'/);
  sqlite.prepare("UPDATE nr_approval_sessions SET revoked_at = ? WHERE session_key_hash = ?")
    .run(currentTime, revokeRace.browser.sessionKeyHash);
};
await assert.rejects(() => service.claim({
  userId, sessionKeyHash: revokeRace.browser.sessionKeyHash,
  proposalId: revokeRace.proposal.proposalId, context: context4,
}), error => error instanceof OperationApprovalError && error.code === "proposal_stale_or_claimed");
assert.equal((await db.prepare("SELECT status FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(revokeRace.proposal.proposalId).first()).status, "approved",
"session revocation immediately before claim cannot win the claim CAS");

const context5 = {
  ...context,
  connectionGeneration: "connection-generation-000000000005",
  selectionGeneration: "selection-generation-000000000005",
};
const ciphertextRace = await prepareApprovedProposal(context5);
db.beforeNextRun = query => {
  assert.match(query, /SET status = 'claimed'/);
  sqlite.prepare("UPDATE nr_operation_proposals SET encrypted_arguments = ? WHERE proposal_id = ?")
    .run("synthetic-iv.substituted", ciphertextRace.proposal.proposalId);
};
await assert.rejects(() => service.claim({
  userId, sessionKeyHash: ciphertextRace.browser.sessionKeyHash,
  proposalId: ciphertextRace.proposal.proposalId, context: context5,
}), error => error instanceof OperationApprovalError && error.code === "proposal_stale_or_claimed");
assert.equal((await db.prepare("SELECT status FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(ciphertextRace.proposal.proposalId).first()).status, "approved",
"ciphertext substitution between verification and claim is rejected by the atomic CAS");

const context6 = {
  ...context,
  connectionGeneration: "connection-generation-000000000006",
  selectionGeneration: "selection-generation-000000000006",
};
const tamperedArguments = await prepareApprovedProposal(context6);
sqlite.prepare("UPDATE nr_operation_proposals SET encrypted_arguments = ? WHERE proposal_id = ?")
  .run(await encryption(JSON.stringify({ ...syntheticArgs, threshold: 9 })), tamperedArguments.proposal.proposalId);
await assert.rejects(() => service.claim({
  userId, sessionKeyHash: tamperedArguments.browser.sessionKeyHash,
  proposalId: tamperedArguments.proposal.proposalId, context: context6,
}), error => error instanceof OperationApprovalError && error.code === "proposal_arguments_changed");
assert.equal((await db.prepare("SELECT status FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(tamperedArguments.proposal.proposalId).first()).status, "approved",
"decryptable substituted arguments fail the stored content hash");

const context7 = {
  ...context,
  connectionGeneration: "connection-generation-000000000007",
  selectionGeneration: "selection-generation-000000000007",
};
const expiryRace = await prepareApprovedProposal(context7);
const expiryRow = await db.prepare("SELECT expires_at FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(expiryRace.proposal.proposalId).first();
beforeDecrypt = () => { currentTime = Number(expiryRow.expires_at); };
await assert.rejects(() => service.claim({
  userId, sessionKeyHash: expiryRace.browser.sessionKeyHash,
  proposalId: expiryRace.proposal.proposalId, context: context7,
}), error => error instanceof OperationApprovalError && error.code === "proposal_stale_or_claimed");
assert.equal((await db.prepare("SELECT status FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(expiryRace.proposal.proposalId).first()).status, "approved",
"expiry crossed during argument verification is checked at the final claim CAS");
console.log("PASS live account/session/connection/ciphertext checks are repeated atomically at approval and claim");

// Worker endpoints are browser-only, same-origin, D1-backed, and have no proposal-creation or dispatch route.
const workerPath = resolve(root, "dist/server/index.js");
const worker = (await import(pathToFileURL(workerPath).href + "?approval-store-test=" + Date.now())).default;
const encryptionKey = Buffer.alloc(32, 9).toString("base64url");
const workerEnv = { DB: db, NEW_RELIC_TOKEN_ENCRYPTION_KEY: encryptionKey, NEW_RELIC_OPERATION_APPROVALS_ENABLED: "true" };
const siteHeaders = {
  origin: "https://monitor.example.test",
  "content-type": "application/json",
  "oai-authenticated-user-id": "synthetic-site-identity",
};
const sessionResponse = await worker.fetch(new Request("https://monitor.example.test/api/operation-approvals/session", {
  method: "POST", headers: siteHeaders, body: "{}",
}), workerEnv);
assert.equal(sessionResponse.status, 200);
assert.match(sessionResponse.headers.get("set-cookie") || "", /^__Host-nr-approval=[A-Za-z0-9_-]{43};.*Secure; HttpOnly; SameSite=Strict$/);
const workerSession = await sessionResponse.json();
assert.match(workerSession.csrfToken, /^[A-Za-z0-9_-]{43}$/);
const workerCookie = sessionResponse.headers.get("set-cookie").split(";", 1)[0];
const workerListResponse = await worker.fetch(new Request("https://monitor.example.test/api/operation-approvals/list", {
  method: "POST",
  headers: { ...siteHeaders, cookie: workerCookie, "x-approval-csrf": workerSession.csrfToken },
  body: "{}",
}), workerEnv);
assert.equal(workerListResponse.status, 200);
assert.deepEqual(await workerListResponse.json(), { enabled: true, items: [] });
const workerMissingCsrf = await worker.fetch(new Request("https://monitor.example.test/api/operation-approvals/list", {
  method: "POST", headers: { ...siteHeaders, cookie: workerCookie }, body: "{}",
}), workerEnv);
assert.equal(workerMissingCsrf.status, 403, "all approval POSTs require the per-session CSRF token");
const noProposalRoute = await worker.fetch(new Request("https://monitor.example.test/api/operation-approvals/propose", {
  method: "POST", headers: siteHeaders, body: "{}",
}), workerEnv);
assert.equal(noProposalRoute.status, 404);
const noApprovalFlag = await worker.fetch(new Request("https://monitor.example.test/api/operation-approvals/session", {
  method: "POST", headers: siteHeaders, body: "{}",
}), { DB: db, NEW_RELIC_TOKEN_ENCRYPTION_KEY: encryptionKey });
assert.equal(noApprovalFlag.status, 404, "approval APIs are disabled unless explicitly enabled");
const badOrigin = await worker.fetch(new Request("https://monitor.example.test/api/operation-approvals/session", {
  method: "POST", headers: { ...siteHeaders, origin: "https://attacker.example" }, body: "{}",
}), workerEnv);
assert.equal(badOrigin.status, 403);

// Signed-proxy sessions require a browser-channel assertion with stable sid; MCP tokens cannot bootstrap.
const gatewayKeys = await crypto.subtle.generateKey({
  name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256",
}, true, ["sign", "verify"]);
const publicKey = Buffer.from(await crypto.subtle.exportKey("spki", gatewayKeys.publicKey)).toString("base64url");
const issuer = "https://auth.example.test/";
const audience = "newrelic-chatgpt-mcp";
const allowedSubject = "gateway-owner";
const externalOrigin = "https://gateway.example.test";
const signedEnv = {
  ...workerEnv,
  NEW_RELIC_AUTH_MODE: "signed_proxy",
  NEW_RELIC_AUTH_JWT_PUBLIC_KEY: publicKey,
  NEW_RELIC_AUTH_JWT_KID: "test-key",
  NEW_RELIC_AUTH_ISSUER: issuer,
  NEW_RELIC_AUTH_AUDIENCE: audience,
  NEW_RELIC_AUTH_ALLOWED_ORIGIN: externalOrigin,
  NEW_RELIC_AUTH_ALLOWED_SUBJECTS: JSON.stringify([allowedSubject]),
};
const signingKey = gatewayKeys.privateKey;
const browserSessionId = "gateway-stable-browser-session-identifier-0123456789";
let upstreamFetchCalls = 0;
globalThis.fetch = async () => { upstreamFetchCalls += 1; throw new Error("Provider network is disabled in this test."); };
const gateway = createSelfHostGateway({
  externalOrigin, issuer, audience, keyId: "test-key", allowedSubjects: [allowedSubject], signingKey,
  authenticateBrowser: async () => ({ subject: allowedSubject, sessionId: browserSessionId }),
  authenticateMcp: async () => ({ subject: allowedSubject }),
  verifyBrowserCsrf: async () => true,
  backend: { fetch: request => worker.fetch(request, signedEnv) },
});
const gatewaySession = await gateway.fetch(new Request(externalOrigin + "/api/operation-approvals/session", {
  method: "POST", headers: { origin: externalOrigin, "sec-fetch-site": "same-origin", "content-type": "application/json" }, body: "{}",
}));
assert.equal(gatewaySession.status, 200);
const gatewayCsrf = (await gatewaySession.json()).csrfToken;
const gatewayList = await gateway.fetch(new Request(externalOrigin + "/api/operation-approvals/list", {
  method: "POST", headers: { origin: externalOrigin, "sec-fetch-site": "same-origin", "content-type": "application/json", "x-approval-csrf": gatewayCsrf }, body: "{}",
}));
assert.equal(gatewayList.status, 200);
assert.deepEqual(await gatewayList.json(), { enabled: true, items: [] });
const mcpAssertionBinding = await approvalBrowserBinding(new Request(externalOrigin + "/api/operation-approvals/session", {
  headers: { authorization: "Bearer " + (await (async () => {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const encode = value => Buffer.from(JSON.stringify(value)).toString("base64url");
    const head = encode({ alg: "RS256", typ: "JWT", kid: "test-key" });
    const payload = encode({ iss: issuer, aud: audience, sub: allowedSubject, channel: "mcp", iat: nowSeconds, exp: nowSeconds + 60 });
    const input = head + "." + payload;
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signingKey, new TextEncoder().encode(input));
    return input + "." + Buffer.from(signature).toString("base64url");
  })()) },
}), signedEnv);
assert.equal(mcpAssertionBinding, null);
assert.equal(upstreamFetchCalls, 0, "approval session and state tests never call New Relic");

// The optional cleanup handler is inert by default and applies a bounded, idempotent retention policy.
const cleanupSqlite = new DatabaseSync(":memory:");
for (const migration of migrationFiles) cleanupSqlite.exec(await readFile(resolve(root, "drizzle", migration), "utf8"));
const cleanupDb = new SQLiteD1(cleanupSqlite);
const cleanupNow = Date.now();
const cleanupContext = {
  accountId: "synthetic-account", region: "us",
  connectionGeneration: "cleanup-connection-generation",
  selectionGeneration: "cleanup-selection-generation",
};
function insertCleanupSession(sessionHash, { createdAt, expiresAt, revokedAt = null }) {
  cleanupSqlite.prepare("INSERT INTO nr_approval_sessions (session_key_hash, user_id, auth_mode, browser_binding_hash, csrf_hash, created_at, expires_at, revoked_at) VALUES (?, ?, 'sites', ?, ?, ?, ?, ?)")
    .run(sessionHash, "cleanup-owner", "b".repeat(64), "c".repeat(64), createdAt, expiresAt, revokedAt);
}
function insertCleanupProposal({ id = token(18), status, expiresAt, createdAt = cleanupNow - 3600_000,
  claimedAt = null, finishedAt = null, encryptedArguments = "synthetic-iv.ciphertext", resultCode = null }) {
  cleanupSqlite.prepare("INSERT INTO nr_operation_proposals (proposal_id, user_id, session_key_hash, status, tool_name, operation, billing, region, account_id, connection_generation, selection_generation, schema_hash, policy_hash, arguments_hash, encrypted_arguments, effect_summary, approval_nonce_hash, challenge_expires_at, claim_id, created_at, expires_at, approved_at, claimed_at, finished_at, result_code) VALUES (?, ?, NULL, ?, 'synthetic_cleanup_tool', 'write', 'core_compute', ?, ?, ?, ?, ?, ?, ?, ?, 'synthetic retention fixture', NULL, NULL, ?, ?, ?, NULL, ?, ?, ?)")
    .run(id, "cleanup-owner", status, cleanupContext.region, cleanupContext.accountId,
      cleanupContext.connectionGeneration, cleanupContext.selectionGeneration,
      "a".repeat(64), "d".repeat(64), "e".repeat(64), encryptedArguments,
      status === "claimed" ? "claim-" + id.slice(0, 18) : null,
      createdAt, expiresAt, claimedAt, finishedAt, resultCode);
  return id;
}
const oldSessionHash = "1".repeat(64);
const oldRevokedSessionHash = "2".repeat(64);
const recentSessionHash = "3".repeat(64);
insertCleanupSession(oldSessionHash, {
  createdAt: cleanupNow - OPERATION_APPROVAL_LIMITS.sessionTtlMs - OPERATION_APPROVAL_LIMITS.sessionRetentionMs - 1000,
  expiresAt: cleanupNow - OPERATION_APPROVAL_LIMITS.sessionRetentionMs - 1000,
});
insertCleanupSession(oldRevokedSessionHash, {
  createdAt: cleanupNow - 2 * OPERATION_APPROVAL_LIMITS.sessionTtlMs,
  expiresAt: cleanupNow + OPERATION_APPROVAL_LIMITS.sessionTtlMs,
  revokedAt: cleanupNow - OPERATION_APPROVAL_LIMITS.sessionRetentionMs - 1000,
});
insertCleanupSession(recentSessionHash, {
  createdAt: cleanupNow - OPERATION_APPROVAL_LIMITS.sessionTtlMs - OPERATION_APPROVAL_LIMITS.sessionRetentionMs + 1000,
  expiresAt: cleanupNow - OPERATION_APPROVAL_LIMITS.sessionRetentionMs + 1000,
});
const expiredPendingId = insertCleanupProposal({ status: "pending", expiresAt: cleanupNow - 1000 });
const expiredApprovedId = insertCleanupProposal({ status: "approved", expiresAt: cleanupNow - 2000 });
const staleClaimId = insertCleanupProposal({ status: "claimed", expiresAt: cleanupNow - 3000,
  claimedAt: cleanupNow - OPERATION_APPROVAL_LIMITS.claimRecoveryGraceMs - 1000 });
const recentClaimId = insertCleanupProposal({ status: "claimed", expiresAt: cleanupNow - 4000,
  claimedAt: cleanupNow - OPERATION_APPROVAL_LIMITS.claimRecoveryGraceMs + 1000 });
const oldCancelledId = insertCleanupProposal({ status: "cancelled",
  expiresAt: cleanupNow - OPERATION_APPROVAL_LIMITS.proposalRetentionMs - 2000,
  finishedAt: cleanupNow - OPERATION_APPROVAL_LIMITS.proposalRetentionMs - 1000,
  encryptedArguments: "" });
const recentUnknownId = insertCleanupProposal({ status: "outcome_unknown", expiresAt: cleanupNow - 10_000,
  finishedAt: cleanupNow - 24 * 60 * 60 * 1000, encryptedArguments: "", resultCode: "provider_outcome_unknown" });
await worker.scheduled({}, { DB: cleanupDb, NEW_RELIC_OPERATION_APPROVAL_CLEANUP_ENABLED: "false" }, {
  waitUntil() { throw new Error("disabled cleanup must not schedule work"); },
});
assert.equal((await cleanupDb.prepare("SELECT status FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(expiredPendingId).first()).status, "pending", "cleanup remains inert unless explicitly enabled");
let scheduledCleanup;
await worker.scheduled({}, { DB: cleanupDb, NEW_RELIC_OPERATION_APPROVAL_CLEANUP_ENABLED: "true" }, {
  waitUntil(promise) { scheduledCleanup = promise; },
});
assert.ok(scheduledCleanup, "enabled scheduled cleanup is dispatched through waitUntil");
await scheduledCleanup;
const expiredPendingRow = await cleanupDb.prepare("SELECT status, encrypted_arguments, approval_nonce_hash FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(expiredPendingId).first();
assert.equal(expiredPendingRow.status, "stale");
assert.equal(expiredPendingRow.encrypted_arguments, "");
assert.equal(expiredPendingRow.approval_nonce_hash, null);
assert.equal((await cleanupDb.prepare("SELECT status, encrypted_arguments FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(expiredApprovedId).first()).status, "stale");
const staleClaimRow = await cleanupDb.prepare("SELECT status, encrypted_arguments, result_code FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(staleClaimId).first();
assert.equal(staleClaimRow.status, "outcome_unknown");
assert.equal(staleClaimRow.encrypted_arguments, "");
assert.equal(staleClaimRow.result_code, "claim_stale_no_retry");
assert.equal((await cleanupDb.prepare("SELECT status FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(recentClaimId).first()).status, "claimed", "active claim remains untouched inside its recovery grace");
assert.equal(await cleanupDb.prepare("SELECT proposal_id FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(oldCancelledId).first(), null, "terminal proposal metadata is purged after its retention window");
assert.ok(await cleanupDb.prepare("SELECT proposal_id FROM nr_operation_proposals WHERE proposal_id = ?")
  .bind(recentUnknownId).first(), "recent sanitized outcome metadata remains for review");
assert.equal(await cleanupDb.prepare("SELECT session_key_hash FROM nr_approval_sessions WHERE session_key_hash = ?")
  .bind(oldSessionHash).first(), null);
assert.equal(await cleanupDb.prepare("SELECT session_key_hash FROM nr_approval_sessions WHERE session_key_hash = ?")
  .bind(oldRevokedSessionHash).first(), null);
assert.ok(await cleanupDb.prepare("SELECT session_key_hash FROM nr_approval_sessions WHERE session_key_hash = ?")
  .bind(recentSessionHash).first(), "recent session records remain until the retention cutoff");
const cleanupReplay = await cleanupOperationApprovalStore({ db: cleanupDb, now: cleanupNow });
assert.deepEqual(cleanupReplay, { expiredProposals: 0, staleClaims: 0, purgedProposals: 0, purgedSessions: 0 },
  "retention cleanup is idempotent");
const expiryPlan = cleanupSqlite.prepare("EXPLAIN QUERY PLAN SELECT proposal_id FROM nr_operation_proposals WHERE status IN ('pending', 'approved') AND expires_at <= ? ORDER BY expires_at ASC LIMIT ?")
  .all(cleanupNow, OPERATION_APPROVAL_LIMITS.cleanupBatchSize).map(row => row.detail).join(" ");
assert.match(expiryPlan, /nr_operation_proposals_expiry_cleanup/);
assert.doesNotMatch(expiryPlan, /USE TEMP B-TREE/);
const terminalPlan = cleanupSqlite.prepare("EXPLAIN QUERY PLAN SELECT proposal_id FROM nr_operation_proposals WHERE status IN ('stale', 'cancelled', 'outcome_unknown', 'completed', 'failed') AND COALESCE(finished_at, expires_at) <= ? ORDER BY COALESCE(finished_at, expires_at) ASC LIMIT ?")
  .all(cleanupNow, OPERATION_APPROVAL_LIMITS.cleanupBatchSize).map(row => row.detail).join(" ");
assert.match(terminalPlan, /nr_operation_proposals_terminal_cleanup/);
assert.doesNotMatch(terminalPlan, /USE TEMP B-TREE/);
const backlogIds = Array.from({ length: OPERATION_APPROVAL_LIMITS.cleanupBatchSize + 1 }, () => insertCleanupProposal({
  status: "pending", expiresAt: cleanupNow - 5000,
}));
const backlogFirst = await cleanupOperationApprovalStore({ db: cleanupDb, now: cleanupNow });
assert.equal(backlogFirst.expiredProposals, OPERATION_APPROVAL_LIMITS.cleanupBatchSize,
  "one cleanup run transitions at most the configured number of expired proposals");
const backlogSecond = await cleanupOperationApprovalStore({ db: cleanupDb, now: cleanupNow });
assert.equal(backlogSecond.expiredProposals, 1, "the next run drains the remaining expired row");
for (const id of backlogIds) {
  assert.equal((await cleanupDb.prepare("SELECT status FROM nr_operation_proposals WHERE proposal_id = ?").bind(id).first()).status, "stale");
}
console.log("PASS default-off bounded retention cleanup, ordered indexes, 100-row batches, secret clearing, stale-claim stop and idempotence");

console.log("D1-backed approval session, proposal, nonce CAS, gateway binding and cleanup tests passed; provider calls: 0");
