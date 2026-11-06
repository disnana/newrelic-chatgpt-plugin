import assert from "node:assert/strict";

class FakeElement {
  constructor(selector) {
    this.selector = selector;
    this.disabled = false;
    this.checked = false;
    this.value = selector === "#threshold" ? "0.75" : "";
    this.textContent = selector === "#proposal-summary"
      ? "No proposal has been created."
      : selector === "#status" ? "Rehearsal controls are off." : "";
    this.listeners = new Map();
  }
  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }
  async click() {
    if (this.disabled) return;
    for (const listener of this.listeners.get("click") || []) await listener({ target: this });
  }
  async change() {
    for (const listener of this.listeners.get("change") || []) await listener({ target: this });
  }
}

const selectors = [
  "#enable-rehearsal", "#threshold", "#create", "#approve", "#claim", "#unknown", "#cancel",
  "#status", "#proposal-summary",
];
let demoNumber = 0;
async function loadDemo() {
  const elements = new Map(selectors.map(selector => [selector, new FakeElement(selector)]));
  globalThis.document = { querySelector: selector => elements.get(selector) || null };
  await import(new URL(`../examples/operation-approval/demo.mjs?ui-test=${++demoNumber}`, import.meta.url));
  return Object.fromEntries(selectors.map(selector => [selector.slice(1).replaceAll("-", "_"), elements.get(selector)]));
}

const originalFetch = globalThis.fetch;
let networkCalls = 0;
globalThis.fetch = async () => {
  networkCalls += 1;
  throw new Error("network disabled in UI rehearsal test");
};

try {
  const interrupted = await loadDemo();
  interrupted.enable_rehearsal.checked = true;
  await interrupted.enable_rehearsal.change();
  const creationInFlight = interrupted.create.click();
  assert.equal(interrupted.create.disabled, true, "repeated creation is disabled while hashing is in flight");
  await interrupted.create.click();
  interrupted.enable_rehearsal.checked = false;
  await interrupted.enable_rehearsal.change();
  await creationInFlight;
  assert.match(interrupted.status.textContent, /disabled before creation completed/);
  assert.equal(interrupted.proposal_summary.textContent, "No proposal has been created.");
  interrupted.enable_rehearsal.checked = true;
  await interrupted.enable_rehearsal.change();
  assert.equal(interrupted.approve.disabled, true, "a late proposal cannot become approvable after re-enabling");
  assert.equal(interrupted.create.disabled, false);
  console.log("PASS repeated clicks and disable/re-enable during creation discard late proposals");

  const approvalRace = await loadDemo();
  approvalRace.enable_rehearsal.checked = true;
  await approvalRace.enable_rehearsal.change();
  await approvalRace.create.click();
  const approvalInFlight = approvalRace.approve.click();
  approvalRace.enable_rehearsal.checked = false;
  const disableDuringApproval = approvalRace.enable_rehearsal.change();
  await Promise.all([approvalInFlight, disableDuringApproval]);
  assert.match(approvalRace.proposal_summary.textContent, /State: cancelled/);
  approvalRace.enable_rehearsal.checked = true;
  await approvalRace.enable_rehearsal.change();
  assert.equal(approvalRace.create.disabled, false);
  assert.equal(approvalRace.approve.disabled, true);
  assert.equal(approvalRace.claim.disabled, true);
  console.log("PASS disabling during approval cancels the proposal and recovers cleanly");

  const claimRace = await loadDemo();
  claimRace.enable_rehearsal.checked = true;
  await claimRace.enable_rehearsal.change();
  await claimRace.create.click();
  await claimRace.approve.click();
  const claimInFlight = claimRace.claim.click();
  claimRace.enable_rehearsal.checked = false;
  const disableDuringClaim = claimRace.enable_rehearsal.change();
  await Promise.all([claimInFlight, disableDuringClaim]);
  assert.match(claimRace.proposal_summary.textContent, /State: cancelled/);
  claimRace.enable_rehearsal.checked = true;
  await claimRace.enable_rehearsal.change();
  assert.equal(claimRace.create.disabled, false);
  assert.equal(claimRace.approve.disabled, true);
  assert.equal(claimRace.claim.disabled, true);
  console.log("PASS disabling during claim prevents action and exposes no stale approve/claim controls");

  const stale = await loadDemo();
  stale.enable_rehearsal.checked = true;
  await stale.enable_rehearsal.change();
  await stale.create.click();
  assert.match(stale.proposal_summary.textContent, /0\.75%.*State: pending/);
  await stale.approve.click();
  assert.match(stale.proposal_summary.textContent, /State: approved/);
  stale.threshold.value = "1.25";
  await stale.claim.click();
  assert.match(stale.status.textContent, /proposal_stale/);
  assert.match(stale.proposal_summary.textContent, /State: stale/);
  assert.equal(stale.create.disabled, false, "stale proposals recover to a state where the owner can start a fresh rehearsal");
  assert.equal(stale.cancel.disabled, true);
  console.log("PASS stale claim refreshes UI state and enables recovery");

  const exact = await loadDemo();
  exact.enable_rehearsal.checked = true;
  await exact.enable_rehearsal.change();
  exact.threshold.value = "0.754";
  await exact.create.click();
  assert.match(exact.proposal_summary.textContent, /0\.754%/,
    "the displayed impact must preserve the exact numeric argument");
  await exact.approve.click();
  await exact.claim.click();
  assert.match(exact.proposal_summary.textContent, /State: claimed/);
  assert.match(exact.status.textContent, /No New Relic or other provider was contacted/);
  await exact.unknown.click();
  assert.match(exact.proposal_summary.textContent, /State: outcome_unknown/);
  assert.match(exact.status.textContent, /cannot be retried/);
  assert.equal(exact.claim.disabled, true, "unknown outcome never exposes a retry action");
  console.log("PASS exact-effect display and uncertain-outcome UI never offers retry");

  assert.equal(networkCalls, 0, "the UI rehearsal makes zero provider/API network calls");
} finally {
  if (originalFetch === undefined) delete globalThis.fetch;
  else globalThis.fetch = originalFetch;
  delete globalThis.document;
}

console.log("Synthetic approval UI tests passed; no provider call was made");
