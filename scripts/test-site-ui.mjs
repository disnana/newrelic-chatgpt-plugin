import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { runInNewContext } from "node:vm";

const html = await readFile(new URL("../worker/page.html", import.meta.url), "utf8");
const script = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(script, "the Site page must contain its inline controller");

class FakeElement {
  constructor(tag = "div") {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.listeners = new Map();
    this.className = "";
    this.textContent = "";
    this.value = "";
    this.href = "";
    this.disabled = false;
    this.checked = false;
    this.hidden = false;
    this.dataset = {};
    this.parent = null;
    this.classes = new Set();
    this.classList = {
      add: name => this.classes.add(name),
      remove: name => this.classes.delete(name),
      toggle: (name, enabled) => enabled ? this.classes.add(name) : this.classes.delete(name),
      contains: name => this.classes.has(name),
    };
  }
  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }
  append(...children) {
    for (const child of children) {
      child.parent = this;
      this.children.push(child);
    }
  }
  replaceChildren(...children) {
    for (const child of this.children) child.parent = null;
    this.children = [];
    this.append(...children);
  }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this);
    this.parent = null;
  }
  querySelectorAll(selector) {
    const output = [];
    const visit = node => {
      for (const child of node.children) {
        if (selector === "button" && child.tagName === "BUTTON") output.push(child);
        visit(child);
      }
    };
    visit(this);
    return output;
  }
  async click() {
    if (this.disabled) return;
    for (const listener of this.listeners.get("click") || []) await listener({ target: this });
  }
}

function collectText(element) {
  return [element.textContent, ...element.children.map(collectText)].filter(Boolean).join(" ");
}

async function mountPage({ capabilityData, proposalData, approvalEnabled = true, approveOutcomeUncertain = false }) {
  const elements = new Map();
  const document = {
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, new FakeElement());
      return elements.get(selector);
    },
    createElement(tag) { return new FakeElement(tag); },
  };
  const calls = [];
  const csrfToken = "C".repeat(43);
  const approvalNonce = "N".repeat(43);
  const fakeFetch = async (path, options = {}) => {
    calls.push({ path, options });
    if (path === "/api/status") return { ok: true, status: 200, json: async () => ({
      authenticated: true, connected: true, requiresReauthentication: false,
      connectedAt: 1_800_000_000_000, region: "us", selectedAccount: { id: "fake-account", name: "Synthetic" },
    }) };
    if (path === "/api/usage-consent") return { ok: true, status: 200, json: async () => ({ usageConsents: {} }) };
    if (path === "/api/capabilities") return { ok: true, status: 200, json: async () => capabilityData };
    if (path === "/api/operation-approvals/session") {
      if (!approvalEnabled) return { ok: false, status: 404, json: async () => ({ error: "Operation approvals are unavailable." }) };
      return { ok: true, status: 200, json: async () => ({ csrfToken, sessionExpiresAt: 1_800_000_900_000 }) };
    }
    if (path === "/api/operation-approvals/list") return { ok: true, status: 200, json: async () => proposalData };
    if (path === "/api/operation-approvals/challenge") return { ok: true, status: 200, json: async () => ({
      proposalId: "A".repeat(24), approvalNonce, challengeExpiresAt: Date.now() + 90_000,
      effectSummary: "Would update synthetic alert threshold to 2.5%.",
    }) };
    if (path === "/api/operation-approvals/approve") {
      if (approveOutcomeUncertain) return { ok: false, status: 502, json: async () => ({
        error: "Operation approval request could not be completed.", errorCode: "proposal_stale_or_replayed",
      }) };
      return { ok: true, status: 200, json: async () => ({
        proposalId: "A".repeat(24), status: "approved", dispatchAvailable: false,
        message: "Approval recorded. No New Relic mutation was sent.",
      }) };
    }
    if (path === "/api/operation-approvals/cancel") return { ok: true, status: 200, json: async () => ({ status: "cancelled" }) };
    throw new Error("Unexpected endpoint: " + path);
  };
  const context = {
    document,
    window: { location: { href: "https://monitor.example.test/" } },
    fetch: fakeFetch,
    URL,
    Date,
    console,
  };
  runInNewContext(script, context, { timeout: 1000 });
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  return { elements, calls, csrfToken, approvalNonce, fakeFetch };
}

const catalogPage = await mountPage({
  capabilityData: { tools: [
    { name: "execute_nrql", operation: "read", billing: "core_compute", available: false, reason: "usage_consent_required", description: "<script>secret-ish prompt injection</script>" },
    { name: "unsafe_write", operation: "write", billing: "unknown", available: false, reason: "operation_approval_not_implemented", description: "Provider prose must not be rendered." },
  ], truncated: false },
  proposalData: { enabled: true, items: [] },
});
const catalogButton = catalogPage.elements.get("#load-capabilities");
assert.equal(catalogButton.disabled, false, "the catalog button is available only after local status says the connection is ready");
assert.deepEqual(catalogPage.calls.map(call => call.path).sort(), ["/api/status", "/api/usage-consent"],
  "page load does not create approval sessions or fetch the live catalog");
await catalogButton.click();
assert.equal(catalogPage.calls.filter(call => call.path === "/api/capabilities").length, 1,
  "the official MCP catalog is fetched only after an explicit click");
assert.ok(catalogPage.calls.every(call => call.path !== "/api/accounts"), "catalog retrieval does not list accounts");
const catalogText = collectText(catalogPage.elements.get("#capability-list"));
assert.match(catalogText, /execute_nrql/);
assert.match(catalogText, /usage_consent_required/);
assert.doesNotMatch(catalogText, /prompt injection|Provider prose|<script>/,
  "untrusted provider descriptions are never inserted into the DOM");
assert.equal(catalogPage.calls.find(call => call.path === "/api/capabilities").options.credentials, "same-origin");
console.log("PASS explicit tools/list-only capability retrieval; no telemetry query and provider descriptions stay hidden");

const approvalPage = await mountPage({
  capabilityData: { tools: [] },
  proposalData: { enabled: true, items: [{
    proposalId: "A".repeat(24), status: "pending", toolName: "demo_write", operation: "write",
    billing: "core_compute", account: { id: "synthetic-account", region: "us" },
    effectSummary: "Would update synthetic alert threshold to 2.5%.",
  }] },
});
const approvalButton = approvalPage.elements.get("#load-approvals");
assert.equal(approvalButton.disabled, false);
assert.equal(approvalPage.calls.some(call => call.path.includes("operation-approvals")), false,
  "approval sessions are not created on page load");
await approvalButton.click();
const approvalCalls = approvalPage.calls.filter(call => call.path.includes("operation-approvals"));
assert.deepEqual(approvalCalls.map(call => call.path), [
  "/api/operation-approvals/session", "/api/operation-approvals/list",
]);
assert.equal(approvalCalls[0].options.method, "POST");
assert.equal(approvalCalls[0].options.credentials, "same-origin");
assert.equal(approvalCalls[1].options.headers["x-approval-csrf"], approvalPage.csrfToken,
  "the per-session CSRF token is attached to browser-only requests");
const proposalCard = approvalPage.elements.get("#approval-list").children[0];
assert.match(collectText(proposalCard), /2\.5%/);
const reviewButton = proposalCard.children.find(child => child.textContent === "対象と影響を確認");
await reviewButton.click();
assert.equal(reviewButton.disabled, true, "a proposal challenge cannot be created twice from repeated clicks");
assert.doesNotMatch(collectText(proposalCard), new RegExp(approvalPage.approvalNonce),
  "the browser-only single-use nonce is kept out of rendered text");
const approveButton = proposalCard.children.find(child => child.textContent === "この提案を1回だけ承認");
assert.ok(approveButton);
await approveButton.click();
assert.match(approvalPage.elements.get("#approval-status").textContent, /No New Relic mutation was sent/);
const approveCall = approvalPage.calls.find(call => call.path === "/api/operation-approvals/approve");
assert.ok(approveCall);
assert.equal(approveCall.options.headers["x-approval-csrf"], approvalPage.csrfToken);
assert.deepEqual(Object.keys(JSON.parse(approveCall.options.body)).sort(), ["approvalNonce", "proposalId"]);
assert.equal(JSON.parse(approveCall.options.body).approvalNonce, approvalPage.approvalNonce);
assert.equal(approvalPage.calls.some(call => call.path === "/api/operation-approvals/propose"), false);
assert.equal(approvalPage.calls.some(call => /nrql|logs|metrics|tools\/call/i.test(call.path)), false);
console.log("PASS explicit session, proposal review, single approval click and no mutation dispatch");

const disabledPage = await mountPage({
  capabilityData: { tools: [] },
  proposalData: { enabled: true, items: [] },
  approvalEnabled: false,
});
await disabledPage.elements.get("#load-approvals").click();
assert.match(disabledPage.elements.get("#approval-status").textContent, /既定で停止中/);
assert.equal(disabledPage.calls.some(call => call.path === "/api/operation-approvals/list"), false,
  "a disabled API does not continue into proposal listing");
assert.equal(disabledPage.calls.some(call => call.path.startsWith("/api/operation-approvals/approve")), false);
console.log("PASS default-off approval APIs stop before listing or approval");

const uncertainPage = await mountPage({
  capabilityData: { tools: [] },
  proposalData: { enabled: true, items: [{
    proposalId: "B".repeat(24), status: "pending", toolName: "demo_write", operation: "write",
    billing: "core_compute", account: { id: "synthetic-account", region: "us" },
    effectSummary: "Would update synthetic alert threshold to 2.5%.",
  }] },
  approveOutcomeUncertain: true,
});
await uncertainPage.elements.get("#load-approvals").click();
const uncertainCard = uncertainPage.elements.get("#approval-list").children[0];
await uncertainCard.children.find(child => child.textContent === "対象と影響を確認").click();
const uncertainApprove = uncertainCard.children.find(child => child.textContent === "この提案を1回だけ承認");
await uncertainApprove.click();
assert.match(uncertainPage.elements.get("#approval-status").textContent, /再送はしないでください/);
assert.equal(uncertainApprove.disabled, true, "an uncertain approval response permanently disables that one-click control");
const approveAttemptsBeforeRetry = uncertainPage.calls.filter(call => call.path === "/api/operation-approvals/approve").length;
await uncertainApprove.click();
assert.equal(uncertainPage.calls.filter(call => call.path === "/api/operation-approvals/approve").length, approveAttemptsBeforeRetry,
  "an uncertain approval is not replayed from the browser");
console.log("PASS uncertain approval responses disable the action and prevent browser replay");
