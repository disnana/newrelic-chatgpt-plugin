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

async function mountPage({ capabilityData, proposalData, approvalEnabled = true, approveOutcomeUncertain = false,
  csrfCookie = "", logoutEnabled = false }) {
  const elements = new Map();
  const document = {
    cookie: csrfCookie,
    querySelector(selector) {
      if (!elements.has(selector)) elements.set(selector, new FakeElement());
      if (selector === "#gateway-session") elements.get(selector).dataset.logoutEnabled = logoutEnabled ? "true" : "";
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
    if (path.startsWith("/api/capabilities")) {
      const url = new URL(path, "https://monitor.example.test");
      const toolName = url.searchParams.get("name");
      const data = toolName
        ? capabilityData.details?.[toolName]
        : capabilityData.pages?.find(page => page.offset === Number(url.searchParams.get("offset") || 0));
      return data
        ? { ok: true, status: 200, json: async () => data }
        : { ok: false, status: 409, json: async () => ({ error: "Catalog changed.", errorCode: "catalog_changed" }) };
    }
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
    if (path === "/auth/logout") return { ok: true, status: 200, json: async () => ({ signedOut: true, newRelicConnectionPreserved: true }) };
    throw new Error("Unexpected endpoint: " + path);
  };
  const navigation = [];
  const context = {
    document,
    window: { location: { href: "https://monitor.example.test/", assign: path => navigation.push(path) } },
    fetch: fakeFetch,
    URL,
    Date,
    console,
  };
  runInNewContext(script, context, { timeout: 1000 });
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
  return { elements, calls, csrfToken, approvalNonce, fakeFetch, navigation };
}

const catalogPage = await mountPage({
  capabilityData: {
    pages: [
      { snapshot: "A".repeat(64).toLowerCase(), discovered: 3, enabled: 0, offset: 0, limit: 2, items: [
        { name: "execute_nrql", schemaHash: "a".repeat(64), schemaAvailable: true, scope: "account", preview: false, operation: "read", billing: "core_compute", available: false, reason: "usage_consent_required" },
        { name: "unsafe_write", schemaHash: "b".repeat(64), schemaAvailable: true, scope: "account", preview: true, operation: "write", billing: "unknown", available: false, reason: "operation_approval_not_implemented" },
      ], nextOffset: 2 },
      { snapshot: "A".repeat(64).toLowerCase(), discovered: 3, enabled: 0, offset: 2, limit: 2, items: [
        { name: "another_tool", schemaHash: "c".repeat(64), schemaAvailable: true, scope: "identity", preview: false, operation: "read", billing: "unknown", available: false, reason: "billing_unverified" },
      ], nextOffset: null },
    ],
    details: { execute_nrql: { snapshot: "A".repeat(64).toLowerCase(), tool: {
      name: "execute_nrql", schemaHash: "a".repeat(64), description: "<script>untrusted provider text</script>",
      inputSchema: { type: "object", properties: { nrql: { type: "string", maxLength: 1000 } }, required: ["nrql"], additionalProperties: false },
      outputSchema: null, schemaWasRedacted: false,
    } } },
  },
  proposalData: { enabled: true, items: [] },
  csrfCookie: "__Host-nr-gateway-csrf=" + "S".repeat(43),
});
const catalogButton = catalogPage.elements.get("#load-capabilities");
assert.equal(catalogButton.disabled, false, "the catalog button is available only after local status says the connection is ready");
assert.deepEqual(catalogPage.calls.map(call => call.path).sort(), ["/api/status", "/api/usage-consent"],
  "page load does not create approval sessions or fetch the live catalog");
await catalogButton.click();
assert.equal(catalogPage.calls.filter(call => call.path.startsWith("/api/capabilities")).length, 1,
  "the official MCP catalog is fetched only after an explicit click");
assert.ok(catalogPage.calls.every(call => call.path !== "/api/accounts"), "catalog retrieval does not list accounts");
const catalogText = collectText(catalogPage.elements.get("#capability-list"));
assert.match(catalogText, /execute_nrql/);
assert.match(catalogText, /usage_consent_required/);
assert.match(catalogText, /account · 通常/);
assert.doesNotMatch(catalogText, /untrusted provider text|<script>/,
  "provider text is not fetched or rendered until the user opens a tool detail");
const loadMore = catalogPage.elements.get("#load-more-capabilities");
assert.equal(loadMore.hidden, false);
await loadMore.click();
assert.match(collectText(catalogPage.elements.get("#capability-list")), /another_tool/,
  "the catalog exposes later pages instead of silently truncating entries");
assert.equal(loadMore.hidden, true);
const schemaButton = catalogPage.elements.get("#capability-list").children[0].children[2];
await schemaButton.click();
const capabilityCalls = catalogPage.calls.filter(call => call.path.startsWith("/api/capabilities"));
assert.equal(capabilityCalls.length, 3, "one explicit initial page, one requested next page, and one requested schema detail are fetched");
assert.match(capabilityCalls[1].path, /offset=2/);
assert.match(capabilityCalls[1].path, /snapshot=/);
assert.match(capabilityCalls[2].path, /name=execute_nrql/);
assert.equal(capabilityCalls[0].options.credentials, "same-origin");
assert.equal(capabilityCalls[0].options.headers["x-csrf-token"], "S".repeat(43),
  "a self-host CSRF cookie is attached as a same-origin request header, never placed in the URL");
assert.equal(capabilityCalls[2].options.headers["x-csrf-token"], "S".repeat(43));
const schemaPanel = catalogPage.elements.get("#capability-list").children[0].children[3];
assert.equal(schemaPanel.children[1].textContent, "<script>untrusted provider text</script>",
  "untrusted provider description is rendered only as plain text on explicit request");
assert.match(schemaPanel.children[2].textContent, /\"nrql\"/);
assert.ok(!schemaPanel.children.some(child => child.tagName === "SCRIPT"), "provider text never creates DOM markup");
console.log("PASS paged tools/list catalog and on-demand schema inspection; no telemetry query");

const failedSchemaPage = await mountPage({
  capabilityData: { pages: [{ snapshot: "D".repeat(64).toLowerCase(), discovered: 1, enabled: 0, offset: 0, limit: 20,
    items: [{ name: "stale_schema", schemaHash: "d".repeat(64), schemaAvailable: true, scope: "identity", preview: false,
      operation: "read", billing: "unknown", available: false, reason: "unreviewed" }], nextOffset: null }] },
  proposalData: { enabled: true, items: [] },
});
await failedSchemaPage.elements.get("#load-capabilities").click();
const staleRow = failedSchemaPage.elements.get("#capability-list").children[0];
const staleSchemaButton = staleRow.children[2];
await staleSchemaButton.click();
const staleSchemaPanel = staleRow.children[3];
assert.equal(staleSchemaPanel.hidden, false, "catalog/schema failures remain visible in the selected tool panel");
assert.match(staleSchemaPanel.children[0].textContent, /Catalog changed/);
assert.ok(staleSchemaPanel.children[0].classList.contains("error"));

const completionHtml = await readFile(new URL("../worker/oauth-complete.html", import.meta.url), "utf8");
const completionScript = completionHtml.match(/<script>([\s\S]*?)<\/script>/)?.[1];
assert.ok(completionScript, "the localhost-paste completion page must contain its controller");
async function runCompletionPage(cookie) {
  const completionElements = new Map();
  const document = {
    cookie,
    querySelector(selector) {
      if (!completionElements.has(selector)) completionElements.set(selector, new FakeElement());
      return completionElements.get(selector);
    },
  };
  let call = null;
  let replacedWith = null;
  const context = {
    document,
    fetch: async (path, options) => {
      call = { path, options };
      return { ok: true, status: 200, json: async () => ({ ok: true }) };
    },
    setTimeout(callback) { callback(); },
    location: { replace(path) { replacedWith = path; } },
  };
  runInNewContext(completionScript, context, { timeout: 1000 });
  const form = completionElements.get("#complete-form");
  completionElements.get("#callback-url").value = "http://localhost:12345/callback?code=synthetic&state=synthetic";
  await form.listeners.get("submit")[0]({ preventDefault() {} });
  return { call, replacedWith };
}
const selfHostCompletion = await runCompletionPage("__Host-nr-gateway-csrf=" + "K".repeat(43));
assert.equal(selfHostCompletion.call.path, "/api/oauth/manual-complete");
assert.equal(selfHostCompletion.call.options.headers["x-csrf-token"], "K".repeat(43),
  "the localhost-paste page includes the self-host CSRF header without putting it in the URL or body");
assert.doesNotMatch(selfHostCompletion.call.options.body, /K{43}/);
assert.equal(selfHostCompletion.replacedWith, "/");
const sitesCompletion = await runCompletionPage("");
assert.equal(sitesCompletion.call.options.headers["x-csrf-token"], undefined,
  "the existing Sites flow remains unchanged when no self-host CSRF cookie exists");
console.log("PASS self-host CSRF header also protects the localhost OAuth completion form");

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

const logoutPage = await mountPage({
  capabilityData: { pages: [], details: {} },
  proposalData: { enabled: false, items: [] },
  logoutEnabled: true,
  csrfCookie: "__Host-nr-gateway-csrf=" + "S".repeat(43),
});
assert.equal(logoutPage.elements.get("#gateway-session").hidden, false);
assert.equal(logoutPage.calls.some(call => call.path === "/auth/logout"), false,
  "the gateway session is not revoked until the user clicks sign out");
await logoutPage.elements.get("#gateway-logout").click();
const logoutCall = logoutPage.calls.find(call => call.path === "/auth/logout");
assert.equal(logoutCall.options.method, "POST");
assert.equal(logoutCall.options.headers["x-csrf-token"], "S".repeat(43),
  "logout sends the same-origin CSRF cookie in a header");
assert.deepEqual(logoutPage.navigation, ["/login"]);
assert.match(logoutPage.elements.get("#gateway-logout-status").textContent, /保存済みのNew Relic接続は維持/);
assert.equal(logoutPage.calls.some(call => call.path === "/api/disconnect"), false,
  "gateway sign-out does not disconnect the New Relic OAuth connection");
console.log("PASS explicit, CSRF-protected, session-only self-host logout");
