import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const projectRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const workerPath = resolve(projectRoot, "dist/server/index.js");
const manifestPath = resolve(projectRoot, "dist/.openai/hosting.json");

const [source, manifest] = await Promise.all([
  readFile(workerPath, "utf8"),
  readFile(manifestPath, "utf8"),
]);
const parsedManifest = JSON.parse(manifest);
assert.equal(parsedManifest.capabilities?.includes("mcp"), true);
assert.equal(parsedManifest.d1, "DB");
assert.doesNotMatch(source, /^\s*import\s/m, "Worker artifact must be self-contained");
for (const required of [
  "get_connection_status",
  "execute_nrql",
  "mcp.newrelic.com",
  "New Relic公式OAuth",
  "lang=\\\"ja\\\"",
  "/oauth/complete",
  "/api/oauth/manual-complete",
  "localhostから戻ったURL",
]) {
  assert.ok(source.includes(required), `Worker bundle is missing ${required}`);
}

const workerModule = await import(pathToFileURL(workerPath).href + "?validate=" + Date.now());
assert.equal(typeof workerModule.default?.fetch, "function");

console.log("Artifact is valid Worker ESM; MCP capability and D1 binding are declared");
