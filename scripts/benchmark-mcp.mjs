import { performance } from "node:perf_hooks";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const worker = (await import(pathToFileURL(resolve(root, "dist/server/index.js")).href + "?bench=" + Date.now())).default;
const warmupCount = 100;
const sampleCount = 1000;

async function ping() {
  const request = new Request("https://example.test/mcp", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "ping", arguments: {} } }),
  });
  const start = performance.now();
  const response = await worker.fetch(request, {});
  const payload = await response.json();
  const elapsedMs = performance.now() - start;
  if (response.status !== 200 || payload.result?.content?.[0]?.text !== "pong") {
    throw new Error("Ping response was invalid");
  }
  return elapsedMs;
}

for (let i = 0; i < warmupCount; i += 1) await ping();
const samples = [];
for (let i = 0; i < sampleCount; i += 1) samples.push(await ping());
samples.sort((a, b) => a - b);

const percentile = (p) => samples[Math.ceil(p * samples.length) - 1];
const meanMs = samples.reduce((sum, value) => sum + value, 0) / samples.length;
console.log(JSON.stringify({
  runtime: process.version,
  warmupCount,
  sampleCount,
  measurement: "in-process Node Worker.fetch of built artifact; no network, D1, New Relic, or ChatGPT call",
  p50Ms: Number(percentile(0.50).toFixed(4)),
  p95Ms: Number(percentile(0.95).toFixed(4)),
  p99Ms: Number(percentile(0.99).toFixed(4)),
  meanMs: Number(meanMs.toFixed(4)),
}, null, 2));
