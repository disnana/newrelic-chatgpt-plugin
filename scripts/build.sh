#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd "$(dirname "$0")/.." && pwd)
cd "$project_root"
dist_root="$project_root/dist"

rm -rf "$dist_root"
mkdir -p "$dist_root/server" "$dist_root/.openai"
node "$project_root/scripts/bundle-worker.mjs"
cp "$project_root/.openai/hosting.json" "$dist_root/.openai/hosting.json"

echo "Built single-file Worker ESM bundle with MCP, OAuth, D1 metadata, and mobile UI: $dist_root"
