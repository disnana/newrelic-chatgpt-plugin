# Validation status (2026-11-06)

## Local checks

The published v0.4.0 source snapshot was validated locally with Node.js 24.22.1 and Python 3.12. A new local-only approval-backend candidate adds D1 session/approval persistence and signed-proxy browser-session binding; its tests use SQLite, synthetic identities, and a fake private gateway. No provider request is made by these tests.

- Worker build and artifact validation: passed.
- `npm test`: passed for this local candidate, including MCP security, 33 OAuth/transport mocks, synthetic operation-approval/UI rehearsals, and D1-backed approval-store tests. Provider calls: 0.
- TypeScript 5.9.3 checkJs/null checks: passed offline for this candidate using the already-cached repository toolchain (`node ../newrelic-v040/node_modules/typescript/bin/tsc --project tsconfig.json`); no package was installed and no network request was made.
- Syntax/lint checks: passed.
- D1 migrations 0000–0004: passed local SQLite syntax/schema tests; existing connection/account rows are preserved and receive opaque generation values. Migration 0004 was not applied to production D1.
- Artifact validation, distribution and secret-pattern checks: passed; the checker explicitly notes it is not a complete secret detector.
- Local v0.4.0 source ZIP generation and checksum: passed.
- `npm audit --audit-level=high`: passed on 2026-11-06; npm reported `found 0 vulnerabilities` (exit 0). The audit used the committed package manifest and lockfile.
- Draft PR #3 remains open, draft, and unmerged. Published head `9be3685` passed GitHub Actions CI #77, including npm audit; the latest D1-backed approval candidate in `feat/v0.4.0-approval-backend` is local/uncommitted and has not been published or tested by CI.
- Synthetic rehearsal tests use fixed fake targets and an in-memory mock. Separately, the new Worker approval foundation stores session/nonce hashes in D1, encrypts proposal arguments, and uses conditional single-use state transitions. It still has no reviewed write policy, public proposal-creation route, MCP write tool, or provider dispatch.
- Independent local SQLite interleaving probes and committed regression tests cover account switching at approval CAS, disconnect/session revocation/ciphertext substitution at claim CAS, decryptable argument tampering, and expiry during async argument verification. No New Relic provider calls were made.

## Live-provider boundary

Authenticated `tools/list` and New Relic data reads were not available for this change because the connected provider previously reported a refresh failure. The public unauthenticated endpoint returned 401 in earlier read-only research; that is not authenticated capability evidence. No authenticated tool was executed, no billable action was performed, and no production setting, deployment or formal Release was changed.

The documentation inventory contains 41 tool names, but the authenticated account's actual tool count and schemas remain unknown. The v0.4.0 generic adapter has 0 live-verified tools. Official feature/API availability, current account entitlements and billing conditions remain subject to the documented evidence limits. Core Compute measurement is not proof of an extra charge; the integration cannot inspect whether the account's Data + User or Data + Core Compute plan includes a given use.

## Remaining deployment and release checks

- A fresh ChatGPT Site installation, real OAuth renewal and real D1 concurrency still need owner-controlled verification after separate deployment approval.
- An opt-in `signed_proxy` assertion verifier was added and locally tested with synthetic keys/subjects, key rotation, zero-D1/zero-provider rejection, OAuth start/manual completion subject binding, status, MCP requests, and public-origin links behind an internal hostname. A separate fail-closed gateway boundary reference now has synthetic tests for adapter separation, CSRF on side-effecting GETs, assertion signing/header replacement, body limits, routes and redirects. Neither supplies real login/MCP OAuth adapters or production topology. Real browser sessions, CSRF integration, end-to-end New Relic redirect, provider token issuance, and real-user isolation remain unverified; do not expose it as a multi-user public service until operator adapters are implemented and independently reviewed.
- The approval backend is groundwork only. A real reviewed tool catalog, owner/resource-ownership check, human-facing effect display, browser UI, external identity-provider session validation, provider dispatch path, independent review, and dedicated non-production New Relic validation remain incomplete. The empty policy registry and missing proposal-creation/dispatch route keep real writes disabled.
- Expired approval sessions/proposals are unusable but are not automatically purged; proposal encryption uses the existing configured D1 encryption key. Define and implement an explicit retention/cleanup policy before storing real proposals or enabling a reviewed policy. No cleanup or data deletion was performed by this candidate.
- Signed-proxy approval sessions need a real operator auth adapter that returns a stable browser-session binding; only synthetic gateway assertions were tested. MCP assertions cannot provide approval sessions. No generic production login service or MCP OAuth issuer was added.
- Connection status surfaces now inspect local D1 metadata only and do not refresh tokens or contact New Relic. A token refresh is attempted only when an explicit New Relic-backed operation runs; the exact live OAuth failure code remains unknown.
- The connection page labels saved credentials as unverified and keeps an explicit reconnect action available without first deleting them. Explicitly blank or invalid self-host auth mode configuration fails closed instead of falling back to Sites identity.
- Explicitly initiated failures expose only a fixed allowlist of non-secret diagnostic codes in API/MCP responses. The code path was tested with mock OAuth responses; no live error code was retrieved and no code is persisted for local status checks.
- Preview, account entitlements and per-account Core/Advanced Compute pricing were not verified.
- No production deployment or formal Release is included. `VERSION` remains 0.4.0 for the draft PR; merging a version change to main can trigger the existing Release workflow.
- D1 migrations 0003 and 0004 were tested against local SQLite only. Neither was applied to the user's production Site.
- No New Relic `tools/call`, billable read, OAuth refresh, production setting, Site source, deployment or release was performed as part of this local consent implementation.
