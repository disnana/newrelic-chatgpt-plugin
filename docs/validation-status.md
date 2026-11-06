# Validation status (2026-11-06)

## Local checks

The v0.4.0 hardening worktree was validated locally with Node.js 24.22.1 and Python 3.12. The checks cover mocked OAuth token exchange/refresh, concurrent refresh, a callback racing between OAuth-state fencing and credential deletion, separate OAuth and ordinary API rate buckets, local-only status checks for expired grants, explicit per-user Core/Advanced/Preview consent, same-origin grant/revoke, consent expiry and user isolation, revocation/expiry between consent discovery and provider dispatch, schema and billing policy gates, deeply nested metadata, oversized account-name handling, escaped API responses, JSON-RPC ID bounds, additive D1 migration preservation, and existing Scylla Gate regressions.

- Worker build and artifact validation: passed.
- `npm test`: passed, including MCP security and OAuth/transport mocks (33 OAuth/transport tests); no live provider validation was performed.
- TypeScript 5.9.3 `checkJs` and null checks: passed using the compiler installed in the sibling checkout.
- Syntax/lint checks: passed.
- D1 migrations: passed SQLite syntax/schema checks and verified existing connection/account rows survive additive migration 0003.
- Distribution and secret-pattern checks: passed; the checker explicitly notes it is not a complete secret detector.
- Local v0.4.0 source ZIP generation and checksum: passed.
- `npm audit --audit-level=high`: passed on 2026-11-06; npm reported `found 0 vulnerabilities` (exit 0). The audit used the committed package manifest and lockfile.
- Draft PR #3's previously published source commit passed GitHub Actions CI #73, but these additional local consent/gateway changes have not yet been published or tested by CI.

## Live-provider boundary

Authenticated `tools/list` and New Relic data reads were not available for this change because the connected provider currently reports a refresh failure. The public unauthenticated endpoint returned 401 in earlier read-only research; that is not authenticated capability evidence. No authenticated tool was executed, no billable action was performed, and no production setting, deployment or formal Release was changed.

The documentation inventory contains 41 tool names, but the authenticated account's actual tool count and schemas remain unknown. The v0.4.0 generic adapter has 0 live-verified tools. Official feature/API availability, current account entitlements and billing conditions remain subject to the documented evidence limits. Core Compute measurement is not proof of an extra charge; the integration cannot inspect whether the account's Data + User or Data + Core Compute plan includes a given use.

## Remaining deployment and release checks

- A fresh ChatGPT Site installation, real OAuth renewal and real D1 concurrency still need owner-controlled verification after separate deployment approval.
- An opt-in `signed_proxy` assertion verifier was added and locally tested with synthetic keys/subjects, key rotation, zero-D1/zero-provider rejection, OAuth start/manual completion subject binding, status, MCP requests, and public-origin links behind an internal hostname. A separate fail-closed gateway boundary reference now has synthetic tests for adapter separation, CSRF on side-effecting GETs, assertion signing/header replacement, body limits, routes and redirects. Neither supplies real login/MCP OAuth adapters or production topology. Real browser sessions, CSRF integration, end-to-end New Relic redirect, provider token issuance, and real-user isolation remain unverified; do not expose it as a multi-user public service until operator adapters are implemented and independently reviewed.
- Write/destructive approval workflow is not implemented, and those operations remain disabled.
- An operation approval design is documented, but it is not an implementation or authorization to enable writes.
- Connection status surfaces now inspect local D1 metadata only and do not refresh tokens or contact New Relic. A token refresh is attempted only when an explicit New Relic-backed operation runs; the exact live OAuth failure code remains unknown.
- The connection page labels saved credentials as unverified and keeps an explicit reconnect action available without first deleting them. Explicitly blank or invalid self-host auth mode configuration fails closed instead of falling back to Sites identity.
- Explicitly initiated failures expose only a fixed allowlist of non-secret diagnostic codes in API/MCP responses. The code path was tested with mock OAuth responses; no live error code was retrieved and no code is persisted for local status checks.
- Preview, account entitlements and per-account Core/Advanced Compute pricing were not verified.
- No production deployment or formal Release is included. `VERSION` remains 0.4.0 for the draft PR; merging a version change to main can trigger the existing Release workflow.
- D1 migration 0003 was tested against local SQLite only. It was not applied to the user's production Site.
- No New Relic `tools/call`, billable read, OAuth refresh, production setting, Site source, deployment or release was performed as part of this local consent implementation.
