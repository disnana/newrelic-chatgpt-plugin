# Official MCP and feature research (2026-11-06)

This is a public-documentation inventory, **not a captured authenticated `tools/list` response**. The [machine-readable companion](official-mcp-inventory.json) records 41 unique documented tools: 35 non-preview and 6 preview. Descriptions below are editorial summaries, not runtime schemas. All `inputSchema` values in the inventory are deliberately `null`: the public reference does not publish argument schemas. Runtime discovery must obtain and validate them; do not invent schemas or present 41 as the user's available-tool count.

## Evidence and live verification boundary

- [Official tool reference](https://docs.newrelic.com/docs/agentic-ai/mcp/tool-reference/) was retrieved on 2026-11-06. It documents category filtering through the `include-tags` header and a stated limit of 2,000 calls/hour/user (subject to change).
- A historical request to the existing installed plugin's connection-status tool returned `connected: true`, `requiresReauthentication: true`, `providerReachable: false`, and a refresh-failure message, but no provider error code. Although the tool was described as read-only, the project implementation's status path could attempt token refresh and, if metered reads were enabled, an official account-list read. The returned text cannot establish whether a token refresh or billable provider call occurred, so we do not treat that invocation as side-effect-free evidence. It does not establish the user's actual root cause and was not repeated.
- An unauthenticated GET to the fixed US MCP endpoint returned HTTP 401 on 2026-11-06 at 08:47:16 UTC. The provider was reachable from this research environment. Authentication failure is not proof of network failure. No authenticated tools were called successfully and no live account-data test passed in this research.
- Public [protected-resource metadata](https://mcp.newrelic.com/.well-known/oauth-protected-resource) advertises the MCP resource and authorization server. Public [authorization-server metadata](https://oauth2.service.newrelic.com/.well-known/oauth-authorization-server) advertises `authorization_code`, `refresh_token`, PKCE `S256`, token auth method `none`, and `offline`, `offline_access`, `observability:read`. Do not infer that every client ID or redirect URI is registered merely from server-wide metadata.
- The MCP challenge also advertises `dashboards:modify` and `alerts:modify`. These scopes were not requested. Their presence does not establish that undocumented write tools exist or are safe to expose.

## Billing and permission rules

Read-only is an operation category, **not a zero-price guarantee**. The official reference says most tools consume Core Compute allocation. Four AI tools consume Advanced Compute and require its add-on. Preview pricing is not final. The inventory's conservative `core-compute-potentially-metered` designation is not a claim of a specific per-tool price. Account pricing, inclusion and remaining allocation must be checked separately before enabling potentially billable execution.

All tools remain subject to the user's provider RBAC and account access. A tool appearing in `tools/list` does not prove every resource is accessible or that its execution is free. AI tools, gap analysis and preview tools require OAuth. Unknown/new names or changed schemas require re-review instead of automatic exposure.

## Documented tools

Each name is unique below. Groups are a local editorial grouping; runtime tags may overlap. All entries are **documented, actual account execution unverified**.

| Group | Names | Summary |
|---|---|---|
| Discovery | `convert_time_period_to_epoch_ms`, `get_dashboard`, `get_entity`, `list_related_entities`, `list_available_new_relic_accounts`, `list_dashboards`, `search_entity_with_tag`, `list_metric_names` | Time conversion, resource/account discovery |
| Data | `execute_nrql_query` | NRDB query |
| Alerts | `list_alert_conditions`, `search_incident`, `list_alert_policies`, `list_recent_issues`, `list_synthetic_monitors`, `list_synthetic_monitor_results`, `get_synthetic_check_statistics` | Alerts and synthetic observations |
| Incident | `list_entity_error_groups`, `list_change_events`, `get_error_statistics`, `search_errors` | Errors and changes |
| Performance | `analyze_entity_logs`, `analyze_golden_metrics`, `analyze_threads`, `analyze_transactions`, `list_garbage_collection_metrics`, `list_recent_logs`, `list_entity_performance_risk_groups`, `get_metric_statistics`, `get_log_statistics`, `get_distributed_trace_details` | Telemetry investigation |
| Advanced / OAuth / aCCU | `natural_language_to_nrql_query`, `generate_alert_insights_report`, `generate_user_impact_report`, `analyze_deployment_impact` | AI analysis |
| Gap analysis / OAuth | `analyze_github_newrelic_gaps` | Instrumentation review |
| Preview / OAuth | `search_traces`, `analyze_trace_anomaly`, `analyze_service_dependencies` | Trace/dependency investigation |
| Preview / OAuth / feature flag | `analyze_kafka_health`, `analyze_kafka_related_entities`, `analyze_kafka_client_metrics` | Kafka investigation |

Gap analysis is not an ordinary local read: the client sends repository files to New Relic. It requires the New Relic GitHub App and analysis enrollment. Treat the transfer as a separate opt-in and validate selected files, secrets and size; never automatically upload a repository. The reference describes a 5 MB total limit, single-service support and Python-only APM detection.

## Advent Calendar feature matrix

“Not in documented MCP catalog” means no dedicated tool is in the 41-name reference, not proof that no future or account-specific tool can exist. None of these feature-specific APIs was executed against the user's account. Award eligibility itself has not been checked.

| Feature | Official MCP | Public API / other supported route | Practical status and limits |
|---|---|---|---|
| Notebooks | No dedicated documented tool. Generic entity discovery is not full content support. | [Blob Storage API](https://docs.newrelic.com/docs/query-your-data/explore-query-data/notebooks/blob-storage-api-for-notebooks/) for content/version CRUD; NerdGraph for entity metadata; official Terraform resource. | Strong article candidate for repeatable incident reports. Blob API requires User API key (or documented UI login context), not a proven substitute of the MCP OAuth token. Org-level and notebook-level permissions apply. Deletion is permanent. Do not silently create credentials or publish a notebook. |
| Lens | No dedicated documented tool; NRQL is not Lens SQL. | [Query Builder, Notebooks and dashboards](https://docs.newrelic.com/docs/new-relic-lens/query-data/) support SQL. [Workflow actions catalog](https://docs.newrelic.com/docs/workflow-automation/setup-and-configure/actions-catalog/actions-catalog/) documents Lens SQL actions. A standalone direct-query API was not established here. | [Paying customers only](https://docs.newrelic.com/docs/new-relic-lens/overview/): Data + User has no extra Lens cost; Data + Core Compute meters telemetry table queries. External-source setup, region and RBAC must be checked. No unsupported UI endpoint adapter. |
| Workflow Automation | No dedicated documented tool. | [Official NerdGraph APIs](https://docs.newrelic.com/docs/workflow-automation/workflow-automation-apis/using-workflow-automation-api/) for definitions, runs, schedules and actions. | Read definitions/history separately from starting workflows. [Advanced Compute required](https://docs.newrelic.com/docs/workflow-automation/introduction-to-workflow/). Runs may operate infrastructure and create a user API key on the caller's behalf; execution is out of this task's authorization. |
| DB360 | No dedicated documented tool. Generic entity/metric/NRQL tools can inspect already-ingested data if available. | [DB360/NRDOT](https://docs.newrelic.com/docs/opentelemetry/db360/introduction/) is collection and UI capability; generic NerdGraph/NRQL may query its telemetry. | Candidate for observing supported databases. This is not proof of support for the user's ScyllaDB topology or permission to install collectors. No DB360-specific management API verified. |
| Security RX | No dedicated documented tool. Generic NRQL can query documented NRDB events if authorized. | [Security data structure / NRQL](https://docs.newrelic.com/docs/vulnerability-management/advanced/data-structure/); [security-data ingestion API](https://docs.newrelic.com/docs/vulnerability-management/getting-started/integrations/overview/). | Read existing vulnerability data, do not ingest/change findings or launch remediation. Security RX Agent/UI operations are not thereby exposed through MCP. Product permissions/entitlement remain to verify. |
| Autopilot | No dedicated documented control tool. Shared analysis names do not equal Autopilot lifecycle support. | [Official UI and Slack experience](https://docs.newrelic.com/docs/agentic-ai/autopilot/overview/); a direct public orchestration API was not established here. | Overview lists Pro/Enterprise with Advanced Compute or Legacy Compute; [setup](https://docs.newrelic.com/docs/agentic-ai/autopilot/setup/) emphasizes Advanced Compute and creates a system identity. Do not enable it or create access automatically. Cannot claim free-account availability. |
| Teams / Scorecards | No dedicated documented tools. Generic entity reads are not full management. | [Teams NerdGraph](https://docs.newrelic.com/docs/apis/nerdgraph/examples/nerdgraph-teams-tutorial/), [Scorecards management](https://docs.newrelic.com/docs/service-architecture-intelligence/scorecards/managing-scorecards/) and NerdGraph tutorial. | Good API-adapter candidates after distinct authentication and organization-level permission review. Read and modify capabilities differ; do not treat account selection as sufficient organization authorization. |

### API adapter decision

Do not forward the MCP OAuth bearer token to NerdGraph or Blob Storage merely because both belong to New Relic. Their supported credentials/audience must be documented and checked. This research supports adding capability explanations and future typed adapters, not unrestricted GraphQL, arbitrary URLs, or automatic credential provisioning.

## Remaining evidence needed

1. Authenticated, paginated runtime `tools/list` snapshot, sanitized before persistence, with actual schemas and account-visible tool count.
2. A non-secret OAuth refresh error code from an existing diagnostic record, or a separately authorized controlled refresh probe (which can rotate the refresh token), then a read-only live data test only after separately reviewing billing and deployment approval.
3. Account contract/entitlements for Core/Advanced Compute and preview enablement. No free-tier conclusion follows from successful authentication.
4. Feature-specific User API key configuration only through an approved secure setup if an API adapter is selected.
