# Scylla Gate v1.1.0 — incident-gated New Relic telemetry

Run **only on the current centralized collector** (`oracle-cloud-core`). The collector scrapes all three configured ScyllaDB targets. **Do not install this on the ScyllaDB nodes**, which would duplicate ingest. The existing New Relic Infrastructure Agent remains active.

## Upgrade existing v1.0 installation / first installation

After merging this PR into main, run once on the **collector**:

```bash
curl -fsSL https://raw.githubusercontent.com/disnana/newrelic-chatgpt-plugin/main/ops/scylla-gate/install.sh | sudo bash
```

The installer finds the original `scylla-prometheus.yml` or `.disabled` configuration, discovers the same targets, downloads a SHA-256-pinned controller, runs a self-test, checks API and source connectivity, then deploys a systemd service. If the old integration was enabled, it only disables it after the new service has scraped data. Re-running on an installed v1.0 collector retains `/etc/newrelic-scylla-gate/config.json`, local snapshots, incident queue and ingest counters. On a failed upgrade, it attempts to restore the prior running Scylla Gate before exiting.

The installer's API probe sends a single metric; it does not transmit license keys in output. **No automatic remote deployment** is included in this pull request.

### Verify

```bash
sudo python3 /opt/newrelic-scylla-gate/gate.py --selftest
sudo python3 /opt/newrelic-scylla-gate/gate.py --summary
sudo systemctl is-active scylla-gate newrelic-infra
sudo journalctl -u scylla-gate --since '10 minutes ago' --no-pager
ls -l /etc/newrelic-infra/integrations.d/scylla-prometheus.yml*
```

On installed collectors, the separate `rollback.sh` restores the original high-ingest `nri-prometheus` integration:

```bash
sudo /opt/newrelic-scylla-gate/rollback.sh
```

### Incident behavior

- Every 30 seconds, scrape ScyllaDB and save root-only compressed Prometheus snapshots locally, up to 48 hours / 1 GiB.
- Every 120 seconds, upload only a bounded heartbeat and p95 bucket estimate, preserving critical error and reactor signals.
- On a qualifying event, upload **10 minutes before** the incident and continue until **15 minutes after the last trigger**.
- Typed CQL error triggers: `protocol_error` at 1 increment, `invalid` at 3 increments in 60 s, and typically recoverable `unprepared` at 10 increments in 60 s. Other error and timeout counters trigger on any increment. Counter resets establish a baseline rather than a false alert.
- Aggregate coordinator latency cumulative histogram differences to calculate p95 upper-bucket bounds; trigger on p95 >=100ms across two sampling windows or any definitely >500ms observation in supported buckets.
- Persistent SQLite queue retains unsent incident snapshots and incremental upload offsets across service restarts. Uploaded data is checkpointed at least once; a crash after API acceptance but before checkpoint can produce a duplicate upload. Queue entries marked `missing` or `expired` remain visible.
- A 60 MB/day and 500 MB/month **per-gate estimated uncompressed payload** cap limits this collector's sends. When blocked, snapshots remain locally until retention / New Relic's 48-hour acceptance window expires. This is **not** the account's real billing or usage cap.

### External trigger from Bot

For a Bot on the same host, call:

```bash
sudo python3 /opt/newrelic-scylla-gate/gate.py --trigger 'bot_db_timeout'
```

For a remote Bot, an authenticated, constrained notification transport must be built separately. Do not expose this collector's trigger directories or an unauthenticated HTTP endpoint to the internet.

### Configuration

`/etc/newrelic-scylla-gate/config.json` is preserved on upgrades. Default trigger settings added in v1.1 (and used if missing from an older config):

```json
{
  "error_window_seconds": 60,
  "cql_thresholds": {
    "unprepared": 10,
    "invalid": 3,
    "protocol_error": 1
  }
}
```

Advanced `--status` prints the full internal state and detailed histograms; **`--summary`** prints a short incident/queue/budget summary.

### Verification and limitations

The initial collector successfully installed on 2026-11-05 and demonstrated three-node scraping, a manually queued incident, and CQL error-triggered detail sending, as reported by its operator. v1.1 changes have regression tests run in CI; a **live v1.1 upgrade has not yet been verified**.

- A Metric API HTTP 202 confirms request acceptance, **not** all metrics ultimately ingested. Validate query results and `NrIntegrationError` to confirm ingestion.
- Historic points older than 48 hours are dropped by New Relic; local retention and account monthly ingest are separate concerns.
- A persistent budget block, upload outage, or disk cap can create `expired` / `missing` entries; the script reports rather than silently declaring them complete.
- Histogram output as gauges changes semantics from the original `nri-prometheus` metrics. NRQL/alerts may need updating; no automatic migration of dashboard queries.
- CPU steal per DB node remains the responsibility of the New Relic Infrastructure Agent.
- The new queue does not actively detect user-side Bot timeouts without Bot instrumentation.
- Source and saved snapshots may contain service/cluster labels: root-only permissions are required. Prefer SSD over microSD storage where practical.

Official New Relic docs: [Metric API data format](https://docs.newrelic.com/docs/data-apis/ingest-apis/metric-api/report-metrics-metric-api/) · [48-hour and payload limits](https://docs.newrelic.com/docs/data-apis/ingest-apis/metric-api/metric-api-limits-restricted-attributes/).
