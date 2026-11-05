# Scylla Gate (experimental, v1.0.0)

Replaces only the existing `scylla-prometheus.yml` New Relic integration with a bounded Python metric collection service on the **existing collector**. The Infrastructure Agent stays enabled.

## Installation

On `oracle-cloud-core` (the existing collector), run:

```bash
curl -fsSL https://raw.githubusercontent.com/disnana/newrelic-chatgpt-plugin/feature/scylla-local-gate-20261105/ops/scylla-gate/install.sh | sudo bash
```

The installer auto-discovers the Scylla `/metrics` endpoints from the original integration, downloads a SHA-256-pinned controller, checks source connectivity and New Relic Metric API acceptance, backs up the original integration, installs and tests a new systemd collector, then disables only the original Scylla integration. If preflight fails, the old collector stays active. After a failed cutover it attempts to restore the old integration.

**Tested:** local Python tests and mock endpoints. **Not yet tested:** actual cutover on the user's server. Review the shell script before execution. This is an experimental branch, not part of the read-only ChatGPT plugin runtime.

## Behavior

- 30-second local scrapes saved as compressed Prometheus text snapshots; 48-hour / 1 GiB rolling retention (whichever comes first).
- 120-second lightweight metric heartbeat to New Relic.
- On collector errors, CQL error/timeout counter increases or large coordinator read/write latency bucket changes, upload up to ten minutes of prior snapshots and continue for fifteen minutes after last detected anomaly.
- Explicit external triggers can be queued on the collector host.
- Bounded local estimated uncompressed upload JSON: 60 MB/day and 500 MB/month **for this process only**.
- Old metric type and labels may differ; check NRQL and alerts. No complete account usage enforcement.

## Verify / operate

```bash
sudo python3 /opt/newrelic-scylla-gate/gate.py --status
sudo journalctl -u scylla-gate --since '30 minutes ago' --no-pager
sudo python3 /opt/newrelic-scylla-gate/gate.py --trigger 'bot_db_timeout'
sudo /opt/newrelic-scylla-gate/rollback.sh
```

## Limitations

- The bot process cannot be automatically observed unless its own timeout/error handler calls the trigger command or exports a machine-readable signal. Scylla-side errors and latency work automatically.
- OS CPU steal per database node must still be observed through the Infrastructure Agent, not this collector.
- Detection of a single latency outlier is approximate: aggregated histogram buckets cannot prove a single 500 ms sample without an appropriate threshold-specific difference calculation.
- Gate byte budget does not control other New Relic integrations. Already ingested data cannot be retracted.
- Local storage and network load should be monitored; use SSD rather than SD card when feasible.
- Local snapshots contain metric labels and may reveal internal paths or services. Files are root-only.
- The installer assumes the existing integration path `/etc/newrelic-infra/integrations.d/scylla-prometheus.yml`. If not present, it exits without changes.
- The new Metric API stream uses gauge samples instead of the old Prometheus metric types. Previously saved queries may need updating.
- The temporary preflight sends one probe metric to the user's New Relic account.

New Relic docs:
- [Metric API](https://docs.newrelic.com/docs/data-apis/ingest-apis/metric-api/report-metrics-metric-api/)
- [48-hour timestamp window](https://docs.newrelic.com/docs/data-apis/ingest-apis/metric-api/metric-api-limits-restricted-attributes/)
