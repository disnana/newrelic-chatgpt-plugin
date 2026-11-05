#!/usr/bin/env bash
# Scylla Gate v1.1.0: upgrade the existing New Relic Scylla collector.
set -Eeuo pipefail
umask 077
(( EUID == 0 )) || { echo "Run as root (sudo bash)" >&2; exit 1; }
SOURCE=/etc/newrelic-infra/integrations.d/scylla-prometheus.yml
DISABLED="$SOURCE.disabled"
APP=/opt/newrelic-scylla-gate
CFGDIR=/etc/newrelic-scylla-gate
DATADIR=/var/lib/newrelic-scylla-gate
SVC=/etc/systemd/system/scylla-gate.service
REGION="${NR_SCYLLA_REGION:-us}"
BASE=https://raw.githubusercontent.com/disnana/newrelic-chatgpt-plugin/feature/scylla-local-gate-20261105/ops/scylla-gate
SHA=fd8f0d7e31df128c80a503f39144c842a69182c44b7b505f5883fce38c7fc8a0
ACTION="${1:-install}"
log() { printf '[scylla-gate] %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
if [[ "$ACTION" == "--rollback" ]]; then
  [[ -x "$APP/rollback.sh" ]] || die 'No rollback script'
  exec "$APP/rollback.sh"
fi
[[ "$ACTION" == "install" || "$ACTION" == "--dry-run" ]] || die 'Unsupported action'
[[ "$REGION" == "us" || "$REGION" == "eu" || "$REGION" == "jp" ]] || die 'Unsupported NR_SCYLLA_REGION'
for cmd in curl python3 sha256sum systemctl df; do command -v "$cmd" >/dev/null || die "$cmd missing"; done
if [[ -f "$SOURCE" ]]; then ORIGINAL="$SOURCE"
elif [[ -f "$DISABLED" ]]; then ORIGINAL="$DISABLED"
else die "Existing Scylla config missing ($SOURCE). Original monitoring is unchanged"; fi
export ORIGINAL
TARGETS=$(python3 - <<'PY'
import os,re,json
from urllib.parse import urlsplit
src=open(os.environ['ORIGINAL'],encoding='utf-8').read()
targets=[]
for entry in re.findall(r'https?://[^\s\'"\],}]+',src):
    u=entry.rstrip(',')
    parsed=urlsplit(u)
    if parsed.hostname and parsed.path.rstrip('/')=='/metrics' and u not in targets:
        targets.append(u)
if not 1 <= len(targets) <= 12:
    raise SystemExit('Could not find 1-12 /metrics URLs in original config')
print(json.dumps([{'id':'n'+str(i),'url':u} for i,u in enumerate(targets)]))
PY
)
log "Detected $(python3 -c 'import sys,json;print(len(json.loads(sys.argv[1])))' "$TARGETS") existing targets"
if [[ "$ACTION" == "--dry-run" ]]; then
  log 'Dry-run passed; no service or config changed'
  exit 0
fi
[[ -f /etc/newrelic-infra.yml || -f /etc/newrelic-infra/newrelic-infra.yml || -n "${NRIA_LICENSE_KEY:-}" ]] || die 'Existing New Relic license key configuration not found'
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
log 'Fetching pinned Scylla Gate controller'
curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 10 --max-time 60 "$BASE/gate.py" -o "$TMP/gate.py"
printf '%s  %s\n' "$SHA" "$TMP/gate.py" | sha256sum -c --status || die 'Controller checksum mismatch, old integration unchanged'
python3 "$TMP/gate.py" --selftest
mkdir -p "$APP/backups" "$CFGDIR" "$DATADIR"
chmod 700 "$CFGDIR" "$DATADIR"
FREE=$(df -Pk "$DATADIR" | awk 'END{print $4}')
(( FREE > 1048576 )) || die 'Need at least 1GiB free for local history, existing config unchanged'
export TARGETS TMP REGION
python3 - <<'PY'
import os,json
cfg={
 'schema_version':1,
 'region':os.environ['REGION'],
 'targets':json.loads(os.environ['TARGETS']),
 'scrape_seconds':30, 'heartbeat_seconds':120, 'timeout_seconds':10,
 'pre_seconds':600,'post_seconds':900,'drain_seconds':7200,
 'retention_hours':48,'disk_cap_mb':1024,'daily_upload_mb':60,
 'monthly_upload_mb':500,'max_incident_batches_per_cycle':8,
 'max_heartbeat_series_per_node':200,'histogram_unit':'microseconds',
 'error_window_seconds':60,
 'cql_thresholds':{'unprepared':10,'invalid':3,'protocol_error':1},
 'p95_latency_ms':100,'single_latency_ms':500,'min_latency_samples':5,
}
with open(os.path.join(os.environ['TMP'],'config.json'),'w') as f:
    json.dump(cfg,f,indent=2)
PY
log 'Preflight: source metrics and actual New Relic Metric API POST'
SCYLLA_GATE_CONFIG="$TMP/config.json" SCYLLA_GATE_DATA="$TMP/data" python3 "$TMP/gate.py" --probe || die 'Preflight failed, old integration remains enabled'
BACKUP="$APP/backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP"; chmod 700 "$BACKUP"
cp -p "$ORIGINAL" "$BACKUP/scylla-prometheus.yml"
for spec in "$APP/gate.py" "$CFGDIR/config.json" "$SVC"; do
  [[ ! -f "$spec" ]] || cp -p "$spec" "$BACKUP/$(basename "$spec")"
done
OLD_GATE_ACTIVE=0
if systemctl is-active --quiet scylla-gate.service; then OLD_GATE_ACTIVE=1; fi
CUTOVER_STARTED=0
COMMITTED=0
MOVED=0
restore_on_exit() {
  local rc=$?
  trap - EXIT
  if [[ "$CUTOVER_STARTED" == 1 && "$COMMITTED" != 1 ]]; then
    echo 'Upgrade failed: restoring previous monitoring configuration' >&2
    systemctl stop scylla-gate.service || true
    [[ ! -f "$BACKUP/gate.py" ]] || install -m 0700 "$BACKUP/gate.py" "$APP/gate.py"
    [[ ! -f "$BACKUP/config.json" ]] || install -m 0600 "$BACKUP/config.json" "$CFGDIR/config.json"
    [[ ! -f "$BACKUP/scylla-gate.service" ]] || install -m 0644 "$BACKUP/scylla-gate.service" "$SVC"
    systemctl daemon-reload || true
    if [[ "$OLD_GATE_ACTIVE" == 1 ]]; then
      systemctl enable scylla-gate.service || true
      systemctl restart scylla-gate.service || true
    else
      systemctl disable --now scylla-gate.service || true
    fi
    if [[ "$MOVED" == 1 && ! -f "$SOURCE" && -f "$DISABLED" ]]; then
      mv "$DISABLED" "$SOURCE" || true
      systemctl restart newrelic-infra.service || true
    fi
  fi
  rm -rf "$TMP"
  exit "$rc"
}
trap restore_on_exit EXIT
CUTOVER_STARTED=1
install -m 0700 "$TMP/gate.py" "$APP/gate.py"
if [[ ! -f "$CFGDIR/config.json" || "${NR_SCYLLA_RESET_CONFIG:-0}" == "1" ]]; then
  install -m 0600 "$TMP/config.json" "$CFGDIR/config.json"
fi
cat > "$SVC" <<'UNIT'
[Unit]
Description=Scylla Gate: anomaly-gated Scylla metrics to New Relic
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/newrelic-scylla-gate/gate.py
Restart=always
RestartSec=10
User=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/newrelic-scylla-gate
MemoryMax=384M
Nice=10
[Install]
WantedBy=multi-user.target
UNIT
chmod 644 "$SVC"
cat > "$APP/rollback.sh" <<'ROLLBACK'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ "$EUID" == 0 ]] || { echo 'Run as root' >&2; exit 1; }
src=/etc/newrelic-infra/integrations.d/scylla-prometheus.yml
[[ ! -f "$src" ]] || { echo 'Original integration already active'; exit 0; }
[[ -f "$src.disabled" ]] || { echo 'Old configuration missing' >&2; exit 1; }
mv "$src.disabled" "$src"
systemctl disable --now scylla-gate.service || true
systemctl restart newrelic-infra.service
systemctl is-active --quiet newrelic-infra.service
echo 'Original Scylla integration restored (high ingestion may resume)'
ROLLBACK
chmod 700 "$APP/rollback.sh"
systemctl daemon-reload
systemctl enable --now scylla-gate.service >/dev/null
systemctl restart scylla-gate.service
log 'Verifying local snapshots before switching the old collector off'
READY=0
START=$(date +%s)
for i in $(seq 1 16); do
  sleep 2
  if ! systemctl is-active --quiet scylla-gate.service; then break; fi
  if python3 - "$DATADIR/state.json" "$START" <<'PY'
import json,sys
try:
  s=json.load(open(sys.argv[1]))
  assert s.get('last_scrape',0)>=int(sys.argv[2])-1
  assert s.get('last_successes',0)>0
except (OSError,ValueError,AssertionError): sys.exit(1)
PY
  then READY=1;break;fi
done
if [[ "$READY" != 1 ]]; then
  die 'Replacement did not collect any metrics; restoring previous collector'
fi

if [[ -f "$SOURCE" ]]; then
  [[ ! -e "$DISABLED" ]] || die 'Existing disabled file conflict; not overwriting it'
  mv "$SOURCE" "$DISABLED"
  MOVED=1
fi
systemctl restart newrelic-infra.service
systemctl is-active --quiet newrelic-infra.service
systemctl is-active --quiet scylla-gate.service
COMMITTED=1
log 'Installed. Original Scylla nri-prometheus integration disabled, Infra Agent retained'
log "Backup: $BACKUP"
log "Status: sudo python3 $APP/gate.py --status"
log 'Logs: sudo journalctl -u scylla-gate -f'
log "Manual trigger: sudo python3 $APP/gate.py --trigger bot_db_timeout"
log "Rollback: sudo $APP/rollback.sh"
log 'Budget applies only to Scylla Gate, not the whole New Relic account'
