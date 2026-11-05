#!/usr/bin/env python3
"""Local Scylla Prometheus snapshot gate for New Relic (stdlib only).

Uses the existing New Relic Infrastructure Agent license key; never logs it.
No application instrumentation or Prometheus daemon is required.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import gzip
import hashlib
import json
import math
import os
import re
import shutil
import sqlite3
import sys
import time
import uuid
from urllib.parse import urlparse
from pathlib import Path
from urllib import error, request

CONF_PATH = Path(os.environ.get('SCYLLA_GATE_CONFIG', '/etc/newrelic-scylla-gate/config.json'))
DATA_PATH = Path(os.environ.get('SCYLLA_GATE_DATA', '/var/lib/newrelic-scylla-gate'))
KEY_PATH = Path(os.environ.get('SCYLLA_GATE_AGENT_CONFIG', '/etc/newrelic-infra.yml'))
SNAPSHOTS = DATA_PATH / 'snapshots'
TRIGGERS = DATA_PATH / 'triggers'
STATE_PATH = DATA_PATH / 'state.json'
DB_PATH = DATA_PATH / 'uploads.sqlite3'
SAMPLE_NAME = re.compile(r'^[a-zA-Z_:][a-zA-Z_0-9:]*$')
LABEL = re.compile(r'\s*([a-zA-Z_][a-zA-Z_0-9]*)\s*=\s*"((?:\\.|[^"\\])*)"\s*(?:,|$)')
ENDPOINTS = {
    'us': 'https://metric-api.newrelic.com/metric/v1',
    'eu': 'https://metric-api.eu.newrelic.com/metric/v1',
    'jp': 'https://metric-api.jp.nr-data.net/metric/v1',
}
# Dimensions are intentionally bounded: do not generate a bill from arbitrary labels.
ALLOWED_LABELS = {
    'dc', 'rack', 'cluster', 'type', 'operation', 'status', 'error', 'reason',
    'keyspace', 'ks', 'cf', 'table', 'scheduling_group', 'group', 'le', 'mode',
    'shard', 'queue', 'stage', 'source', 'class', 'priority',
}
NORMAL = re.compile(
    r'^scylla_(reactor_(utilization|stalls_(sum|count))|'
    r'transport_cql_(errors_total|connections)|'
    r'storage_proxy_coordinator_(read|write)_latency_(sum|count)|'
    r'io_queue_total_(reads|writes)|scheduler_runtime_ms)$'
)
INCIDENT = re.compile(
    r'^scylla_(reactor_|storage_proxy_|column_family_.*latency|'
    r'transport_cql_|queue_|io_queue_|storage_total_|execution_stages_|'
    r'scheduler_|memory_|net_|database_|compaction_)'
)
ERROR_NAME = re.compile(r'(^scylla_transport_cql_errors_total$|^scylla_.*(?:errors_total|timeouts_total|timeout_count)$)')
HISTOGRAMS = ('scylla_storage_proxy_coordinator_read_latency_bucket',
              'scylla_storage_proxy_coordinator_write_latency_bucket')


def load_config() -> dict:
    c = json.loads(CONF_PATH.read_text(encoding='utf8'))
    assert c['region'] in ENDPOINTS
    assert 1 <= len(c['targets']) <= 12
    for t in c['targets']:
        assert t['url'].startswith(('http://', 'https://'))
    return c


def license_key() -> str:
    # An explicit env key is used for tests; deployment relies on the existing agent config.
    key = os.environ.get('NRIA_LICENSE_KEY', '').strip()
    if key:
        return key
    for f in (KEY_PATH, Path('/etc/newrelic-infra/newrelic-infra.yml')):
        if not f.exists():
            continue
        for line in f.read_text(encoding='utf8').splitlines():
            m = re.match(r'^\s*license_key:\s*(.*?)\s*(?:#.*)?$', line)
            if m and m.group(1).strip().strip('"\' '):
                return m.group(1).strip().strip('"\' ')
    raise RuntimeError('New Relic license_key not available in Infrastructure Agent config')


def init_storage() -> None:
    for p in (DATA_PATH, SNAPSHOTS, TRIGGERS):
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
        p.chmod(0o700)


def atomic_json(path: Path, payload: dict) -> None:
    tmp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(',', ':')), encoding='utf8')
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def read_state() -> dict:
    try:
        return json.loads(STATE_PATH.read_text(encoding='utf8'))
    except FileNotFoundError:
        return {'last_heartbeat': 0, 'prev': {}, 'hist': {}, 'bad_latency': {},
                'active_until': 0, 'incident_start': 0, 'last_reason': '',
                'last_scrape': 0, 'last_successes': 0, 'last_upload_error': ''}


def db_connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.execute('CREATE TABLE IF NOT EXISTS offsets (path TEXT PRIMARY KEY, done INTEGER NOT NULL DEFAULT 0, finished INTEGER NOT NULL DEFAULT 0)')
    conn.execute('CREATE TABLE IF NOT EXISTS bytes (period TEXT PRIMARY KEY, total INTEGER NOT NULL)')
    # Persistent spool: an incident is not lost when it stops firing or the process restarts.
    conn.execute("""CREATE TABLE IF NOT EXISTS incident_queue (
        path TEXT PRIMARY KEY, snapshot_ts INTEGER NOT NULL, enqueued_at INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending', error TEXT NOT NULL DEFAULT ''
    )""")
    conn.execute('CREATE INDEX IF NOT EXISTS incident_queue_status_time ON incident_queue(status, snapshot_ts)')
    conn.commit()
    return conn

def read_sample(line: str):
    if not line or line[0] == '#':
        return None
    parts = line.split(None, 1)
    if len(parts) < 2:
        return None
    key = parts[0]
    attrs = {}
    if '{' in key:
        sep = key.find('{')
        if not key.endswith('}'):
            return None
        name, labels = key[:sep], key[sep + 1:-1]
        pos = 0
        while pos < len(labels):
            m = LABEL.match(labels, pos)
            if m is None:
                return None
            v = m.group(2).replace('\\"', '"').replace('\\\\', '\\').replace('\\n', '\n')
            attrs[m.group(1)] = v
            pos = m.end()
    else:
        name = key
    if not SAMPLE_NAME.fullmatch(name):
        return None
    try:
        value = float(parts[1].split()[0])
    except (ValueError, IndexError):
        return None
    if not math.isfinite(value):
        return None
    return name, attrs, value


def scrape_one(target: dict, timeout: int):
    req = request.Request(target['url'], headers={'User-Agent': 'ScyllaGate/1.0', 'Accept-Encoding': 'identity'})
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            # Limit the uncompressed response to protect RAM and disk from unexpected payloads.
            payload = resp.read(32 * 1024 * 1024 + 1)
        if len(payload) > 32 * 1024 * 1024:
            raise RuntimeError('metrics response exceeds 32 MiB')
        if b'# HELP' not in payload and b'scylla_' not in payload:
            raise RuntimeError('metrics response did not contain Scylla metrics')
        return target, payload, None
    except Exception as exc:
        return target, None, type(exc).__name__ + ': ' + str(exc)[:160]


def take_snapshot(target: dict, payload: bytes, now: int) -> Path:
    blob = gzip.compress(payload, compresslevel=1)
    f = SNAPSHOTS / f'{now:010d}-{target["id"]}-{uuid.uuid4().hex[:8]}.prom.gz'
    tmp = f.with_suffix('.tmp')
    tmp.write_bytes(blob)
    os.chmod(tmp, 0o600)
    os.replace(tmp, f)
    return f


def bounded_label(name: str, labels: dict) -> dict:
    keep_shard = name.startswith(('scylla_reactor_', 'scylla_scheduler_', 'scylla_queue_'))
    out = {}
    for k, v in labels.items():
        if k not in ALLOWED_LABELS or (k == 'shard' and not keep_shard):
            continue
        if len(str(v)) > 150:
            continue
        out[k] = str(v)
    return out


def aggregated_metrics(payload: bytes, tid: str, mode: str, ts: int):
    """Aggregate high-cardinality histogram shards; preserve le/table/node dimensions."""
    sums = {}
    pat = NORMAL if mode == 'normal' else INCIDENT
    for line in payload.decode('utf8', 'replace').splitlines():
        obj = read_sample(line)
        if not obj:
            continue
        name, attrs, value = obj
        if not pat.search(name):
            continue
        keep = bounded_label(name, attrs)
        key = (name, tuple(sorted(keep.items())))
        if name.endswith(('_bucket', '_sum', '_count', '_total')) or ('shard' in attrs and 'shard' not in keep):
            sums[key] = sums.get(key, 0) + value
        else:
            sums[key] = value
    output = []
    for (name, labels), value in sums.items():
        attr = {'instance': tid, 'telemetry.pipeline': 'scylla-gate'}
        attr.update(dict(labels))
        output.append({'name': name, 'type': 'gauge', 'value': value,
                       'timestamp': ts * 1000, 'attributes': attr})
    return output


def event_signals(payload: bytes):
    counters = {}
    hist = {}
    for line in payload.decode('utf8', 'replace').splitlines():
        obj = read_sample(line)
        if not obj:
            continue
        name, attrs, value = obj
        if ERROR_NAME.match(name):
            # Do not mix protocol_error, invalid and usually recoverable UNPREPARED.
            kind = attrs.get('type', 'unknown')
            key = name + '|type=' + kind
            counters[key] = counters.get(key, 0) + value
        if name in HISTOGRAMS and 'le' in attrs:
            by_name = hist.setdefault(name, {})
            bound = attrs['le']
            by_name[bound] = by_name.get(bound, 0) + value
    return counters, hist

def detect(target_id: str, payload: bytes, state: dict, config: dict, now: int | None = None):
    """Trigger on typed CQL-error deltas and correct cumulative-histogram deltas.

    A large single observation can trigger independently from the p95 threshold.
    Restarted/decreased counters establish a new baseline, not an error event.
    """
    now = int(time.time()) if now is None else now
    reasons = []
    counters, hist = event_signals(payload)
    old_counters = state.setdefault('prev', {}).get(target_id, {})
    windows = state.setdefault('error_windows', {}).setdefault(target_id, {})
    window_seconds = int(config.get('error_window_seconds', 60))
    thresholds = {'unprepared': 10, 'invalid': 3, 'protocol_error': 1}
    thresholds.update(config.get('cql_thresholds', {}))
    for key, value in counters.items():
        previous = old_counters.get(key)
        delta = max(0, value - previous) if previous is not None else 0
        recent = [(t, n) for t, n in windows.get(key, []) if now - t < window_seconds]
        if delta > 0:
            recent.append((now, delta))
        windows[key] = recent[-120:]
        kind = key.split('|type=', 1)[-1]
        if key.startswith('scylla_transport_cql_errors_total|'):
            minimum = max(1, int(thresholds.get(kind, 1)))
        else:
            # Timeouts and other error counters: a single increment is significant.
            minimum = 1
        window_count = sum(n for _, n in recent)
        if delta > 0 and window_count >= minimum:
            reasons.append(f'{target_id}: {key} +{int(delta)} ({int(window_count)} in {window_seconds}s)')
    state['prev'][target_id] = counters

    old_histograms = state.setdefault('hist', {}).get(target_id, {})
    for hist_name, current in hist.items():
        old_hist = old_histograms.get(hist_name, {})
        if '+Inf' not in current or '+Inf' not in old_hist:
            continue
        total = current['+Inf'] - old_hist['+Inf']
        if total <= 0:  # No activity, or a counter reset.
            continue
        values = []
        invalid = False
        for key, value in current.items():
            if key == '+Inf':
                continue
            try:
                bound = float(key)
            except ValueError:
                continue
            if key not in old_hist or value < old_hist[key]:
                invalid = True  # Changed buckets or mixed-shard counter reset.
                break
            values.append((bound, value - old_hist[key]))
        if invalid:
            continue
        values.sort()
        kind = 'read' if '_read_' in hist_name else 'write'
        track = target_id + ':' + kind
        unit = config.get('histogram_unit', 'microseconds')
        to_ms = (lambda n: n / 1000.0) if unit == 'microseconds' else (lambda n: n * 1000.0)

        if total >= config.get('min_latency_samples', 5):
            # Histogram buckets are cumulative: find the first >= 95% of new observations.
            p95_ms = None
            for bound, cumulative_delta in values:
                if cumulative_delta >= total * .95:
                    p95_ms = to_ms(bound)
                    break
            if p95_ms is not None:
                state.setdefault('last_p95_ms', {}).setdefault(target_id, {})[kind] = round(p95_ms, 3)
                if p95_ms >= config.get('p95_latency_ms', 100):
                    n = state.setdefault('bad_latency', {}).get(track, 0) + 1
                    state['bad_latency'][track] = n
                    if n == 2 or (n > 2 and n % 5 == 0):
                        reasons.append(f'{target_id}: coordinator {kind} p95 bucket >= {p95_ms:.1f}ms ({n} checks)')
                else:
                    state.setdefault('bad_latency', {})[track] = 0

        extreme_ms = float(config.get('single_latency_ms', 500))
        # Use the first bucket ABOVE the threshold, so a tail sample is definitely > threshold.
        upper = next(((bound, cumulative_delta) for bound, cumulative_delta in values
                      if to_ms(bound) >= extreme_ms), None)
        if upper is not None and total - upper[1] > 0:
            reasons.append(f'{target_id}: coordinator {kind} >{extreme_ms:g}ms observations +{int(total - upper[1])}')
    state['hist'][target_id] = hist
    return reasons

def api_post(metrics: list, cfg: dict, key: str, dry_run: bool = False) -> int:
    body = json.dumps([{'metrics': metrics}], separators=(',', ':'), allow_nan=False).encode('utf8')
    if len(body) > 900_000:
        raise RuntimeError('Metric API batch too large before compression')
    if dry_run:
        return len(body)
    req = request.Request(ENDPOINTS[cfg['region']], data=gzip.compress(body, compresslevel=3), method='POST', headers={
        'Api-Key': key, 'Content-Type': 'application/json', 'Content-Encoding': 'gzip',
        'User-Agent': 'ScyllaGate/1.0',
    })
    with request.urlopen(req, timeout=15) as resp:
        if resp.status < 200 or resp.status >= 300:
            raise RuntimeError(f'Metric API returned HTTP {resp.status}')
    return len(body)  # Bound conservatively by uncompressed JSON bytes, not wire bytes.


def periods(ts: int):
    d = dt.datetime.fromtimestamp(ts, dt.timezone.utc)
    return ('day:' + d.strftime('%Y-%m-%d'), 'month:' + d.strftime('%Y-%m'))


def usage(conn, now: int):
    d, m = periods(now)
    return (conn.execute('SELECT COALESCE(total,0) FROM bytes WHERE period=?', (d,)).fetchone() or (0,))[0], \
           (conn.execute('SELECT COALESCE(total,0) FROM bytes WHERE period=?', (m,)).fetchone() or (0,))[0]


def budget_ok(conn, now: int, add: int, cfg: dict):
    day, month = usage(conn, now)
    return (day + add <= int(cfg['daily_upload_mb']) * 1000000 and
            month + add <= int(cfg['monthly_upload_mb']) * 1000000)


def bill(conn, now: int, n: int):
    for p in periods(now):
        conn.execute('INSERT INTO bytes(period,total) VALUES(?,?) ON CONFLICT(period) DO UPDATE SET total=total+excluded.total', (p, n))
    conn.commit()


def send_chunks(metrics: list, cfg: dict, conn, *, ident: str, now: int, key: str, max_batches: int = 999):
    """Durable per-batch checkpoints. At-least-once on crash between HTTP and sqlite commit."""
    offset_row = conn.execute('SELECT done, finished FROM offsets WHERE path=?', (ident,)).fetchone()
    if offset_row and offset_row[1]:
        return 0, True
    done = int(offset_row[0]) if offset_row else 0
    if done >= len(metrics):
        conn.execute('INSERT INTO offsets(path,done,finished) VALUES(?,?,1) ON CONFLICT(path) DO UPDATE SET finished=1', (ident, done))
        conn.commit()
        return 0, True
    batches = 0
    while done < len(metrics) and batches < max_batches:
        batch = metrics[done:done + 250]
        estimated = api_post(batch, cfg, key, dry_run=True)
        if not budget_ok(conn, now, estimated, cfg):
            raise RuntimeError('ingest budget reached; local snapshots remain available')
        n = api_post(batch, cfg, key)
        bill(conn, now, n)
        done += len(batch)
        batches += 1
        finished = 1 if done >= len(metrics) else 0
        conn.execute('INSERT INTO offsets(path,done,finished) VALUES (?,?,?) ON CONFLICT(path) DO UPDATE SET done=excluded.done,finished=excluded.finished', (ident, done, finished))
        conn.commit()
    return batches, done >= len(metrics)


def snapshots_between(start: int, end: int):
    files = []
    for f in SNAPSHOTS.glob('*.prom.gz'):
        try:
            ts = int(f.name[:10])
        except ValueError:
            continue
        if start <= ts <= end:
            files.append((ts, f))
    return sorted(files, key=lambda p: (p[0], p[1].name))


def enqueue_incident(cfg, state, conn, now: int):
    """Discover all old and future snapshots in the incident window.

    Queue entries survive restarts, idle periods and the original 2-hour drain window.
    """
    if not state.get('incident_start'):
        return
    start = int(state['incident_start']) - int(cfg.get('pre_seconds', 600))
    cutoff = min(now, int(state.get('active_until', 0)))
    if cutoff < start:
        return
    previous_scan = int(state.get('incident_enqueued_through', start - 1))
    since = max(start, previous_scan - 2 * int(cfg.get('scrape_seconds', 30)))
    rows = [('incident:' + f.name, ts, now) for ts, f in snapshots_between(since, cutoff)]
    if rows:
        conn.executemany('INSERT OR IGNORE INTO incident_queue(path,snapshot_ts,enqueued_at) VALUES (?,?,?)', rows)
        conn.commit()
    state['incident_enqueued_through'] = cutoff


def send_incident(cfg, state, conn, now: int, key: str):
    """Drain durable queued snapshots until complete, budget-blocked, expired or missing."""
    remaining_batches = int(cfg.get('max_incident_batches_per_cycle', 8))
    instances = {t['id']: urlparse(t['url']).netloc for t in cfg['targets']}
    for ident, ts in conn.execute("""SELECT path,snapshot_ts FROM incident_queue
                                    WHERE status='pending' ORDER BY snapshot_ts,path""").fetchall():
        if now - ts >= 47 * 3600:  # Keep distance from Metric API's 48h cutoff.
            conn.execute("UPDATE incident_queue SET status='expired',error='New Relic 48h ingestion window' WHERE path=?", (ident,))
            conn.commit()
            print(f'WARNING incident snapshot expired before upload: {ident}', flush=True)
            continue
        filename = ident.removeprefix('incident:')
        f = SNAPSHOTS / filename
        if not f.exists():
            conn.execute("UPDATE incident_queue SET status='missing',error='local snapshot pruned or removed' WHERE path=?", (ident,))
            conn.commit()
            print(f'WARNING incident snapshot missing: {ident}', flush=True)
            continue
        tid = filename.split('-')[1]
        try:
            payload = gzip.decompress(f.read_bytes())
            metrics = aggregated_metrics(payload, instances.get(tid, tid), 'incident', ts)
            count, complete = send_chunks(metrics, cfg, conn, ident=ident,
                                          now=now, key=key, max_batches=remaining_batches)
            remaining_batches -= count
            if complete:
                conn.execute("UPDATE incident_queue SET status='finished',error='' WHERE path=?", (ident,))
                conn.commit()
            if not complete or remaining_batches <= 0:
                state['last_upload_error'] = ''
                return
        except Exception as exc:
            state['last_upload_error'] = str(exc)[:180]
            print(f'WARNING incident upload deferred: {type(exc).__name__}: {str(exc)[:120]}', flush=True)
            return
    state['last_upload_error'] = ''

def heartbeat(cfg, state, conn, now, key, samples):
    if now - int(state.get('last_heartbeat', 0)) < int(cfg['heartbeat_seconds']):
        return
    instances = {t['id']: urlparse(t['url']).netloc for t in cfg['targets']}
    for tid, (ts, payload) in samples.items():
        instance = instances.get(tid, tid)
        metrics = aggregated_metrics(payload, instance, 'normal', ts)
        derived = []
        for kind, p95 in state.get('last_p95_ms', {}).get(tid, {}).items():
            derived.append({'name': 'scylla_gate_coordinator_' + kind + '_p95_bucket_ms',
                            'type': 'gauge', 'value': p95, 'timestamp': ts * 1000,
                            'attributes': {'instance': instance, 'telemetry.pipeline': 'scylla-gate'}})
        # Derived p95 must survive the heartbeat cardinality cap.
        metrics = (derived + metrics)[:int(cfg.get('max_heartbeat_series_per_node', 200))]
        try:
            send_chunks(metrics, cfg, conn, ident=f'heartbeat:{tid}:{ts}', now=now, key=key)
        except Exception as exc:
            state['last_upload_error'] = str(exc)[:180]
            print(f'WARNING heartbeat deferred: {type(exc).__name__}: {str(exc)[:120]}', flush=True)
            return
    state['last_heartbeat'] = now


def check_triggers(state, now, cfg):
    reasons = []
    for f in sorted(TRIGGERS.glob('*.json')):
        try:
            record = json.loads(f.read_text(encoding='utf8'))
            reasons.append('app: ' + str(record.get('reason', 'external trigger'))[:120])
            f.unlink()
        except (OSError, ValueError):
            pass
    if reasons:
        activate(state, now, reasons, cfg)


def activate(state, now, reasons, cfg):
    if not reasons:
        return
    if now > int(state.get('active_until', 0)):
        state['incident_start'] = now
        state['incident_enqueued_through'] = 0
        state['incident_id'] = str(uuid.uuid4())[:12]
    state['active_until'] = now + int(cfg['post_seconds'])
    state['pending_until'] = state['active_until'] + int(cfg.get('drain_seconds', 7200))
    state['last_reason'] = '; '.join(reasons[:6])[:300]
    print(f'INCIDENT {state["incident_id"]} {state["last_reason"]}', flush=True)


def prune(cfg, now):
    cutoff = now - int(cfg['retention_hours']) * 3600
    size_limit = int(cfg['disk_cap_mb']) * 1024 * 1024
    entries = []
    total = 0
    for f in SNAPSHOTS.glob('*.prom.gz'):
        st = f.stat()
        if st.st_mtime < cutoff:
            f.unlink(missing_ok=True)
            continue
        entries.append((st.st_mtime, f, st.st_size))
        total += st.st_size
    for _ts, f, sz in sorted(entries):
        if total <= size_limit:
            break
        f.unlink(missing_ok=True)
        total -= sz


def run_once(cfg, state, conn, key):
    now = int(time.time())
    # Capture old incident history before a new trigger resets its incident_start.
    enqueue_incident(cfg, state, conn, now)
    check_triggers(state, now, cfg)
    samples = {}
    reasons = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(cfg['targets']))) as pool:
        outcomes = list(pool.map(lambda t: scrape_one(t, int(cfg['timeout_seconds'])), cfg['targets']))
    for t, payload, err in outcomes:
        if err:
            reasons.append(f'{t["id"]}: scrape failure {err}')
            continue
        take_snapshot(t, payload, now)
        samples[t['id']] = (now, payload)
        reasons += detect(t['id'], payload, state, cfg, now=now)
    activate(state, now, reasons, cfg)
    state['last_scrape'] = now
    state['last_successes'] = len(samples)
    enqueue_incident(cfg, state, conn, now)
    prune(cfg, now)
    atomic_json(STATE_PATH, state)
    heartbeat(cfg, state, conn, now, key, samples)
    send_incident(cfg, state, conn, now, key)
    atomic_json(STATE_PATH, state)
    if not samples:
        print('WARNING all targets unreachable (saved previous local history)', flush=True)
    return len(samples)

def probe(cfg):
    key = license_key()
    outcomes = [scrape_one(t, int(cfg['timeout_seconds'])) for t in cfg['targets']]
    good = sum(p is not None for _, p, _ in outcomes)
    if not good:
        raise RuntimeError('All configured Scylla Prometheus targets failed before cutover')
    for t, p, err in outcomes:
        print(f'check {t["id"]}: {"OK" if p is not None else "UNREACHABLE"} (details withheld)')
    api_post([{'name':'scylla_gate_install_probe', 'type':'gauge', 'value':1,
               'timestamp':int(time.time()*1000),
               'attributes':{'telemetry.pipeline':'scylla-gate'}}], cfg, key)
    print('New Relic Metric API probe accepted')


def cmd_trigger(reason):
    init_storage()
    record = {'timestamp':int(time.time()), 'reason':reason[:200]}
    atomic_json(TRIGGERS / f'{record["timestamp"]}-{uuid.uuid4().hex}.json', record)
    print('Incident trigger queued')


def selftest():
    assert read_sample('scylla_x{le="+Inf",shard="2"} 5') == ('scylla_x', {'le': '+Inf', 'shard': '2'}, 5.0)
    assert read_sample('a_b 1.5') == ('a_b', {}, 1.5)
    assert read_sample('a_b{hello="a,b"} 1') == ('a_b', {'hello': 'a,b'}, 1.0)
    assert read_sample('a_b NaN') is None
    txt = b'scylla_storage_proxy_coordinator_read_latency_bucket{le="100000",shard="0"} 3\nscylla_storage_proxy_coordinator_read_latency_bucket{le="100000",shard="1"} 4\n'
    out = aggregated_metrics(txt, 'n0', 'incident', 1700000000)
    assert len(out) == 1 and out[0]['value'] == 7.0
    assert out[0]['attributes']['le'] == '100000'
    print('self-test OK')


def main():
    ap = argparse.ArgumentParser(description='Local Scylla metric gate')
    ap.add_argument('--selftest', action='store_true')
    ap.add_argument('--probe', action='store_true')
    ap.add_argument('--once', action='store_true')
    ap.add_argument('--status', action='store_true')
    ap.add_argument('--summary', action='store_true')
    ap.add_argument('--trigger', metavar='REASON')
    args = ap.parse_args()
    if args.selftest:
        selftest(); return
    if args.trigger:
        cmd_trigger(args.trigger); return
    if args.status or args.summary:
        s = read_state()
        s['budget_utc'] = {}
        if DB_PATH.exists():
            conn = db_connect()
            day, month = usage(conn, int(time.time()))
            s['queue'] = dict(conn.execute('SELECT status,COUNT(*) FROM incident_queue GROUP BY status').fetchall())
            s['budget_utc'] = {'day_uncompressed_mb':round(day/1000000,3), 'month_uncompressed_mb':round(month/1000000,3)}
        if args.summary:
            fields = ('incident_id','incident_start','active_until','last_reason','last_scrape','last_successes','last_upload_error','last_p95_ms','queue','budget_utc')
            s = {k:s.get(k) for k in fields}
        print(json.dumps(s, ensure_ascii=False, indent=2)); return
    cfg = load_config()
    if args.probe:
        probe(cfg); return
    init_storage()
    key = license_key()
    conn = db_connect()
    state = read_state()
    while True:
        started = time.monotonic()
        try:
            run_once(cfg, state, conn, key)
        except Exception as exc:
            print(f'ERROR loop: {type(exc).__name__}: {str(exc)[:150]}', flush=True)
            state['last_upload_error'] = str(exc)[:150]
            atomic_json(STATE_PATH, state)
        if args.once:
            break
        time.sleep(max(1, int(cfg['scrape_seconds']) - (time.monotonic() - started)))


if __name__ == '__main__':
    main()
