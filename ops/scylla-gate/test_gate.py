"""Regression tests for the incident-gated Scylla collector (no network or secrets)."""
import importlib.util
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SPEC = importlib.util.spec_from_file_location('gate', Path(__file__).with_name('gate.py'))
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
CONFIG = {
    'region': 'us', 'targets': [{'id': 'n0', 'url': 'http://example.invalid:9180/metrics'}],
    'scrape_seconds': 30, 'heartbeat_seconds': 120, 'timeout_seconds': 3,
    'pre_seconds': 600, 'post_seconds': 900, 'drain_seconds': 7200,
    'retention_hours': 48, 'disk_cap_mb': 10, 'daily_upload_mb': 10,
    'monthly_upload_mb': 100, 'max_incident_batches_per_cycle': 1,
    'max_heartbeat_series_per_node': 200, 'histogram_unit': 'microseconds',
    'p95_latency_ms': 100, 'single_latency_ms': 500, 'min_latency_samples': 5,
}
NAME = 'scylla_storage_proxy_coordinator_read_latency_bucket'


def cql(unprepared=0, invalid=0, protocol_error=0):
    return '\n'.join(
        f'scylla_transport_cql_errors_total{{shard="0",type="{kind}"}} {count}'
        for kind, count in [('unprepared', unprepared), ('invalid', invalid), ('protocol_error', protocol_error)]
    ).encode()


def hist(b1000, b100000, b524288, total):
    return '\n'.join(
        f'{NAME}{{shard="0",le="{le}"}} {count}'
        for le, count in [('1000', b1000), ('100000', b100000), ('524288', b524288), ('+Inf', total)]
    ).encode()


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.original = tuple(getattr(gate, name) for name in ('DATA_PATH','SNAPSHOTS','TRIGGERS','STATE_PATH','DB_PATH'))
        gate.DATA_PATH = self.root
        gate.SNAPSHOTS = self.root / 'snapshots'
        gate.TRIGGERS = self.root / 'triggers'
        gate.STATE_PATH = self.root / 'state.json'
        gate.DB_PATH = self.root / 'uploads.sqlite3'
        gate.init_storage()
        self.db = gate.db_connect()

    def tearDown(self):
        self.db.close()
        for name, val in zip(('DATA_PATH','SNAPSHOTS','TRIGGERS','STATE_PATH','DB_PATH'), self.original):
            setattr(gate, name, val)
        self.tmp.cleanup()

    def test_parser_and_shard_aggregation(self):
        self.assertEqual(gate.read_sample('a_b{le="+Inf",shard="2"} 5'), ('a_b', {'le':'+Inf','shard':'2'}, 5.0))
        self.assertIsNone(gate.read_sample('a_b NaN'))
        p = (b'scylla_column_family_read_latency_bucket{shard="0",le="1000",cf="foo"} 3\n'
             b'scylla_column_family_read_latency_bucket{shard="1",le="1000",cf="foo"} 7')
        result = gate.aggregated_metrics(p, 'db-node', 'incident', 1000)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['value'], 10)
        self.assertEqual(result[0]['attributes']['cf'], 'foo')
        self.assertNotIn('shard', result[0]['attributes'])

    def test_cql_type_thresholds_and_reset(self):
        state = gate.read_state()
        self.assertFalse(gate.detect('n0', cql(), state, CONFIG, now=1000))
        self.assertFalse(gate.detect('n0', cql(unprepared=2, invalid=1), state, CONFIG, now=1030))
        reasons = gate.detect('n0', cql(unprepared=10, invalid=3, protocol_error=1), state, CONFIG, now=1060)
        self.assertTrue(any('type=unprepared' in x for x in reasons), reasons)
        self.assertTrue(any('type=invalid' in x for x in reasons), reasons)
        self.assertTrue(any('type=protocol_error' in x for x in reasons), reasons)
        self.assertFalse(gate.detect('n0', cql(unprepared=1,invalid=0,protocol_error=0), state, CONFIG, now=1090))
        self.assertFalse(gate.detect('n0', cql(unprepared=1,invalid=0,protocol_error=0), state, CONFIG, now=1120))
        self.assertEqual(state['prev']['n0']['scylla_transport_cql_errors_total|type=unprepared'], 1)

    def test_legacy_error_state_migration_has_no_false_alert(self):
        state = gate.read_state()
        state['prev']['n0'] = {'scylla_transport_cql_errors_total': 451}
        self.assertFalse(gate.detect('n0', cql(unprepared=433, invalid=17, protocol_error=3), state, CONFIG, now=1000))

    def test_single_long_tail_and_p95_repeated(self):
        state = gate.read_state()
        self.assertFalse(gate.detect('n0', hist(0,0,0,0), state, CONFIG, now=1000))
        # 19 fast samples and one >524 ms: p95 remains normal, but single-tail alert fires.
        reasons = gate.detect('n0', hist(19,19,19,20), state, CONFIG, now=1030)
        self.assertTrue(any('>500ms observations +1' in x for x in reasons), reasons)
        self.assertEqual(state['last_p95_ms']['n0']['read'], 1.0)
        # p95 at 100 ms for two subsequent windows.
        self.assertFalse(gate.detect('n0', hist(19,29,29,30), state, CONFIG, now=1060))
        reasons = gate.detect('n0', hist(19,39,39,40), state, CONFIG, now=1090)
        self.assertTrue(any('p95 bucket >= 100.0ms' in x for x in reasons), reasons)
        # All histogram counters decrease (Scylla restart): no false incident.
        self.assertFalse(gate.detect('n0', hist(0,0,0,0), state, CONFIG, now=1120))

    def test_durable_queue_resume_after_restart(self):
        ts = 1_790_000_000
        p = b'\n'.join(
            f'scylla_transport_cql_connections{{queue="{i}"}} 1'.encode()
            for i in range(600)
        )
        file = gate.take_snapshot(CONFIG['targets'][0], p, ts)
        state = gate.read_state()
        state.update({'incident_start':ts+100,'active_until':ts+1000,'incident_enqueued_through':0})
        gate.enqueue_incident(CONFIG, state, self.db, ts+100)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM incident_queue").fetchone()[0], 1)
        posts = []
        def fake_post(metrics, cfg, key, dry_run=False):
            if not dry_run:
                posts.extend(m['value'] for m in metrics)
            return len(json.dumps(metrics))
        with mock.patch.object(gate, 'api_post', side_effect=fake_post):
            gate.send_incident(CONFIG, state, self.db, ts+100, 'dummy')
            self.assertEqual(self.db.execute("SELECT done FROM offsets").fetchone()[0], 250)
            self.db.close()
            self.db = gate.db_connect()  # Resume with persisted checkpoint.
            gate.send_incident(CONFIG, state, self.db, ts+130, 'dummy')
            gate.send_incident(CONFIG, state, self.db, ts+160, 'dummy')
        self.assertEqual(len(posts), 600)
        self.assertEqual(self.db.execute("SELECT status FROM incident_queue").fetchone()[0], 'finished')
        self.assertEqual(self.db.execute("SELECT finished FROM offsets").fetchone()[0], 1)
        gate.enqueue_incident(CONFIG, state, self.db, ts+160)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM incident_queue").fetchone()[0], 1)
        self.assertEqual(file.exists(), True)

    def test_budget_keeps_queue_for_future_day(self):
        ts = 1_790_000_000
        gate.take_snapshot(CONFIG['targets'][0], b'scylla_transport_cql_connections 1', ts)
        state = gate.read_state()
        state.update({'incident_start':ts,'active_until':ts+100})
        gate.enqueue_incident(CONFIG, state, self.db, ts)
        cfg = dict(CONFIG, daily_upload_mb=0)
        with mock.patch.object(gate, 'api_post', side_effect=lambda metrics, cfg, key, dry_run=False: len(json.dumps(metrics))):
            gate.send_incident(cfg, state, self.db, ts, 'dummy')
        self.assertIn('budget reached', state['last_upload_error'])
        self.assertEqual(self.db.execute("SELECT status FROM incident_queue").fetchone()[0], 'pending')
        self.assertEqual(gate.usage(self.db, ts), (0,0))

    def test_expired_and_missing_snapshots_visible(self):
        old_ts, now = 1_700_000_000, 1_700_000_000 + 48 * 3600
        gate.take_snapshot(CONFIG['targets'][0], b'scylla_reactor_utilization 1', old_ts)
        state = gate.read_state()
        state.update({'incident_start':old_ts,'active_until':old_ts+1})
        gate.enqueue_incident(CONFIG,state,self.db,now)
        gate.send_incident(CONFIG,state,self.db,now,'dummy')
        self.assertEqual(self.db.execute("SELECT status FROM incident_queue").fetchone()[0], 'expired')
        # New missing snapshot still in the supported timestamp window.
        p=gate.take_snapshot(CONFIG['targets'][0],b'scylla_reactor_utilization 1',now)
        self.db.execute('INSERT INTO incident_queue(path,snapshot_ts,enqueued_at) VALUES(?,?,?)',
                        ('incident:'+p.name,now,now))
        self.db.commit()
        p.unlink()
        gate.send_incident(CONFIG,state,self.db,now,'dummy')
        self.assertEqual(self.db.execute("SELECT status FROM incident_queue WHERE path=?",('incident:'+p.name,)).fetchone()[0], 'missing')

    def test_heartbeat_derived_metric_present(self):
        state = gate.read_state()
        state['last_p95_ms'] = {'n0':{'read':13.0}}
        cfg = dict(CONFIG, max_heartbeat_series_per_node=1)
        with mock.patch.object(gate,'send_chunks') as chunks:
            gate.heartbeat(cfg,state,self.db,1000,'key',{'n0':(1000,b'scylla_reactor_utilization{shard="0"} 0.1')})
            self.assertEqual(chunks.call_args[0][0][0]['name'],'scylla_gate_coordinator_read_p95_bucket_ms')


    def test_installer_pin_matches_current_controller(self):
        import hashlib
        import re
        base = Path(__file__).parent
        installer = (base/'install.sh').read_text()
        match = re.search(r'^SHA=([a-f0-9]{64})$', installer, re.MULTILINE)
        self.assertIsNotNone(match, 'installer must pin source sha256')
        actual = hashlib.sha256((base/'gate.py').read_bytes()).hexdigest()
        self.assertEqual(match.group(1), actual, 'installer will fail at runtime if controller changes')
        self.assertIn('restore_on_exit()', installer, 'upgrades need rollback on failure')

if __name__ == '__main__':
    unittest.main(verbosity=2)
