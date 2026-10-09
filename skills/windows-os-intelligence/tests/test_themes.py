from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from osintel.model import Event
from osintel.themes import validate_theme, build_themes, store_themes
from osintel.triage import build_triage
from osintel.engineer_report import write_engineer_bundle
from osintel.store import Store
from osintel.runtime import RunSpace
from osintel.datasets import make_package, approve_package, import_package, validate_package, reprocess
import build_report

QUOTE = 'Opened: 2026-01-03. Remote connections fail on configured session hosts.'

def event(key='a'):
    return Event(key, '远程连接线索', 'compatibility', 'confirmed', 'fixture', 'P1',
                 'https://support.microsoft.com/topic/' + key, evidence=QUOTE,
                 authoritative_evidence=True, components=['RDP'], symptoms=['连接中断'])

def theme(events, key='connection-path'):
    return {'schema': 'theme-v1', 'claim_key': key, 'title': '核对连接路径',
            'risk': '特定配置的连接可能中断', 'mechanism': '会话路径异常',
            'relation': 'same-risk', 'grouping_note': '同一故障条件的原始记录',
            'event_refs': [{'event_id': e.event_id, 'fact_hash': e.fact_hash()} for e in events],
            'basis': [{'event_id': e.event_id, 'url': e.source_url, 'quote': QUOTE} for e in events],
            'scope': ['限定会话主机'], 'queue': 'verify', 'critical': True,
            'why_now': '检查更新后的会话基线', 'first_action': '记录主机版本和会话配置',
            'owner': '会话测试', 'steps': ['条件匹配后连接并记录断开情况'],
            'record': ['版本、配置和连接日志'],
            'decisions': [{'when': '条件不匹配', 'then': '记录排除依据'}],
            'evidence_state': '官方已确认，内部未知', 'source_verified': True,
            'review_note': '核对原文，不代表内部复现', 'reviewed_at': '2026-10-09T10:00:00+08:00',
            'timeline': [{'kind': 'first_signal', 'date': '2026-01-03',
                          'note': '已审阅官方记录的Opened日期',
                          'basis': [{'event_id': events[0].event_id, 'url': events[0].source_url, 'quote': QUOTE}]},
                         {'kind': 'outbreak', 'date': None, 'note': '没有规模证据'}],
            'subitems': [], 'closed': False}

class ThemeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.e = event(); self.events = {'a': self.e}
    def checked(self):
        return validate_theme(theme([self.e]), self.events)
    def bundle(self, themes):
        triage = build_triage([self.e], run_at="2026-10-09T10:00:00+08:00"); triage['themes'] = themes
        return write_engineer_bundle(self.root / 'report', [self.e], triage,
                                     '2026-09-01', '2026-09-30', ['覆盖有限'], [])
    def test_no_automatic_theme_or_engineer_action(self):
        self.bundle([]); text = (self.root / 'report/index.html').read_text()
        self.assertIn('尚无已完成', text); self.assertIn('情报分析补证据', text)
    def test_date_defaults_and_no_capture_date_inference(self):
        row = theme([self.e]); row.pop('timeline'); row.pop('subitems')
        checked = validate_theme(row, self.events)
        self.assertEqual([], checked['timeline'])
        self.bundle([checked]); text = (self.root / 'report/index.html').read_text()
        self.assertIn('最早可追溯信号：未知', text); self.assertIn('大规模爆发：未知', text)
    def test_quotation_is_bound_to_exact_source(self):
        row = theme([self.e]); row['basis'][0]['url'] += '/other'
        with self.assertRaises(ValueError): validate_theme(row, self.events)
    def test_known_date_requires_quote_and_canonical_calendar_day(self):
        for day in ('2026-02-30', '20260103', '2026-01-03'):
            row = theme([self.e]); row['timeline'][0]['date'] = day
            row['timeline'][0]['basis'] = []
            with self.assertRaises(ValueError): validate_theme(row, self.events)
    def test_outbreak_needs_explicit_scale_and_authoritative_source(self):
        row = theme([self.e]); node = deepcopy(row['timeline'][0]); node['kind'] = 'outbreak'
        row['timeline'] = [node]
        with self.assertRaises(ValueError): validate_theme(row, self.events)
        node['scale_basis'] = 'explicit-source'; self.e.authoritative_evidence = False
        row['event_refs'][0]['fact_hash'] = self.e.fact_hash()
        with self.assertRaises(ValueError): validate_theme(row, self.events)
    def test_batch_preserves_each_independent_scope_and_result(self):
        b = event('b'); events = dict(self.events, b=b); row = theme([self.e, b])
        row['relation'] = 'verification-batch'
        with self.assertRaises(ValueError): validate_theme(row, events)
        row['subitems'] = [{'event_ids': [e.event_id], 'scope': '该事件的范围',
                            'action': '分别检查', 'expected': '单独记录结果'} for e in (self.e, b)]
        self.assertEqual(2, len(validate_theme(row, events)['subitems']))
    def test_unverified_external_scope_cannot_be_engineer_ready(self):
        row = theme([self.e]); row['source_verified'] = False
        with self.assertRaises(ValueError): validate_theme(row, self.events)
        row['queue'] = 'evidence'; self.assertEqual('evidence', validate_theme(row, self.events)['queue'])
    def test_identity_and_history_survive_members_and_earlier_signal(self):
        store = Store(self.root / 'test.sqlite3', self.root / 'raw')
        store.upsert_events([self.e]); old = self.checked(); store.upsert_record('theme', old)
        b = event('b'); b.evidence = QUOTE + ' Earlier report: 2025-12-01, remote connections fail on these session hosts.'
        store.upsert_events([b]); new = theme([self.e, b])
        new['timeline'][0]['date'] = '2025-12-01'
        new['timeline'][0]['basis'] = [{'event_id':'b','url':b.source_url,'quote':b.evidence}]
        new = validate_theme(new, dict(self.events, b=b)); store.upsert_record('theme', new)
        self.assertEqual(old['id'], new['id']); self.assertEqual(2, len(store.record_history('theme', old['id'])))
        self.assertEqual('2026-01-03', store.record_history('theme', old['id'])[0]['timeline'][0]['date'])
    def test_source_revision_or_reprocess_demotes_without_erasing_timeline(self):
        row = self.checked(); self.e.status = 'resolved'
        result = build_themes([row], self.events)[0]
        self.assertTrue(result['needs_review']); self.assertEqual('evidence', result['queue'])
        self.assertEqual(row['timeline'], result['timeline'])
        self.e.status = 'confirmed'
        self.assertTrue(build_themes([row], self.events, pending={row['id']: {}})[0]['needs_review'])
    def test_overflow_bidirectional_links_and_complete_portable_archive(self):
        themes = [validate_theme(theme([self.e], 'path-' + str(i)), self.events) for i in range(6)]
        before = self.e.fact_hash(); result = self.bundle(themes)
        index = Path(result['index']).read_text(); archive = Path(result['archive']).read_text()
        self.assertIn('另有 1 项', index); self.assertIn('含 1 项重大事项', index)
        for row in themes:
            name = row['id'].split(':')[1] + '.html'
            self.assertIn(name, index); self.assertIn('topics/' + name, archive)
            self.assertIn('../archive.html#event-1', (self.root / 'report/topics' / name).read_text())
        self.assertEqual(before, Event(**json.loads((self.root / 'report/data/events.ndjson').read_text())).fact_hash())
        with zipfile.ZipFile(result['zip']) as package:
            self.assertEqual(6, len([n for n in package.namelist() if '/topics/' in n]))
        with self.assertRaises(ValueError): self.bundle(themes)
    def test_package_theme_capability_and_reprocess_lifecycle(self):
        space = RunSpace(self.root); space.ensure(); store = Store(space.db, space.root / 'data/raw')
        store.upsert_events([self.e]); coverage = {'start':'2026-01-01','end':'2026-01-31',
            'sources':['fixture'],'input_runs':['test'],'limitations':['合成测试']}
        old = make_package(store, space, 'test', 'v1', coverage); validate_package(old)
        store.upsert_record('theme', self.checked()); package = make_package(store, space, 'test', 'v2', coverage)
        self.assertEqual('theme-v1', package['manifest']['theme_schema'])
        bad = deepcopy(package); bad['manifest'].pop('theme_schema')
        with self.assertRaises(ValueError): validate_package(bad)
        target = Store(self.root / 'target.sqlite3', self.root / 'target-raw')
        import_package(target, approve_package(package, 'tester', '合成范围检查'))
        self.assertEqual(1, len(store_themes(target, [self.e])))
        taxonomy = json.loads((ROOT / 'config/risk-taxonomy.json').read_text())
        reprocess(target, taxonomy, {})
        self.assertTrue(store_themes(target, [self.e])[0]['needs_review'])
    def test_offline_rejects_mislabelled_window_without_creating_database(self):
        ndjson = self.root / 'events.ndjson'; ndjson.write_text(json.dumps(self.e.payload()))
        source = self.root / 'source.json'; source.write_text(json.dumps({'window': {'start':'2026-01-01','end':'2026-01-31'}}))
        with redirect_stdout(StringIO()):
            status = build_report.run(['--input', str(ndjson), '--source-report', str(source),
                                      '--start','2026-09-01','--end','2026-09-30','--output',str(self.root / 'output')])
        self.assertEqual(2, status); self.assertFalse((self.root / 'output').exists())
        self.assertEqual([], list(self.root.rglob('*.sqlite3')))
    def test_quiet_month_preserves_old_unclosed_theme_and_high_attention(self):
        b = event('b'); self.e.published_at = '2026-01-03'; self.e.updated_at = '2026-01-03'
        old = validate_theme(theme([self.e]), self.events)
        triage = build_triage([], run_at='2026-10-09T10:00:00+08:00'); triage['themes'] = [old]
        result = write_engineer_bundle(self.root/'quiet', [self.e,b], triage,
                                      '2026-09-01','2026-09-30',[],[])
        text = Path(result['index']).read_text()
        self.assertIn('持续事项／窗口内无可核对更新日期', text)
        self.assertEqual(1, result['summary']['uncovered_high_attention'])
        self.assertIn(old['title'], text)
    def test_baseline_rollback_hides_imported_theme_and_preserves_live_review(self):
        space = RunSpace(self.root); space.ensure(); store = Store(space.db, space.root/'data/raw')
        store.upsert_events([self.e]); coverage={'start':'2026-01-01','end':'2026-01-31',
            'sources':['fixture'],'input_runs':['test'],'limitations':['合成测试']}
        old = approve_package(make_package(store,space,'test','v1',coverage),'tester','合成核验')
        imported = self.checked(); store.upsert_record('theme',imported)
        new = approve_package(make_package(store,space,'test','v2',coverage),'tester','合成核验')
        target=Store(self.root/'target.sqlite3',self.root/'target-raw'); import_package(target,new)
        live=validate_theme(theme([self.e],'live-review'),self.events)
        target.upsert_record('theme',live); target.set_metadata('live-record-ids',{'theme':[live['id']]})
        import_package(target,old)
        self.assertEqual([live['id']],[r['id'] for r in target.records('theme')])
