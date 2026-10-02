from copy import deepcopy
from datetime import date
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from osintel.cli import _dedupe
from osintel.feishu import alert_fingerprint, build_publish_plan, event_fingerprint
from osintel.http import FetchError
from osintel.model import Event, RawDocument, stable_hash
from osintel.sources import MsrcCollector, ReleaseHealthCollector, parse_msrc_document
from osintel.store import Store


class Context:
    def __init__(self, bodies):
        self.bodies = bodies
        self.urls = []

    def fetch(self, source_id, url, accept):
        self.urls.append(url)
        value = self.bodies[url]
        if isinstance(value, Exception):
            raise value
        body = json.dumps(value).encode() if isinstance(value, dict) else value.encode()
        return RawDocument(source_id, url, body, 'application/json', '2026-10-02T00:00:00Z')


class MonthlyIntegrityTests(unittest.TestCase):
    def event(self):
        return Event('test:1', 'Issue', 'vulnerability', 'confirmed', 'msrc', 'P0',
                     'https://example.test/issue', alert_level='正式告警',
                     update_details=[{'kb': ['KB5000002', 'KB5000001'], 'products': ['B', 'A'],
                                      'product_ids': ['2', '1'], 'fixed_build': '10.1'},
                                     {'kb': ['KB5000003'], 'fixed_build': '10.2'}])

    def test_collection_order_and_duplicates_do_not_change_any_fingerprint(self):
        first = self.event()
        second = deepcopy(first)
        second.update_details.reverse()
        second.update_details[-1]['kb'].reverse()
        second.update_details[-1]['products'].reverse()
        second.update_details[-1]['product_ids'].reverse()
        second.update_details.append(deepcopy(second.update_details[-1]))
        second.identifiers = {'kb': ['KB5000002', 'KB5000001', 'KB5000001']}
        first.identifiers = {'kb': ['KB5000001', 'KB5000002']}
        self.assertEqual(first.fact_hash(), second.fact_hash())
        self.assertEqual(first.record_hash(), second.record_hash())
        self.assertEqual(alert_fingerprint(first.payload()), alert_fingerprint(second.payload()))

    def test_ordered_unknown_source_timeline_is_not_sorted(self):
        event = self.event()
        event.update_details[0]['timeline'] = ['second', 'first']
        self.assertEqual(['second', 'first'], next(x for x in event.payload()['update_details'] if 'timeline' in x)['timeline'])

    def test_cvrf_container_change_alone_is_not_new_risk(self):
        first, second = self.event(), self.event()
        first.identifiers['msrc_document'] = '2026-Jun'
        second.identifiers['msrc_document'] = '2026-Jul'
        self.assertEqual(first.fact_hash(), second.fact_hash())
        self.assertNotEqual(first.record_hash(), second.record_hash())

    def test_legacy_order_baseline_does_not_add_change_or_resend_alert(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder)/'state.db', Path(folder)/'raw')
            original = self.event()
            store.upsert_events([original])
            legacy = original.fact_payload()
            legacy['update_details'].reverse()
            legacy_hash = 'fact-v4:' + stable_hash(legacy)
            with store.connect() as db:
                db.execute('UPDATE events SET fact_hash=?,content_hash=?', (legacy_hash, 'legacy-order'))
            current = self.event()
            stats = store.upsert_events([current])
            self.assertEqual(0, stats['changed'])
            self.assertIn(legacy_hash, current.fact_hash_aliases)
            with store.connect() as db:
                self.assertEqual(1, db.execute('SELECT count(*) FROM event_changes').fetchone()[0])
            payload = store.list_events()[0]
            existing = [{'record_id':'record-1', 'fields':{'事件编号':payload['event_id'],
                         '内容指纹':event_fingerprint(payload), '告警状态':'已发送',
                         '最近告警指纹':alert_fingerprint(payload, legacy_hash)}}]
            self.assertEqual([], build_publish_plan([payload], existing, ['正式告警'])['alerts'])
            existing[0]['fields']['告警状态'] = '发送中'
            pending = build_publish_plan([payload], existing, ['正式告警'])['alerts'][0]
            self.assertEqual(existing[0]['fields']['最近告警指纹'], pending['fingerprint'])
            existing[0]['fields']['告警状态'] = '已发送'
            current.status = 'resolved'
            self.assertEqual(1, store.upsert_events([current])['fact_changed'])
            changed = store.list_events()[0]
            self.assertEqual([], changed['fact_hash_aliases'])
            self.assertEqual(1, len(build_publish_plan([changed], existing, ['正式告警'])['alerts']))

    def test_backfill_cannot_move_incremental_checkpoint_backwards(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder)/'state.db', Path(folder)/'raw')
            store.source_success('msrc', '2026-09-30', 10)
            store.source_success('msrc', '2026-06-30', 12)
            self.assertEqual('2026-09-30', store.source_checkpoint('msrc'))

    def test_latest_cve_scope_does_not_reintroduce_removed_platforms(self):
        before, after = self.event(), self.event()
        before.products = ['Windows 11', 'Windows Server 2022']
        before.updated_at = '2026-06-09'
        after.products = ['Windows Server 2022']
        after.updated_at = '2026-07-15'
        self.assertEqual(['Windows Server 2022'], _dedupe([before, after])[0].products)
        self.assertEqual(['Windows Server 2022'], _dedupe([after, before])[0].products)

    def test_month_filter_preserves_all_product_pages_for_same_issue(self):
        template = """<main><h2>Issue details</h2><h3>June 2026</h3>
        <h4 id='same'>Shared issue</h4><p>Status: Resolved</p>
        <p>Opened: 2026-06-18 Resolved: {resolved}</p>
        <p>{product} KB5000001 {build}.</p></main>"""
        context = Context({'https://example.test/client':template.format(resolved='2026-06-20',product='Windows 11',build='OS Build 26100.1111'),
                           'https://example.test/server':template.format(resolved='2026-07-14',product='Windows Server 2022',build='OS Build 20348.2222')})
        config = {'release_health':[{'id':'client','product':'Windows 11','url':'https://example.test/client'},
                                   {'id':'server','product':'Windows Server 2022','url':'https://example.test/server'}]}
        june = _dedupe(ReleaseHealthCollector().collect(context,date(2026,6,1),date(2026,6,30),config).events)[0]
        july = _dedupe(ReleaseHealthCollector().collect(context,date(2026,7,1),date(2026,7,31),config).events)[0]
        self.assertEqual(2,len(july.source_references))
        self.assertEqual(june.fact_hash(),july.fact_hash())
        self.assertEqual(june.builds,july.builds)

    def document(self, cve, first, updated):
        doc = json.loads((ROOT/'tests/fixtures/sample_msrc.json').read_text())
        doc['Vulnerability'] = [doc['Vulnerability'][0]]
        doc['Vulnerability'][0].update(CVE=cve, ReleaseDate=first,
                                      RevisionHistory=[{'Date': first}, {'Date': updated, 'Description':{'Value':'Affected scope corrected'}}])
        return doc

    def test_historical_index_finds_old_cve_revision_in_later_month(self):
        prefix = 'https://api.msrc.microsoft.com/cvrf/v3.0/'
        context = Context({prefix+'updates':{'value':[{'ID':'2026-Jun','CurrentReleaseDate':'2026-08-10'},
                                                      {'ID':'2026-Jul','CurrentReleaseDate':'2026-07-15'}]},
                           prefix+'cvrf/2026-Jun': self.document('CVE-2026-11111','2026-06-09','2026-07-15'),
                           prefix+'cvrf/2026-Jul': self.document('CVE-2026-22222','2026-07-14','2026-07-15')})
        result = MsrcCollector().collect(context,date(2026,7,1),date(2026,7,31),{'target_products':['Windows 11']})
        self.assertEqual({'msrc:CVE-2026-11111','msrc:CVE-2026-22222'}, {e.event_id for e in result.events})
        self.assertFalse(result.coverage_errors)
        self.assertEqual(1,result.metrics['history_documents_selected'])

    def test_same_current_cve_has_same_fact_across_report_windows(self):
        doc = self.document('CVE-2026-11111','2026-06-09','2026-07-15')
        june = parse_msrc_document(doc,date(2026,6,1),date(2026,6,30),['Windows 11'],'raw')[0]
        july = parse_msrc_document(doc,date(2026,7,1),date(2026,7,31),['Windows 11'],'raw')[0]
        self.assertEqual(june.fact_hash(),july.fact_hash())
        self.assertEqual('2026-07-15',june.updated_at)

    def test_index_handles_supplemental_release_ids(self):
        prefix = 'https://api.msrc.microsoft.com/cvrf/v3.0/'
        context = Context({prefix+'updates':{'value':[{'ID':'2017-May-B','CurrentReleaseDate':'2017-05-08'},
                                                      {'ID':'2026-Jul-B','CurrentReleaseDate':'2026-07-20'}]},
                           prefix+'cvrf/2026-Jul':self.document('CVE-2026-11111','2026-07-14','2026-07-15'),
                           prefix+'cvrf/2026-Jul-B':self.document('CVE-2026-22222','2026-07-20','2026-07-20')})
        result = MsrcCollector().collect(context,date(2026,7,1),date(2026,7,31),{'target_products':['Windows 11']})
        self.assertFalse(result.coverage_errors)
        self.assertEqual(2,len(result.events))
        self.assertEqual(1,result.metrics['supplemental_window_documents'])

    def test_failed_history_index_keeps_month_output_but_exposes_gap(self):
        prefix = 'https://api.msrc.microsoft.com/cvrf/v3.0/'
        context = Context({prefix+'updates':FetchError(prefix+'updates','offline'),
                           prefix+'cvrf/2026-Jul':self.document('CVE-2026-22222','2026-07-14','2026-07-15')})
        result = MsrcCollector().collect(context,date(2026,7,1),date(2026,7,31),{'target_products':['Windows 11']})
        self.assertEqual(1,len(result.events))
        self.assertTrue(any('索引获取失败' in text for text in result.coverage_errors))

    def test_history_budget_truncation_is_not_reported_as_complete(self):
        prefix = 'https://api.msrc.microsoft.com/cvrf/v3.0/'
        context = Context({prefix+'updates':{'value':[{'ID':'2026-Jun','CurrentReleaseDate':'2026-07-15'},
                                                      {'ID':'2026-May','CurrentReleaseDate':'2026-07-15'}]},
                           prefix+'cvrf/2026-Jun':self.document('CVE-2026-11111','2026-06-09','2026-07-15'),
                           prefix+'cvrf/2026-Jul':self.document('CVE-2026-22222','2026-07-14','2026-07-15')})
        result = MsrcCollector().collect(context,date(2026,7,1),date(2026,7,31),
                                        {'target_products':['Windows 11'],'msrc':{'max_history_documents':1}})
        self.assertTrue(any('预算' in text for text in result.coverage_errors))


if __name__ == '__main__':
    unittest.main()
