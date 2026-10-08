from contextlib import redirect_stdout, redirect_stderr
from datetime import date
from io import StringIO
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from osintel.model import Event, stable_hash
from osintel.store import Store
from osintel.runtime import RunSpace, validate_publication, reviewed_publication_input, target_fingerprint
from osintel.continuity import validate_review, build_context
from osintel.datasets import make_package, approve_package, import_package, validate_package, reprocess, write_package
from osintel.feishu import FeishuSettings
import manage
import backfill
import publish_feishu

QUOTE = 'The update enables a mandatory check during remote session authentication.'

def event(key='a', day='2026-01-03'):
    return Event(key, 'Authentication behavior changes', 'feature', 'confirmed', 'fixture', 'P1',
                 'https://support.microsoft.com/topic/' + key, published_at=day, evidence=QUOTE,
                 components=['authentication'], affected_workflows=['身份认证与登录'],
                 products=['Windows 11'], authoritative_evidence=True)

def constraint(e):
    return validate_review('constraint', {'schema':'constraint-v1','claim_key':'mandatory-check',
        'title':'远程身份检查', 'mechanism':'身份校验新增必需检查', 'before':'未检查', 'after':'必须检查',
        'status':'active','effective_at':'','products':['Windows 11'],'components':['authentication'],
        'workflows':['身份认证与登录'],'conditions':['远程连接'],'exclusions':[],
        'event_refs':[{'event_id':e.event_id,'fact_hash':e.fact_hash()}],
        'basis':[{'event_id':e.event_id,'url':e.source_url,'quote':QUOTE}], 'review_note':'已核对原文范围'},
        {e.event_id:e}, {})

def risk(a,b,c):
    return validate_review('risk', {'schema':'risk-v1','claim_key':'combined-path','title':'组合待核验',
        'mechanism':'两个检查可能在同一连接路径共同生效','status':'hypothesis', 'coexistence':'unknown',
        'coexistence_basis':'尚未核对版本与配置是否相交', 'constraint_refs':[{'id':c['id'],'revision_hash':stable_hash(c)}],
        'event_refs':[{'event_id':e.event_id,'fact_hash':e.fact_hash()} for e in (a,b)],
        'basis':[{'event_id':e.event_id,'url':e.source_url,'quote':QUOTE} for e in (a,b)],
        'missing_inputs':['共同生效版本'],'first_action':'核对两份公告支持的版本与配置范围',
        'steps':['记录两份公告的支持版本与配置，列出交集'], 'record':['版本与配置交集表'],
        'decisions':[{'when':'版本不相交','then':'记录排除依据'}], 'review_note':'外部假设，尚未执行内部测试'},
        {a.event_id:a,b.event_id:b},{c['id']:dict(c,revision_hash=stable_hash(c))})

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.project=Path(self.tmp.name); self.space=RunSpace(self.project); self.space.ensure()
        self.store=Store(self.space.db,self.space.root/'data/raw')
        self.a,self.b=event(),event('b','2026-05-05')
        self.store.upsert_events([self.a,self.b]); self.c=constraint(self.a)
        self.store.upsert_record('constraint',self.c)
    def package(self, version='v1'):
        return approve_package(make_package(self.store,self.space,'test-history',version,
            {'start':'2026-01-01','end':'2026-05-31','sources':['fixture'],'input_runs':['synthetic-test'],'limitations':['仅合成验收样例，不证明真实历史覆盖']}), 'test reviewer', '仅用于受控验收，未上传')
    def target(self):
        return Store(RunSpace(self.project,'production').db,self.project/'runtime/production/data/raw')
    def feedback(self):
        return {'schema':'feedback-v1','id':'feedback:1','subject_kind':'event','subject_id':'a',
                'subject_revision':self.a.record_hash(),'applicability':'未知','action_clear':True,
                'executed':True,'result':'样本没有复现，范围未穷尽','baseline':'lab-build','owner':'tester',
                'next_action':'补核对生产版本','recorded_at':'2026-10-08','note':'private customer name'}
    def test_trial_and_debug_are_isolated_from_production_and_legacy(self):
        prod=self.target(); prod.source_success('fixture','2026-09-01',1)
        before=prod.db_path.read_bytes(); debug=RunSpace(self.project,'debug'); debug.ensure()
        Store(debug.db,debug.root/'data/raw').upsert_events([event('debug')])
        self.store.upsert_events([event('trial')]); self.store.source_success('fixture','2026-01-01',1)
        self.assertEqual(before,prod.db_path.read_bytes()); self.assertFalse((self.project/'data').exists())
        with self.assertRaises(ValueError): self.space.input(debug.db,'')
    def test_marker_and_symlink_cannot_relabel_a_space(self):
        (self.space.root/'space.json').write_text('{"purpose":"production"}')
        with self.assertRaises(ValueError): self.space.ensure()
        (self.project/'runtime/debug').symlink_to(self.space.root)
        with self.assertRaises(ValueError): RunSpace(self.project,'debug')
    def test_four_month_candidate_survives_quiet_week_without_confirming_risk(self):
        context=build_context(self.store,[self.b]); self.assertEqual(1,context['candidate_total'])
        self.assertEqual([],context['risks']); self.assertEqual(1,build_context(self.store,[])['candidate_total'])
        self.assertFalse(context['product_tests_executed'])
    def test_three_year_old_active_constraint_is_retained(self):
        self.a.published_at='2021-01-03'; self.store.upsert_events([self.a])
        c=constraint(self.a); self.store.upsert_record('constraint',c)
        self.assertEqual(1,build_context(self.store,[self.b])['candidate_total'])
    def test_shared_dimension_without_constraint_has_explicit_gap(self):
        empty=Store(self.project/'empty.sqlite3',self.project/'raw')
        empty.upsert_events([self.a,self.b]); ctx=build_context(empty,[self.b])
        self.assertEqual([],ctx['risks']); self.assertTrue(ctx['coverage_gaps'])
    def test_quote_must_belong_to_cited_page(self):
        self.a.source_references=[{'url':'https://support.microsoft.com/topic/other','excerpt':'A completely different detailed quotation in the other source page.'}]
        row=constraint(self.a); row['basis'][0]['url']=self.a.source_references[0]['url']
        with self.assertRaises(ValueError): validate_review('constraint',row,{'a':self.a},{})
    def test_unknown_and_disjoint_cannot_be_supported(self):
        r=risk(self.a,self.b,self.c); r['status']='supported'
        with self.assertRaises(ValueError): validate_review('risk',r,{'a':self.a,'b':self.b},{self.c['id']:dict(self.c,revision_hash=stable_hash(self.c))})
        r.update(coexistence='disjoint',status='dismissed')
        self.assertEqual('dismissed',validate_review('risk',r,{'a':self.a,'b':self.b},{self.c['id']:dict(self.c,revision_hash=stable_hash(self.c))})['status'])
    def test_stable_risk_revisions_and_old_source_change_require_review(self):
        r=risk(self.a,self.b,self.c); self.store.upsert_record('risk',r)
        self.assertFalse(self.store.upsert_record('risk',r)); ctx=build_context(self.store,[])
        self.store.set_metadata('continuity-report-state',ctx['state'])
        self.assertEqual([],build_context(self.store,[])['changed_risk_ids'])
        r['mechanism']+='，新的限定'; self.store.upsert_record('risk',r)
        self.assertEqual(2,len(self.store.record_history('risk',r['id'])))
        self.a.status='resolved'; self.store.upsert_events([self.a])
        ctx=build_context(self.store,[]); self.assertTrue(ctx['risks'][0]['needs_review'])
        self.assertTrue(ctx['constraints'][0]['needs_review'])
    def test_retired_constraint_invalidates_risk_and_removes_candidate(self):
        r=risk(self.a,self.b,self.c); self.store.upsert_record('risk',r)
        self.c['status']='retired'; self.store.upsert_record('constraint',self.c)
        ctx=build_context(self.store,[self.b]); self.assertEqual(0,ctx['candidate_total']); self.assertTrue(ctx['risks'][0]['needs_review'])
    def test_feedback_keeps_result_and_flags_new_revision(self):
        f=validate_review('feedback',self.feedback(),{'a':self.a},{})
        self.store.upsert_record('feedback',f); self.a.status='resolved'; self.store.upsert_events([self.a])
        ctx=build_context(self.store,[]); self.assertTrue(ctx['feedback'][0]['needs_review'])
        self.assertEqual(f['result'],ctx['feedback'][0]['result'])
    def test_reprocess_twice_does_not_manufacture_assessment_changes(self):
        taxonomy=json.loads((ROOT/'config/risk-taxonomy.json').read_text())
        reprocess(self.store,taxonomy,{})
        self.assertEqual([],reprocess(self.store,taxonomy,{})['changes'])
    def test_missing_dataset_identity_is_rejected_before_target_creation(self):
        p=self.package(); p['manifest'].pop('dataset_id'); file=self.project/'bad.json'
        file.write_text(json.dumps(p)); workspace=self.project/'new-production'
        with redirect_stdout(StringIO()): self.assertEqual(2,manage.run(['--workspace',str(workspace),'--purpose','production','import','--input',str(file)]))
        self.assertFalse((workspace/'runtime').exists())
    def test_coverage_requires_range_input_runs_and_all_sources(self):
        p=self.package()
        for key in ('start','sources','input_runs','limitations'):
            changed=copy.deepcopy(p); changed['manifest']['coverage'].pop(key)
            with self.assertRaises(ValueError): validate_package(changed)
        p['manifest']['coverage']['sources']=['different-source']
        with self.assertRaises(ValueError): validate_package(p)
    def test_public_package_whitelist_excludes_private_feedback_and_assets(self):
        self.a.asset_matches=[{'customer':'private'}]; self.a.recommended_action='private detail'
        self.store.upsert_events([self.a]); self.store.upsert_record('feedback',self.feedback())
        package=self.package(); text=json.dumps(package)
        self.assertNotIn('private',text); self.assertNotIn('asset_matches',text)
        self.assertEqual(self.a.fact_hash(),Event(**package['data']['events'][0]).fact_hash())
    def test_debug_cannot_export_public_baseline(self):
        with self.assertRaises(ValueError): make_package(self.store,RunSpace(self.project,'debug'),'x','v1',{'limitations':['example']})
    def test_candidate_corrupt_format_and_internal_fields_are_rejected(self):
        good=self.package()
        for mutation in ('candidate','corrupt','format','internal'):
            p=copy.deepcopy(good)
            if mutation=='candidate': p['manifest']['status']='candidate'
            if mutation=='corrupt': p['data']['events'][0]['status']='unknown'
            if mutation=='format': p['manifest']['versions']['schema']='unknown'
            if mutation=='internal':
                p['data']['events'][0]['asset_matches']=[{'private':'x'}]; p['manifest']['data_sha256']=stable_hash(p['data'])
            with self.assertRaises(ValueError): validate_package(p,approved=True)
    def test_idempotent_import_does_not_advance_checkpoint_or_duplicate_events(self):
        dest=self.target(); dest.source_success('fixture','2026-10-01',1)
        p=self.package(); import_package(dest,p); import_package(dest,p)
        self.assertEqual(2,len(dest.list_events())); self.assertEqual('2026-10-01',dest.source_checkpoint('fixture'))
        self.assertEqual(1,len(dest.record_history('constraint',self.c['id'])))
    def test_preview_never_creates_target_database(self):
        path=self.project/'candidate.json'; write_package(path,self.package())
        workspace=self.project/'clean'
        with redirect_stdout(StringIO()): code=manage.run(['--workspace',str(workspace),'--purpose','production','import','--input',str(path),'--dry-run'])
        self.assertEqual(0,code); self.assertFalse((workspace/'runtime').exists())
    def test_import_rolls_back_when_derived_write_fails(self):
        dest=self.target()
        with patch.object(dest,'upsert_record',side_effect=ValueError('controlled interruption')):
            with self.assertRaises(ValueError): import_package(dest,self.package())
        self.assertEqual([],dest.list_events()); self.assertIsNone(dest.metadata('active-dataset'))
    def test_new_version_switch_and_rollback_hide_inactive_baseline_rows(self):
        dest=self.target(); p1=self.package(); import_package(dest,p1)
        self.store.upsert_events([event('c')]); p2=self.package('v2'); import_package(dest,p2)
        self.assertEqual(3,len(dest.list_events())); import_package(dest,p1)
        self.assertEqual({'a','b'},{e['event_id'] for e in dest.list_events()})
        self.assertEqual('test-history:v1',dest.metadata('active-dataset'))
    def test_local_observation_and_feedback_survive_import_and_rollback(self):
        dest=self.target(); p1=self.package(); import_package(dest,p1)
        local=event(); local.status='resolved'; dest.upsert_events([local]); dest.set_metadata('live-event-ids',['a'])
        f=self.feedback(); f['subject_revision']=local.record_hash(); dest.upsert_record('feedback',f)
        import_package(dest,p1); self.assertEqual('resolved',next(e['status'] for e in dest.list_events() if e['event_id']=='a'))
        self.assertEqual(f['result'],dest.records('feedback')[0]['result'])
    def test_published_version_and_files_are_immutable(self):
        dest=self.target(); p=self.package(); import_package(dest,p)
        changed=copy.deepcopy(p); changed['manifest']['approval']['note']='different'
        with self.assertRaises(ValueError): import_package(dest,changed)
        path=self.project/'package.json.gz'; write_package(path,p)
        with self.assertRaises(FileExistsError): write_package(path,p)
    def test_reprocess_preserves_facts_and_human_results(self):
        self.store.upsert_record('feedback',self.feedback()); before={e['event_id']:Event(**e).fact_hash() for e in self.store.list_events()}
        result=reprocess(self.store,json.loads((ROOT/'config/risk-taxonomy.json').read_text()),{})
        self.assertEqual(before,{e['event_id']:Event(**e).fact_hash() for e in self.store.list_events()})
        self.assertFalse(result['notifications_sent']); self.assertEqual(self.feedback()['result'],self.store.records('feedback')[0]['result'])
    def test_publisher_rejects_wrong_target_before_network(self):
        config=self.project/'feishu.json'; config.write_text((ROOT/'config/feishu.example.json').read_text())
        settings=FeishuSettings.load(config,require_remote=False)
        with patch.object(publish_feishu.FeishuSettings,'load',return_value=settings), patch.object(publish_feishu,'FeishuClient') as client, redirect_stderr(StringIO()):
            self.assertEqual(2,publish_feishu.run(['--workspace',str(self.project),'--purpose','debug','--target','formal','--config',str(config)]))
            client.assert_not_called()
        cfg={'publish':{'binding':{'target':'pilot','fingerprint':target_fingerprint(settings)}}}
        validate_publication(self.space,'pilot',cfg,settings)
        with self.assertRaises(ValueError): validate_publication(self.space,'formal',cfg,settings)
    def test_reviewed_publication_detects_data_changes_and_new_report(self):
        report=manage.render(self.space,self.store,'baseline')
        with redirect_stdout(StringIO()): self.assertEqual(0,manage.run(['--workspace',str(self.project),'approve-publication','--target','pilot','--reviewer','tester','--note','核对缺口','--allow-partial']))
        self.assertTrue(reviewed_publication_input(self.space,'pilot').exists())
        with self.assertRaises(ValueError): reviewed_publication_input(self.space,'pilot',send_alerts=True)
        input_path=Path(report['report_data']); original=input_path.read_bytes(); input_path.write_bytes(original+b'\n')
        with self.assertRaises(ValueError): reviewed_publication_input(self.space,'pilot')
        input_path.write_bytes(original); manage.render(self.space,self.store)
        with self.assertRaises(ValueError): reviewed_publication_input(self.space,'pilot')
    def test_risk_survives_empty_report_window_and_is_html_escaped(self):
        r=risk(self.a,self.b,self.c); r['mechanism']='<script>bad</script>'; self.store.upsert_record('risk',r)
        report=manage.render(self.space,self.store); html=Path(report['html_report']).read_text()
        self.assertIn(r['id'],html); self.assertIn('&lt;script&gt;bad&lt;/script&gt;',html)
        self.assertNotIn('<script>bad</script>',html)
    def test_reprocess_requires_semantic_review_before_new_package(self):
        self.store.upsert_record('risk',risk(self.a,self.b,self.c))
        reprocess(self.store,json.loads((ROOT/'config/risk-taxonomy.json').read_text()),{})
        ctx=build_context(self.store,[])
        self.assertTrue(ctx['risks'][0]['needs_review']); self.assertTrue(ctx['constraints'][0]['needs_review'])
        with self.assertRaises(ValueError): self.package('v2')
    def test_selected_reprocess_checks_event_ids_and_lists_field_differences(self):
        with self.assertRaises(ValueError): reprocess(self.store,{}, {},event_ids={'missing'})
        result=reprocess(self.store,json.loads((ROOT/'config/risk-taxonomy.json').read_text()),{},event_ids={'b'})
        self.assertEqual(['b'],result['scope'])
        self.assertTrue(all(not row['fact_changed'] for row in result['changes']))
    def test_unchanged_revision_cannot_hide_a_second_mechanism_candidate(self):
        r=risk(self.a,self.b,self.c); self.store.upsert_record('risk',r)
        extra=dict(self.c); extra.pop('id'); extra['claim_key']='different-path'
        extra=validate_review('constraint',extra,{'a':self.a},{})
        self.store.upsert_record('constraint',extra)
        ctx=build_context(self.store,[self.b]); self.assertEqual(1,ctx['candidate_total'])
        self.assertEqual(extra['id'],ctx['candidates'][0]['constraint_id'])
    def test_feedback_risk_invalidated_by_changed_underlying_source(self):
        r=risk(self.a,self.b,self.c); self.store.upsert_record('risk',r)
        f=self.feedback(); f.update(subject_kind='risk',subject_id=r['id'],subject_revision=stable_hash(r))
        self.store.upsert_record('feedback',f); self.a.status='resolved'; self.store.upsert_events([self.a])
        self.assertTrue(build_context(self.store,[])['feedback'][0]['needs_review'])
    def test_explicit_pending_review_can_be_cleared_only_by_review_submission(self):
        reprocess(self.store,json.loads((ROOT/'config/risk-taxonomy.json').read_text()),{})
        path=self.project/'review.json'; path.write_text(json.dumps(self.c))
        with redirect_stdout(StringIO()): self.assertEqual(0,manage.run(['--workspace',str(self.project),'review','--kind','constraint','--input',str(path)]))
        self.assertFalse(build_context(self.store,[])['constraints'][0]['needs_review'])
        self.package('v2')
    def test_feedback_export_is_explicit_private_and_does_not_touch_production(self):
        self.store.upsert_record('feedback',self.feedback()); output=self.project/'private.json'
        with redirect_stdout(StringIO()): self.assertEqual(0,manage.run(['--workspace',str(self.project),'export-feedback','--output',str(output)]))
        self.assertEqual('private',json.loads(output.read_text())['visibility'])
        self.assertFalse((self.project/'runtime/production').exists())
    def test_continuity_digest_budget_does_not_delete_risks(self):
        first=risk(self.a,self.b,self.c); self.store.upsert_record('risk',first)
        second=dict(first); second.pop('id'); second['claim_key']='another-mechanism'
        second=validate_review('risk',second,{'a':self.a,'b':self.b},{self.c['id']:dict(self.c,revision_hash=stable_hash(self.c))})
        self.store.upsert_record('risk',second)
        context=build_context(self.store,[],risk_budget=1)
        self.assertEqual(2,len(context['risks'])); self.assertEqual(1,len(context['display_risk_ids'])); self.assertEqual(1,len(context['risk_overflow_ids']))
        with self.assertRaises(ValueError): build_context(self.store,[],risk_budget=-1)
    def test_plan_only_has_correct_sources_and_does_not_create_space(self):
        workspace=self.project/'empty'; args=['--workspace',str(workspace),'--config',str(ROOT/'config/sources.json'),'--start','2026-07-01','--end','2026-09-30','--plan-only']
        with patch.object(backfill.cli,'run') as collect,redirect_stdout(StringIO()): self.assertEqual(0,backfill.run(args)); collect.assert_not_called()
        self.assertFalse((workspace/'runtime').exists())
    def test_report_partial_requires_explicit_acknowledgement(self):
        manage.render(self.space,self.store)
        with redirect_stdout(StringIO()): self.assertEqual(2,manage.run(['--workspace',str(self.project),'approve-publication','--target','pilot','--reviewer','tester','--note','checked']))
        self.assertFalse((self.space.root/'publication.json').exists())
    def test_month_chunks_and_resumable_failed_month(self):
        self.assertEqual([(date(2024,2,10),date(2024,2,29)),(date(2024,3,1),date(2024,3,3))],list(backfill.chunks(date(2024,2,10),date(2024,3,3))))
        args=['--workspace',str(self.project),'--start','2026-01-01','--end','2026-02-28','--config',str(ROOT/'config/sources.json')]
        calls=[]
        def collect(argv):
            start=argv[argv.index('--start')+1]; end=argv[argv.index('--end')+1]; calls.append(start)
            path=self.space.root/'reports'/('batch-'+str(len(calls))+'.json'); path.parent.mkdir(exist_ok=True)
            code=2 if len(calls)==1 else 0
            path.write_text(json.dumps({'window':{'start':start,'end':end},'source_coverage':[],'discovery_coverage':{'status':'not_planned'},'warnings':['not complete']}))
            self.store.set_metadata('latest-report',str(path)); return code
        with patch.object(backfill.cli,'run',side_effect=collect), redirect_stdout(StringIO()):
            self.assertEqual(2,backfill.run(args)); self.assertEqual(0,backfill.run(args))
        self.assertEqual(['2026-01-01','2026-02-01','2026-01-01'],calls)

if __name__=='__main__': unittest.main()
