from copy import deepcopy
from dataclasses import asdict
from datetime import datetime
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.model import Event
from osintel.triage import build_triage


NOW = "2026-10-02T12:00:00+08:00"


def candidate(identifier="test:one", **kwargs):
    values = {
        "event_id": identifier, "title": "待核验 Windows 线索", "event_type": "compatibility",
        "status": "reported", "source_id": "microsoft-qa", "source_tier": "P3",
        "source_url": "https://example.test/" + identifier, "confidence": 55,
        "products": ["Windows 11"], "evidence": "原文记录了具体行为；尚未在内部进行验证。",
    }
    values.update(kwargs)
    return Event(**values)


class TriageTests(unittest.TestCase):
    def test_no_environment_does_not_block_single_community_failure(self):
        event = candidate(components=["RDP"], affected_workflows=["远程会话连接"], symptoms=["连接中断"])
        result = build_triage([event], run_at=NOW)
        item = result["queue"][0]
        self.assertTrue(item["high_attention"])
        self.assertIn("用户报告", item["evidence_state"])
        self.assertEqual("未知", item["internal_applicability"]["status"])
        self.assertEqual("留档", event.alert_level)
        self.assertEqual(0, event.environment_relevance)

    def test_enterprise_failure_without_vdi_terms_has_shared_workflow(self):
        event = candidate(components=["authentication"], affected_workflows=["身份认证与登录"], symptoms=["认证或授权失败"])
        item = build_triage([event], run_at=NOW)["queue"][0]
        self.assertEqual("共性流程候选", item["external_relevance"]["label"])
        self.assertTrue(item["high_attention"])
        self.assertIn("真实调用路径", item["questions"][1])

    def test_new_feature_without_failure_can_enter_change_assessment(self):
        event = candidate(components=["authentication"], change_kinds=["新功能"], symptoms=[])
        item = build_triage([event], run_at=NOW)["queue"][0]
        self.assertEqual("change", item["category"])
        self.assertFalse(item["high_attention"])
        self.assertIn("行为", item["questions"][0])
        self.assertNotIn("复现", item["questions"][0])

    def test_released_feature_with_unknown_workflow_gets_evidence_opportunity(self):
        event = candidate(event_type="feature", components=[], affected_workflows=[], evidence="", preview=False)
        item = build_triage([event], run_at=NOW)["queue"][0]
        self.assertEqual("feature", item["direction"])
        self.assertIn("正文", item["next_action"])
        self.assertFalse(item["high_attention"])

    def test_vulnerability_impact_is_not_classified_as_observed_failure(self):
        event = candidate(event_type="vulnerability", components=["RDP"], symptoms=["崩溃或无响应"], risk_score=99)
        item = build_triage([event], run_at=NOW)["queue"][0]
        self.assertFalse(item["high_attention"])
        self.assertNotIn("来源记录了具体异常症状", " ".join(item["reasons"]))
        event.kev = {"listed": True}
        self.assertTrue(build_triage([event], run_at=NOW)["queue"][0]["high_attention"])

    def test_sitemap_is_body_collection_not_confirmed_behavior(self):
        event = candidate(event_type="feature preview", preview=True, source_id="windows-insider-sitemap", source_tier="P1", evidence="官方站点地图索引")
        item = build_triage([event], run_at=NOW)["queue"][0]
        self.assertIn("正文待核验", item["evidence_state"])
        self.assertIn("完整原文", item["questions"][0])
        self.assertIn("补正文", item["next_action"])
        event.source_id = "windows-itpro"
        event.evidence = event.title
        item = build_triage([event], run_at=NOW)["queue"][0]
        self.assertIn("正文待核验", item["evidence_state"])

    def test_weak_relation_not_promoted_by_windows_or_enterprise_alone(self):
        event = candidate(preconditions=["企业或托管环境"], roles=["guest"], risk_score=99, environment_relevance=100, action_priority=100)
        result = build_triage([event], run_at=NOW)
        self.assertEqual([], result["queue"])
        self.assertEqual(1, result["summary"]["low_signal_retained"])
        self.assertEqual(1, len(result["items"]))
        self.assertIn("不是已证明无风险", result["items"][0]["exclusion_reason"])

    def test_generated_advice_and_source_prose_not_reclassified(self):
        event = candidate(title="RDP authentication failure", recommended_action="检查克隆和加域", evidence="remote desktop image clone")
        self.assertEqual([], build_triage([event], run_at=NOW)["queue"])

    def test_input_and_config_are_not_mutated_and_internal_fit_does_not_rank(self):
        one = candidate("test:a", components=["authentication", "RDP", "RDP"], symptoms=["连接中断"], published_at="September 1, 2026")
        two = deepcopy(one)
        two.event_id = "test:b"
        two.environment_relevance, two.action_priority = 100, 100
        two.asset_matches = ["某内部组合"]
        values = [one, two]
        before = [asdict(value) for value in values]
        config = {"display_budget": 1}
        result = build_triage(values, run_at=NOW, config=config)
        self.assertEqual(before, [asdict(value) for value in values])
        self.assertEqual({"display_budget": 1}, config)
        self.assertEqual("test:a", result["queue"][0]["event_id"])
        json.dumps(result, ensure_ascii=False)

    def test_category_fairness_and_complete_overflow_accounting(self):
        security = [candidate(f"security:{i}", event_type="vulnerability", components=["RDP"], kev={"listed": True}) for i in range(20)]
        failure = candidate("failure:1", symptoms=["连接中断"], components=["RDP"])
        change = candidate("change:1", change_kinds=["默认行为变化"], components=["authentication"])
        lifecycle = candidate("lifecycle:1", event_type="lifecycle")
        weak = candidate("weak:1")
        result = build_triage(security + [failure, change, lifecycle, weak], run_at=NOW, config={"display_budget": 4})
        self.assertEqual({"failure", "change", "security", "lifecycle"}, {item["category"] for item in result["queue"]})
        self.assertEqual(24, len(result["items"]))
        self.assertEqual(20, result["summary"]["not_shown"])
        self.assertEqual(19, result["summary"]["high_attention_overflow"])
        self.assertEqual(19, len(result["high_attention_overflow_ids"]))
        self.assertTrue(result["warnings"])
        self.assertEqual(19, result["categories"]["security"]["not_shown"])

    def test_review_uses_actual_run_time_not_old_source_date_and_is_not_scheduled(self):
        event = candidate(published_at="2020-01-01", components=["RDP"], symptoms=["连接中断"])
        review = build_triage([event], run_at=NOW)["queue"][0]["review"]
        self.assertEqual("2026-10-03T04:00:00+00:00", review["suggested_at"])
        self.assertFalse(review["scheduled"])
        self.assertGreater(datetime.fromisoformat(review["suggested_at"]), datetime.fromisoformat(NOW))

    def test_multiple_index_titles_do_not_displace_high_attention_after_first_round(self):
        changes = [candidate(f"index:{i}", event_type="feature preview", preview=True, source_id="windows-insider-sitemap") for i in range(8)]
        failures = [candidate(f"failure:{i}", components=["RDP"], symptoms=["连接中断"]) for i in range(8)]
        result = build_triage(changes + failures, run_at=NOW, config={"display_budget": 4})
        self.assertEqual(1, result["categories"]["change"]["shown"])
        self.assertEqual(3, result["categories"]["failure"]["shown"])
        self.assertEqual(5, result["summary"]["high_attention_overflow"])

    def test_behavior_constraints_and_feature_indexes_have_separate_opportunities(self):
        changes = [candidate(f"index:{i}", event_type="feature preview", preview=True, source_id="windows-insider-sitemap", confidence=99) for i in range(20)]
        constraint = candidate("constraint:1", change_kinds=["安全机制收紧"], components=["authentication"], confidence=60)
        result = build_triage(changes + [constraint], run_at=NOW, config={"display_budget": 2})
        self.assertEqual({"constraint", "feature"}, {item["direction"] for item in result["queue"]})
        self.assertEqual(1, result["directions"]["constraint"]["shown"])
        self.assertEqual(19, result["directions"]["feature"]["not_shown"])

    def test_community_cannot_upgrade_itself_to_official_proof(self):
        event = candidate(components=["RDP"], symptoms=["连接中断"], confidence=100, authoritative_evidence=True,
                          evidence_review={"proof_state": "官方说明", "source_kind": "community"})
        item = build_triage([event], run_at=NOW)["queue"][0]
        self.assertIn("用户报告", item["evidence_state"])
        self.assertNotIn("官方", item["evidence_state"])

    def test_concrete_requirement_change_is_high_attention_without_failure(self):
        event = candidate(components=["authentication"], change_kinds=["前置条件变化"], symptoms=[], source_id="windows-itpro", source_tier="P1", authoritative_evidence=True)
        item = build_triage([event], run_at=NOW)["queue"][0]
        self.assertTrue(item["high_attention"])
        self.assertEqual("constraint", item["direction"])
        item = build_triage([event], run_at=NOW, config={"attention_change_kinds": []})["queue"][0]
        self.assertFalse(item["high_attention"])
        event.event_type = "known issue"
        item = build_triage([event], run_at=NOW)["queue"][0]
        self.assertEqual("constraint", item["direction"])
        self.assertTrue(item["high_attention"])

    def test_routes_and_severe_symptoms_can_be_overridden_with_generic_dimensions(self):
        event = candidate(components=["component-example"], affected_workflows=["共享业务流程"], symptoms=["示例故障"])
        self.assertEqual([], build_triage([event], run_at=NOW)["queue"])
        config = {
            "workflow_routes": [{"label": "共享业务核验", "kind": "shared", "workflows": ["共享业务流程"]}],
            "severe_symptoms": ["示例故障"],
        }
        item = build_triage([event], run_at=NOW, config=config)["queue"][0]
        self.assertTrue(item["high_attention"])
        self.assertEqual("共享业务核验", item["external_relevance"]["routes"][0]["workflow"])

    def test_zero_budget_keeps_all_items_and_high_overflow(self):
        event = candidate(components=["RDP"], symptoms=["连接中断"])
        result = build_triage([event], run_at=NOW, config={"display_budget": 0})
        self.assertEqual([], result["queue"])
        self.assertEqual(1, result["summary"]["high_attention_overflow"])
        self.assertEqual(1, result["summary"]["not_shown"])

    def test_configuration_validation_and_defaults_file(self):
        config = json.loads((ROOT / "config/triage.json").read_text())
        self.assertEqual(8, build_triage([], run_at=NOW, config=config)["summary"]["display_budget"])
        for invalid in ({"display_budget": -1}, {"display_budget": True}, {"category_order": ["security"]}, {"review_days": {"high": 0}}, {"severe_symptoms": "故障"}, {"workflow_routes": [{"label": "bad"}]}):
            with self.assertRaises(ValueError):
                build_triage([], run_at=NOW, config=invalid)
        with self.assertRaises(ValueError):
            build_triage([], run_at="2026-10-02T12:00:00")


if __name__ == "__main__":
    unittest.main()
