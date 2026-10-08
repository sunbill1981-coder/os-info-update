from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.model import Event
from osintel.verification import build_verification_plan, validate_verification_plan


def event(**kwargs):
    values = dict(
        event_id="fixture:verification", title="应用在特定设置下无法启动", event_type="known issue",
        status="reported", source_id="microsoft-qa", source_tier="P3", source_url="https://example.test/source",
        published_at="2026-09-11", products=["Windows 11, version 25H2"], builds=["26200.100"],
        components=["application compatibility"], affected_workflows=["应用启动与兼容"],
        symptoms=["应用可能无法启动"], evidence="Source specifies a named application and its managed-device configuration.",
        preconditions=["企业或托管环境"], affected_scope={
            "applications": ["Fabrikam Viewer"], "cpu_architectures": ["ARM64"],
            "conditions": [{"id": "setting", "label": "来源点名的托管设置开启"}],
            "exclusions": [{"label": "Fabrikam Writer", "certainty": "not_known_affected"}],
        },
    )
    values.update(kwargs)
    return Event(**values)


def reviewed_event(**kwargs):
    kwargs.setdefault("evidence_review", {"source_kind": "community", "scope_verified": True,
                                         "scope_basis": "已逐项核对本事件原始主帖的版本、配置与排除边界；用户观察未独立复现。"})
    return event(**kwargs)


class VerificationTests(unittest.TestCase):
    def test_nonempty_quote_and_scope_extraction_are_not_a_scope_review(self):
        value = event(authoritative_evidence=True, source_tier="P0")
        result = build_verification_plan(value, category="failure", body_missing=False)
        self.assertEqual("情报分析", result["owner"])
        self.assertEqual("待补外部证据", result["status"])
        self.assertIn("Windows 11, 版本 25H2", result["first_action"])
        self.assertIn("26200.100", result["first_action"])
        self.assertTrue(any("自动提取" in item for item in result["missing_inputs"]))
        self.assertTrue(any("完整原文" in item for item in result["steps"]))
        self.assertFalse(result["executed"])

    def test_display_localizes_version_and_does_not_expose_title_or_internal_field_names(self):
        value = event(title="Fabrikam Viewer fails after a configuration change",
                      products=["Windows 11 Version 24H2", "Windows 11, version 25H2"],
                      update_details=[{"products": ["Windows 11 Version 24H2"], "fixed_build": "26100.200", "fix_scope": "complete"}])
        original_products = list(value.products)
        result = build_verification_plan(value, category="failure", body_missing=False)
        self.assertNotIn(value.title, result["first_action"])
        self.assertIn("Windows 11 版本 24H2", result["first_action"])
        self.assertIn("Windows 11, 版本 25H2", " ".join(result["scope"]))
        self.assertNotIn("Version", " ".join(result["scope"]))
        self.assertNotIn("version", " ".join(result["scope"]))
        self.assertNotIn("scope_verified", " ".join(result["steps"]))
        self.assertNotIn("scope_basis", " ".join(result["steps"]))
        self.assertIn("保存范围核验结论与原文依据", " ".join(result["steps"]))
        self.assertEqual(original_products, value.products)

    def test_missing_body_or_date_routes_back_to_analysis_even_with_review_flag(self):
        for value, body_missing in ((reviewed_event(), True), (reviewed_event(published_at=None), False),
                                    (reviewed_event(evidence=""), False),
                                    (reviewed_event(evidence="应用在特定设置下无法启动"), False)):
            with self.subTest(body_missing=body_missing, published=value.published_at, evidence=value.evidence):
                result = build_verification_plan(value, category="failure", body_missing=body_missing)
                self.assertEqual("情报分析", result["owner"])
                self.assertFalse(result["scope_verified"])

    def test_unprofiled_reviewed_community_report_can_check_scope_without_confirming_impact(self):
        value = reviewed_event()
        before = asdict(value)
        result = build_verification_plan(value, category="failure", body_missing=False)
        self.assertEqual("产品研发或测试", result["owner"])
        self.assertEqual("未知", result["internal_applicability"])
        self.assertIn("匹配、不匹配或未知", result["first_action"])
        self.assertTrue(any("隔离测试环境" in item for item in result["steps"]))
        self.assertTrue(any("应用启动与兼容" in item for item in result["steps"]))
        self.assertTrue(any("Fabrikam Viewer" in item for item in result["scope"]))
        self.assertTrue(any("不作绝对排除" in item for item in result["scope"]))
        self.assertEqual(before, asdict(value))
        self.assertNotIn("加域", " ".join(result["steps"]))
        self.assertNotIn("并发", " ".join(result["steps"]))
        json.dumps(result, ensure_ascii=False)

    def test_fix_status_preserves_product_boundary_and_does_not_infer_from_identifiers(self):
        value = reviewed_event(status="resolved", identifiers={"kb": ["KB1000000", "KB2000000"]}, update_details=[
            {"products": ["Windows 11, version 25H2"], "fixed_kb": ["KB2000000"], "fixed_build": "26200.200", "fix_scope": "partial"},
        ])
        result = build_verification_plan(value, category="failure", body_missing=False)
        scope = " ".join(result["scope"])
        self.assertIn("部分修复", scope)
        self.assertIn("来源报告已解决，待核验", scope)
        self.assertIn("26200.200", scope)
        self.assertNotIn("KB1000000", scope)
        self.assertIn("不等于内部已修复", scope)
        value.update_details = []
        self.assertIn("不能当作修复清单", " ".join(build_verification_plan(value, category="failure", body_missing=False)["scope"]))
        value.authoritative_evidence = True
        self.assertIn("官方已发布修复", " ".join(build_verification_plan(value, category="failure", body_missing=False)["scope"]))

    def test_security_plan_checks_exposure_and_fix_without_failure_experiment(self):
        value = reviewed_event(event_type="vulnerability", components=["networking"], symptoms=["崩溃或无响应"])
        result = build_verification_plan(value, category="security", body_missing=False)
        self.assertTrue(any("攻击/暴露前提" in item for item in result["steps"]))
        self.assertTrue(any("不运行漏洞利用" in item for item in result["steps"]))
        self.assertFalse(any("启动原文点名的应用" in item for item in result["steps"]))
        self.assertFalse(any("来源症状" in row["when"] for row in result["decisions"]))

    def test_reviewed_security_plan_without_workflow_is_preserved_but_unreviewed_still_needs_evidence(self):
        value = reviewed_event(event_type="vulnerability", components=[], affected_workflows=[], symptoms=[])
        plan = build_verification_plan(value, category="security", body_missing=False)
        self.assertEqual("产品研发或测试", plan["owner"])
        plan["first_action"] = "按来源已核实的产品修复关系，对照现有产品基线的补丁覆盖。"
        value.evidence_review["verification_plan"] = deepcopy(plan)
        result = build_verification_plan(value, category="security", body_missing=False)
        self.assertEqual(plan["first_action"], result["first_action"])
        self.assertEqual("未知", result["internal_applicability"])
        self.assertFalse(result["executed"])
        value.evidence_review = {}
        unreviewed = build_verification_plan(value, category="security", body_missing=False)
        self.assertEqual("情报分析", unreviewed["owner"])
        self.assertEqual("待补外部证据", unreviewed["status"])
        self.assertTrue(any("外部适用范围" in item for item in unreviewed["missing_inputs"]))

    def test_lifecycle_can_check_product_scope_without_workflow_but_failure_cannot(self):
        value = reviewed_event(event_type="lifecycle", components=[], affected_workflows=[], symptoms=[])
        lifecycle = build_verification_plan(value, category="lifecycle", body_missing=False)
        self.assertEqual("产品研发或测试", lifecycle["owner"])
        self.assertFalse(any("具体组件或操作流程" in item for item in lifecycle["missing_inputs"]))
        failure = build_verification_plan(value, category="failure", body_missing=False)
        self.assertEqual("情报分析", failure["owner"])
        self.assertTrue(any("具体组件或操作流程" in item for item in failure["missing_inputs"]))

    def test_feature_without_symptom_compares_declared_behavior_not_an_invented_failure(self):
        value = reviewed_event(event_type="feature", symptoms=[], change_kinds=["新功能"])
        result = build_verification_plan(value, category="change", body_missing=False)
        self.assertTrue(any("新旧行为差异" in item for item in result["steps"]))
        self.assertFalse(any("完整回归" in item for item in result["steps"]))
        self.assertTrue(any("兼容差异" in row["when"] for row in result["decisions"]))

    def test_lifecycle_has_support_decision_without_blanket_test_suite(self):
        result = build_verification_plan(reviewed_event(event_type="lifecycle"), category="lifecycle", body_missing=False)
        self.assertTrue(any("支持截止条件" in item for item in result["steps"]))
        self.assertFalse(any("隔离测试环境" in item for item in result["steps"]))
        self.assertTrue(any("迁移负责人" in item for item in result["record"]))

    def test_workflow_mapping_is_configurable_and_only_matches_source_workflow(self):
        config = {"workflow_actions": {"定制工作流": "执行来源描述的单个动作并留存结果。", "其它流程": "不应该出现的动作"}}
        with patch("osintel.verification.CONFIG", config):
            result = build_verification_plan(reviewed_event(affected_workflows=["定制工作流"]), category="failure", body_missing=False)
        self.assertIn("执行来源描述的单个动作并留存结果。", result["steps"])
        self.assertNotIn("不应该出现的动作", result["steps"])
        self.assertNotIn("应用启动与兼容", " ".join(result["steps"]))

    def test_semantic_plan_is_copied_and_cannot_certify_internal_impact(self):
        value = reviewed_event()
        plan = build_verification_plan(value, category="failure", body_missing=False)
        plan["first_action"] = "核对来源指定的实际配置与当前测试版本。"
        plan["internal_applicability"] = "已受影响"
        value.evidence_review["verification_plan"] = deepcopy(plan)
        result = build_verification_plan(value, category="failure", body_missing=False)
        self.assertEqual(plan["first_action"], result["first_action"])
        self.assertEqual("未知", result["internal_applicability"])
        result["steps"].append("modified")
        result["basis"][0]["label"] = "modified"
        self.assertEqual(plan, value.evidence_review["verification_plan"])

    def test_validator_rejects_bad_types_executed_or_unrelated_provenance(self):
        value = reviewed_event()
        plan = build_verification_plan(value, category="failure", body_missing=False)
        cases = [dict(schema="unknown"), dict(executed=True), dict(steps=[]), dict(first_action=""),
                 dict(scope="not a list"), dict(basis=[{"label": "unrelated", "url": "https://other.test"}]),
                 dict(decisions=[{"when": "matched"}]), dict(scope_verified=False), dict(scope_basis=""),
                 dict(owner="已执行"), dict(status="已复现"), dict(suggested_role=""), dict(suggested_role=5)]
        for replacement in cases:
            with self.subTest(replacement=replacement):
                with self.assertRaises(ValueError):
                    validate_verification_plan(dict(plan, **replacement), value)
        value.source_references = [{"url": "https://example.test/supplement"}]
        plan["basis"].append({"label": "补充依据", "url": "https://example.test/supplement"})
        plan["suggested_role"] = "负责该流程的测试工程师"
        self.assertEqual(2, len(validate_verification_plan(plan, value)["basis"]))
        self.assertEqual(plan["suggested_role"], validate_verification_plan(plan, value)["suggested_role"])

    def test_reviewed_semantic_plan_cannot_override_missing_body_gate(self):
        value = reviewed_event()
        value.evidence_review["verification_plan"] = build_verification_plan(value, category="failure", body_missing=False)
        result = build_verification_plan(value, category="failure", body_missing=True)
        self.assertEqual("情报分析", result["owner"])
        self.assertNotEqual(value.evidence_review["verification_plan"]["first_action"], result["first_action"])

    def test_all_unknown_scope_still_produces_specific_evidence_action_not_fake_environment(self):
        value = event(products=[], builds=[], affected_scope={}, preconditions=[], components=[], affected_workflows=[],
                      published_at=None, evidence="", source_url="")
        result = build_verification_plan(value, category="change", body_missing=True)
        self.assertEqual("情报分析", result["owner"])
        self.assertGreaterEqual(len(result["missing_inputs"]), 5)
        self.assertIn("未明确", " ".join(result["scope"]))
        self.assertFalse(result["executed"])
        self.assertFalse(any("隔离测试环境" in step for step in result["steps"]))


if __name__ == "__main__":
    unittest.main()
