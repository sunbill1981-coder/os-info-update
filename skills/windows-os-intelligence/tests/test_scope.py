from datetime import date
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.assessment import assess_event
from osintel.cli import _dedupe
from osintel.guidance import build_cloud_desktop_guidance
from osintel.feishu import alert_fingerprint
from osintel.model import Event
from osintel.patches import phase_tests
from osintel.scope import extract_scope, review_applicability
from osintel.sources import parse_release_health
from osintel.store import Store

TAXONOMY = json.loads((ROOT / "config/risk-taxonomy.json").read_text(encoding="utf-8"))


def issue(**kwargs):
    defaults = dict(event_id="release-health:scope-fixture", title="Microsoft Teams might fail to launch on ARM-based devices",
                    event_type="known issue", status="resolved", source_id="release-health", source_tier="P0",
                    source_url="https://example.test/issue", products=["Windows 11, version 24H2"], roles=["guest"],
                    components=["application compatibility", "image/recovery"], affected_workflows=["桌面镜像与交付", "应用启动与兼容"],
                    evidence="Microsoft Teams might fail to launch on ARM-based devices. Classic Outlook, Word and Excel are not known to be affected.", risk_score=82)
    defaults.update(kwargs)
    return Event(**defaults)


def baseline(cpu=None, apps=None, **kwargs):
    group = {"name": "测试基线", "products": ["Windows 11, version 24H2"], "roles": ["guest"]}
    if cpu is not None:
        group["cpu_architectures"] = cpu
    if apps is not None:
        group["applications"] = apps
    group.update(kwargs)
    return {"asset_groups": [group]}


class ScopeTests(unittest.TestCase):
    def test_arm_scope_and_hedged_exclusion_are_preserved(self):
        scope = extract_scope(issue())
        self.assertEqual(["ARM"], scope["cpu_architectures"])
        self.assertEqual(["Microsoft Teams"], scope["applications"])
        self.assertTrue(scope["cpu_scope_known"])
        self.assertEqual("not_known_affected", scope["exclusions"][0]["certainty"])
        self.assertTrue(all(item["url"] == "https://example.test/issue" for item in scope["evidence"]))

    def test_explicit_x64_exclusion_is_not_an_affected_architecture(self):
        event = issue(evidence="ARM devices can fail to launch Teams. x64 devices are not affected.")
        scope = extract_scope(event)
        self.assertNotIn("x64", scope["cpu_architectures"])
        self.assertEqual("explicit", scope["exclusions"][0]["certainty"])

    def test_incidental_architecture_in_workaround_does_not_set_scope(self):
        scope = extract_scope(issue(title="Windows issue", evidence="For an x64 diagnostic package, visit the support page."))
        self.assertEqual([], scope["cpu_architectures"])
        self.assertFalse(scope["cpu_scope_known"])

    def test_generic_64_bit_is_not_assumed_x64(self):
        self.assertEqual([], extract_scope(issue(title="64-bit devices might fail", evidence=""))["cpu_architectures"])

    def test_msrc_mixed_unspecified_product_cannot_exclude_architecture(self):
        event = issue(event_type="vulnerability", title="Windows vulnerability", evidence="", products=["Windows 11 for x64-based Systems", "Windows Server 2022"])
        scope = extract_scope(event)
        self.assertEqual(["x64"], scope["cpu_architectures"])
        self.assertFalse(scope["cpu_scope_known"])
        event.affected_scope = scope
        self.assertEqual("未知", review_applicability(event, baseline(["ARM64"], products=["Windows Server 2022"]))["status"])

    def test_named_application_grammar_is_not_incident_specific(self):
        event = issue(title="Fabrikam Viewer might fail to launch on x64 devices", evidence="")
        scope = extract_scope(event)
        self.assertEqual(["Fabrikam Viewer"], scope["applications"])
        self.assertEqual(["x64"], scope["cpu_architectures"])
        self.assertEqual([], extract_scope(issue(title="Some applications might fail to launch", evidence=""))["applications"])

    def test_delivery_architecture_is_not_cpu(self):
        self.assertEqual("未知", review_applicability(issue(), baseline(delivery_architectures=["VDI"]))["status"])
        self.assertEqual("未知", review_applicability(issue(), baseline(["VDI"], ["Microsoft Teams"]))["status"])

    def test_architecture_is_matched_per_product_not_global_union(self):
        event = issue(event_type="vulnerability", title="Windows vulnerability", evidence="", products=["Windows 11, version 24H2 for ARM64-based Systems", "Windows Server 2022 for x64-based Systems"])
        self.assertEqual("不匹配", review_applicability(event, baseline(["x64"]))["status"])
        self.assertEqual("匹配", review_applicability(event, baseline(["ARM64"]))["status"])

    def test_application_aliases_can_use_official_english_names(self):
        event = issue(title="New Outlook might fail to launch on ARM devices", evidence="")
        self.assertEqual("匹配", review_applicability(event, baseline(["ARM64"], ["new Outlook for Windows"]))["status"])

    def test_unknown_baseline_is_not_a_match(self):
        self.assertEqual("未知", review_applicability(issue(), {"scope_type": "product_portfolio", "delivery_architectures": ["VDI"], "asset_groups": []})["status"])
        self.assertEqual("未知", review_applicability(issue(), baseline())["status"])

    def test_matching_nonmatching_and_unknown_baselines(self):
        event = issue()
        self.assertEqual("匹配", review_applicability(event, baseline(["ARM64"], ["Microsoft Teams"]))["status"])
        self.assertEqual("不匹配", review_applicability(event, baseline(["x64"], ["Microsoft Teams"]))["status"])
        self.assertEqual("不匹配", review_applicability(event, baseline(["ARM64"], []))["status"])
        self.assertEqual("未知", review_applicability(event, baseline(["ARM64"]))["status"])

    def test_likelihood_and_workaround_conditions_are_not_exclusion_gates(self):
        event = issue(evidence="Teams might fail to launch on ARM devices. This is more likely on freshly imaged PCs without Store updates.")
        event.affected_scope = extract_scope(event)
        self.assertEqual(2, len(event.affected_scope["conditions"]))
        env = baseline(["ARM64"], ["Microsoft Teams"], scope_conditions={"fresh_image": False, "store_app_updates": False})
        self.assertEqual("未知", review_applicability(event, env)["status"])

    def test_app_guidance_does_not_claim_clone_or_domain_failure(self):
        event = issue()
        guidance = build_cloud_desktop_guidance(event, {"scope_type": "product_portfolio", "delivery_architectures": ["VDI"]})
        self.assertIn("ARM", guidance.problem_summary)
        self.assertIn("Microsoft Teams", guidance.problem_summary)
        self.assertIn("未发现已知影响", guidance.problem_summary)
        self.assertNotIn("克隆或池扩容可能失败", "".join(guidance.potential_impacts))
        self.assertNotIn("加域", "".join(guidance.recommended_tests))
        self.assertIn("公开 CPU", "".join(guidance.recommended_tests))

    def test_patch_stage_tests_remain_within_application_scope(self):
        event = issue(update_details=[{"relationship": "update_regression", "introduced_kb": ["KB5000000"], "products": ["Windows 11"], "source_url": "https://example.test/issue"}])
        values = phase_tests(event)
        self.assertEqual(3, len(values))
        self.assertTrue(all("ARM" in action and "指定应用" in action for _, action in values))
        self.assertNotIn("持续会话", "".join(action for _, action in values))

    def test_scope_backfill_does_not_change_fact_fingerprint_or_score(self):
        event = issue()
        before = event.fact_hash()
        assess_event(event, TAXONOMY, {})
        self.assertEqual(before, event.fact_hash())
        score = (event.risk_score, event.environment_relevance, event.action_priority)
        assess_event(event, TAXONOMY, {})
        self.assertEqual(score, (event.risk_score, event.environment_relevance, event.action_priority))

    def test_scope_update_is_an_assessment_change_not_fact_change(self):
        event = issue()
        before_alert = alert_fingerprint(event.payload())
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "state.sqlite3", Path(folder) / "raw")
            store.upsert_events([event])
            event.affected_scope = extract_scope(event)
            event.applicability_review = review_applicability(event, {})
            stats = store.upsert_events([event])
            self.assertEqual(0, stats["fact_changed"])
            self.assertEqual(1, stats["assessment_changed"])
            self.assertEqual(before_alert, alert_fingerprint(event.payload()))

    def test_full_issue_scope_survives_evidence_truncation(self):
        html = '<main><h2>Issue details</h2><h3>September 2026</h3><h4 id="scope">Application problem</h4><p>Opened: 2026-09-01</p><p>' + "Padding. " * 200 + '</p><p>Microsoft Teams might fail to launch on ARM devices.</p></main>'
        event = parse_release_health(html, "win11", "https://example.test/health", "Windows 11", date(2026, 9, 1), date(2026, 9, 30), "raw")[0]
        self.assertNotIn("ARM", event.evidence)
        self.assertEqual(["ARM"], event.affected_scope["cpu_architectures"])

    def test_dedupe_preserves_per_page_scope_evidence(self):
        first, second = issue(), issue(source_url="https://example.test/other")
        first.affected_scope = extract_scope(first)
        second.affected_scope = extract_scope(second)
        merged = _dedupe([first, second])[0]
        self.assertEqual({"https://example.test/issue", "https://example.test/other"}, {value["url"] for value in merged.affected_scope["evidence"]})


if __name__ == "__main__":
    unittest.main()
