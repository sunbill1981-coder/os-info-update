from datetime import date
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.model import Event
from osintel.patches import patch_rows, risk_phase, phase_tests
from osintel.sources import parse_release_health, parse_msrc_document
from osintel.report import _html_event_card


class PatchStageTests(unittest.TestCase):
    def health(self, product="Windows Server 2022", partial=False):
        resolution = "partially resolved" if partial else "resolved"
        html = f"""<main><h2>Issue details</h2><h3>August 2026</h3>
        <h4 id='sample-issue'>Remote Desktop Services can stop responding</h4>
        <table><tr><th>Status</th><th>Originating update</th><th>History</th></tr>
        <tr><td>{'Mitigated' if partial else 'Resolved'} KB5000002</td>
        <td>OS Build 20348.1234 KB5000001</td>
        <td>Opened: 2026-08-20 Last updated: 2026-08-25</td></tr></table>
        <p>After installing KB5000001, Remote Desktop Services can stop responding.</p>
        <p>Workaround: use Known Issue Rollback KB5000003.</p>
        <p>Resolution: This issue is {resolution} by KB5000002.</p></main>"""
        return parse_release_health(html, "sample", "https://example.test/health", product,
                                    date(2026, 8, 1), date(2026, 8, 31), "raw")[0]

    def test_roles_keep_origin_fix_and_mitigation_separate(self):
        event = self.health()
        row = patch_rows(event)[0]
        self.assertEqual(["KB5000001"], row["introduced_kb"])
        self.assertEqual(["KB5000002"], row["fixed_kb"])
        self.assertEqual(["KB5000003"], row["mitigation_kb"])
        self.assertEqual("complete", row["fix_scope"])
        self.assertEqual("regression", risk_phase(event)[0])

    def test_partial_fix_is_not_a_complete_resolution(self):
        event = self.health(partial=True)
        self.assertEqual("partial", patch_rows(event)[0]["fix_scope"])
        self.assertIn("剩余症状", phase_tests(event)[2][1])
        self.assertIn("部分修复", _html_event_card(event, 1, set()))

    def test_version_pairs_and_direct_citations_survive_merge(self):
        event = self.health()
        other = dict(event.update_details[0], products=["Windows Server 2019"],
                     introduced_kb=["KB5000011"], fixed_kb=["KB5000012"],
                     source_url="https://example.test/server2019#sample-issue")
        event.update_details.append(other)
        rows = patch_rows(event)
        self.assertEqual(["KB5000011"], rows[0]["introduced_kb"])
        self.assertEqual(["KB5000002"], rows[1]["fixed_kb"])
        html = _html_event_card(event, 1, set())
        self.assertIn('data-phase="regression"', html)
        self.assertIn("当前镜像补丁状态：待核对", html)
        self.assertIn("https://example.test/server2019#sample-issue", html)
        self.assertNotIn("已知问题（KB", html)

    def test_bare_kb_cannot_establish_regression_direction(self):
        event = Event(event_id="unknown", title="Issue KB5000001", event_type="known issue",
                      status="reported", source_id="release-health", source_tier="P0", source_url="https://example.test/issue",
                      identifiers={"kb": ["KB5000001"]})
        self.assertEqual("unknown", risk_phase(event)[0])

    def test_latest_product_observation_wins_without_cross_product_loss(self):
        event = self.health()
        old = dict(event.update_details[0], observed_at="2026-08-19", fixed_kb=[])
        event.update_details.append(old)
        self.assertEqual(["KB5000002"], patch_rows(event)[0]["fixed_kb"])

    def test_security_remediations_map_only_target_products(self):
        doc = json.loads((ROOT / "tests/fixtures/sample_msrc.json").read_text())
        remediations = doc["Vulnerability"][0]["Remediations"]
        remediations[0]["Description"] = {"Value": "Security Update"}
        remediations[0]["RestartRequired"] = {"Value": "Yes"}
        remediations.append(dict(remediations[0], ProductID=["other"],
                                 URL="https://example.test/help/5000099"))
        event = parse_msrc_document(doc, date(2026, 8, 1), date(2026, 8, 31), ["Windows 11"], "raw")[0]
        self.assertEqual(1, len(event.update_details))
        detail = event.update_details[0]
        self.assertEqual(["Windows 11 Version 24H2 for x64-based Systems"], detail["products"])
        self.assertEqual(["KB5099999"], detail["kb"])
        self.assertEqual("Yes", detail["restart_required"])
        self.assertEqual("security", risk_phase(event)[0])
        self.assertEqual([], patch_rows(event)[0]["introduced_kb"])


if __name__ == "__main__":
    unittest.main()
