from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.model import Event  # noqa: E402
from osintel.guidance import build_cloud_desktop_guidance  # noqa: E402
from osintel.report import write_run_html, write_run_report  # noqa: E402


class ReportTests(unittest.TestCase):
    def test_html_report_is_self_contained_and_every_conclusion_has_direct_sources(self):
        event = Event(
            event_id="release-health:123msgdesc", title="Remote Desktop issue",
            event_type="known issue", status="investigating", source_id="release-health",
            source_tier="P0", source_url="https://example.test/health#123msgdesc",
            products=["Windows 11 Version 24H2"], components=["RDP"],
            identifiers={"kb": ["KB5000000"]}, risk_score=82, confidence=97,
            action_priority=76, source_references=[
                {"page_id": "win11-24h2", "url": "https://example.test/24h2#123msgdesc", "raw_hash": "one"},
                {"page_id": "server-2025", "url": "https://example.test/server#123msgdesc", "raw_hash": "two"},
            ],
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.html"
            template = ROOT / "assets/report-template.html"
            write_run_html(
                path, template, 7, "rolling", "2026-09-01", "2026-09-30", [event],
                {"new": 1, "new_ids": [event.event_id]}, ["测试源：<script>alert(1)</script>"], [],
            )
            text = path.read_text(encoding="utf-8")
        self.assertIn("<!doctype html>", text)
        self.assertIn("公开事实摘要", text)
        self.assertIn("对云桌面的潜在影响", text)
        self.assertIn("建议测试", text)
        self.assertIn("预防与上线门禁", text)
        self.assertIn("针对性探索", text)
        self.assertIn("工程推演 · 需验证", text)
        self.assertIn("直达原文", text)
        self.assertIn("触发依据", text)
        self.assertIn("https://example.test/24h2#123msgdesc", text)
        self.assertIn("https://example.test/server#123msgdesc", text)
        self.assertIn('rel="noopener noreferrer"', text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", text)
        self.assertNotIn("{{", text)

    def test_human_report_localizes_source_text(self):
        event = Event(
            event_id="msrc:CVE-2026-12345",
            title="Remote Desktop Client Remote Code Execution Vulnerability",
            event_type="vulnerability",
            status="confirmed",
            source_id="msrc",
            source_tier="P0",
            source_url="https://example.test/CVE-2026-12345",
            products=["Windows 11 Version 24H2"],
            roles=["guest", "host"],
            components=["RDP"],
            identifiers={"cve": ["CVE-2026-12345"], "kb": [], "build": []},
            summary="Critical; CVSS 9.8; Remote Code Execution",
            recommended_action="English action must not be displayed.",
            update_details=[{
                "kb": ["KB5099999"], "fixed_build": "26100.9999",
                "supercedence": "KB5098888", "restart_required": "Yes",
            }],
            risk_score=90,
            confidence=98,
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.md"
            write_run_report(path, 1, "backfill", "2026-08-01", "2026-08-31", [event], {"new": 1}, [], [], 25)
            text = path.read_text(encoding="utf-8")
        self.assertIn("历史回填", text)
        self.assertIn("远程桌面协议（RDP）远程代码执行漏洞", text)
        self.assertIn("可能导致远程代码执行", text)
        self.assertIn("来宾系统、宿主机", text)
        self.assertIn("技术风险 90", text)
        self.assertIn("环境相关度", text)
        self.assertIn("处置优先级", text)
        self.assertIn("Windows 11 版本 24H2", text)
        self.assertIn("补丁关系：KB5099999，修复 Build 26100.9999，取代 KB5098888，重启要求 需要", text)
        self.assertNotIn("Version", text)
        self.assertNotIn(event.title, text)
        self.assertNotIn(event.summary, text)
        self.assertNotIn(event.recommended_action, text)

    def test_incremental_report_hides_unchanged_inventory(self):
        new_event = Event(
            event_id="new", title="New issue", event_type="known issue", status="reported",
            source_id="release-health", source_tier="P0",
            source_url="https://example.test/new", authoritative_evidence=True,
        )
        unchanged = Event(
            event_id="old", title="Old issue", event_type="lifecycle", status="confirmed",
            source_id="lifecycle", source_tier="P0",
            source_url="https://example.test/old", authoritative_evidence=True,
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.md"
            write_run_report(
                path, 2, "incremental", "2026-09-01", "2026-09-07",
                [new_event, unchanged],
                {"new": 1, "new_ids": ["new"], "unchanged": 1, "unchanged_ids": ["old"]},
                [], [], 25,
            )
            text = path.read_text(encoding="utf-8")
        self.assertIn("https://example.test/new", text)
        self.assertNotIn("https://example.test/old", text)
        self.assertIn("本轮新增", text)

    def test_guidance_translates_generic_dimensions_into_cloud_desktop_actions(self):
        event = Event(
            event_id="release-health:generic", title="Generic issue",
            event_type="known issue", status="investigating", source_id="release-health",
            source_tier="P0", source_url="https://example.test/issue",
            products=["Windows 11 Version 24H2"], roles=["guest", "directory"],
            components=["RDP", "authentication", "image/recovery"],
            affected_workflows=["桌面镜像与交付", "域加入与信任关系", "远程会话连接"],
            preconditions=["基于镜像或克隆部署"], symptoms=["认证或授权失败"],
            identifiers={"kb": ["KB5000000"]},
        )
        guidance = build_cloud_desktop_guidance(event)
        combined = "".join(
            [guidance.problem_summary, guidance.applicability]
            + guidance.potential_impacts + guidance.recommended_tests
            + guidance.preventive_actions + guidance.exploration_questions
        )
        self.assertIn("加域", combined)
        self.assertIn("重连", combined)
        self.assertIn("金镜像", combined)
        self.assertIn("回滚", combined)
        self.assertIn("不能断言已影响", guidance.applicability)
        self.assertNotIn("SID", combined)


if __name__ == "__main__":
    unittest.main()
