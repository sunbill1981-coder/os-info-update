from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.model import Event  # noqa: E402
from osintel.report import write_run_report  # noqa: E402


class ReportTests(unittest.TestCase):
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
            risk_score=90,
            confidence=98,
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.md"
            write_run_report(path, 1, "backfill", "2026-08-01", "2026-08-31", [event], {"new": 1}, [], [], 25)
            text = path.read_text(encoding="utf-8")
        self.assertIn("历史回填", text)
        self.assertIn("远程桌面协议（RDP）远程代码执行漏洞", text)
        self.assertIn("来宾系统、宿主机", text)
        self.assertIn("技术风险 90", text)
        self.assertIn("环境相关度", text)
        self.assertIn("处置优先级", text)
        self.assertIn("Windows 11 版本 24H2", text)
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


if __name__ == "__main__":
    unittest.main()
