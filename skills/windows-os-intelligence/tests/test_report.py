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
        self.assertIn("Windows 11 版本 24H2", text)
        self.assertNotIn("Version", text)
        self.assertNotIn(event.title, text)
        self.assertNotIn(event.summary, text)
        self.assertNotIn(event.recommended_action, text)


if __name__ == "__main__":
    unittest.main()
