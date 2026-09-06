from datetime import date
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.sources import (  # noqa: E402
    parse_insider_sitemap,
    parse_lifecycle,
    parse_msrc_document,
    parse_release_health,
)


FIXTURES = Path(__file__).parent / "fixtures"
START = date(2026, 8, 1)
END = date(2026, 8, 31)


class SourceParserTests(unittest.TestCase):
    def test_msrc_filters_products_and_extracts_rdp_risk(self):
        document = json.loads((FIXTURES / "sample_msrc.json").read_text())
        events = parse_msrc_document(document, START, END, ["Windows 11", "Windows Server 2022"], "raw")
        self.assertEqual(1, len(events))
        event = events[0]
        self.assertEqual("msrc:CVE-2026-12345", event.event_id)
        self.assertIn("RDP", event.components)
        self.assertGreaterEqual(event.risk_score, 90)
        self.assertEqual(["CVE-2026-12345"], event.identifiers["cve"])

    def test_msrc_excludes_future_release_with_old_revision(self):
        document = json.loads((FIXTURES / "sample_msrc.json").read_text())
        vulnerability = document["Vulnerability"][0]
        vulnerability["ReleaseDate"] = "2026-09-08T07:00:00Z"
        vulnerability["RevisionHistory"] = [{"Date": "2026-08-20T07:00:00Z"}]
        events = parse_msrc_document(document, START, END, ["Windows 11"], "raw")
        self.assertEqual([], events)

    def test_release_health_extracts_issue(self):
        html = (FIXTURES / "sample_release_health.html").read_text()
        events = parse_release_health(html, "win11", "https://example.test/health", "Windows 11", START, END, "raw")
        self.assertEqual(1, len(events))
        event = events[0]
        self.assertEqual("investigating", event.status)
        self.assertIn("RDP", event.components)
        self.assertIn("KB5070001", event.identifiers["kb"])
        self.assertEqual("release-health:rdp-session-failure", event.event_id)

    def test_release_health_ignores_patch_date_outside_issue_window(self):
        html = """<main><h2>Issue details</h2><h3>September 2026</h3>
        <h4 id='future'>Future issue</h4><p>Opened: 2026-09-01</p>
        <p>After update KB5070001 released 2026-08-11.</p></main>"""
        events = parse_release_health(html, "win11", "https://example.test/health", "Windows 11", START, END, "raw")
        self.assertEqual([], events)

    def test_lifecycle_extracts_milestone(self):
        html = (FIXTURES / "sample_lifecycle.html").read_text()
        events = parse_lifecycle(html, "server-2022", "https://example.test/lifecycle", "Windows Server 2022", START, END, "raw")
        self.assertEqual(1, len(events))
        self.assertEqual("lifecycle", events[0].event_type)

    def test_insider_sitemap_is_preview(self):
        body = (FIXTURES / "sample_insider_sitemap.xml").read_bytes()
        events = parse_insider_sitemap(body, START, END, "raw")
        self.assertEqual(1, len(events))
        self.assertTrue(events[0].preview)
        self.assertEqual(72, events[0].confidence)


if __name__ == "__main__":
    unittest.main()
