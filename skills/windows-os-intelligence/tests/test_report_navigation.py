from html.parser import HTMLParser
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from osintel.model import Event
from osintel.report import write_run_html


class Inventory(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.targets, self.local_links, self.card_types = [], [], [], []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
        if values.get("data-target"):
            self.targets.append(values["data-target"])
        if tag == "a" and values.get("href", "").startswith("#"):
            self.local_links.append(values["href"][1:])
        if tag == "article":
            self.card_types.append(values.get("data-type"))


class ReportNavigationTests(unittest.TestCase):
    def render(self, events, mode="rolling", stats=None):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.html"
            write_run_html(path, ROOT / "assets/report-template.html", 1, mode, "2026-09-01", "2026-09-30", events, stats or {}, [], [])
            return path.read_text(encoding="utf-8")

    def event(self, identity, kind="known issue"):
        return Event(event_id=identity, title="Generic issue", event_type=kind, status="confirmed", source_id="release-health", source_tier="P0", source_url="https://example.test/" + identity)

    def test_every_entry_and_local_link_resolves_to_unique_element(self):
        events = [self.event("a"), self.event("b", "vulnerability"), self.event("c", "feature preview")]
        page = self.render(events)
        inventory = Inventory()
        inventory.feed(page)
        self.assertEqual(len(inventory.ids), len(set(inventory.ids)))
        self.assertTrue(set(inventory.targets).issubset(inventory.ids))
        self.assertTrue(set(inventory.local_links).issubset(inventory.ids))
        self.assertEqual({"event-1", "event-2", "event-3"}, set(inventory.targets))
        self.assertIn("分组目录", page)
        self.assertIn('class="index-subgroup"', page)
        self.assertNotIn("{{", page)

    def test_incremental_index_has_no_unchanged_inventory(self):
        page = self.render([self.event("new"), self.event("old")], "incremental", {"new_ids": ["new"]})
        self.assertIn("https://example.test/new", page)
        self.assertNotIn("https://example.test/old", page)
        inventory = Inventory()
        inventory.feed(page)
        self.assertEqual({"event-1"}, set(inventory.targets))

    def test_empty_report_has_no_dangling_entry(self):
        page = self.render([])
        inventory = Inventory()
        inventory.feed(page)
        self.assertEqual([], inventory.targets)

    def test_assessment_only_update_is_not_labelled_new_fact(self):
        page = self.render([self.event("assessment")], stats={"assessment_changed": 1, "assessment_changed_ids": ["assessment"]})
        self.assertIn("仅评估更新 1 条", page)
        self.assertIn('<span class="chip chip-delta">评估更新</span>', page)
        self.assertNotIn('<span class="chip chip-delta">本轮变化</span>', page)

    def test_scope_is_visible_and_source_excerpt_is_escaped(self):
        event = self.event("scoped")
        event.title = "Fabrikam Viewer might fail to launch on ARM devices"
        event.evidence = '<script>alert(1)</script> ARM devices can fail to launch the app.'
        page = self.render([event])
        self.assertIn("Fabrikam Viewer", page)
        self.assertIn("CPU 范围：", page)
        self.assertIn('data-cpu="ARM"', page)
        self.assertIn('data-applicability="未知"', page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn(event.evidence, page)


if __name__ == "__main__":
    unittest.main()
