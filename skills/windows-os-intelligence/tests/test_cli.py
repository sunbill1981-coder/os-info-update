from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from io import StringIO
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.cli import run  # noqa: E402
from osintel.cli import _dedupe, _restore_failed_enrichment, _source_window  # noqa: E402
from osintel.model import Event, SourceResult  # noqa: E402
from osintel.store import Store  # noqa: E402


class CliTests(unittest.TestCase):
    def test_failed_enrichment_keeps_last_known_historical_value(self):
        prior = Event(
            event_id="msrc:CVE-2026-12345", title="漏洞", event_type="vulnerability",
            status="confirmed", source_id="msrc", source_tier="P0",
            source_url="https://example.test", identifiers={"cve": ["CVE-2026-12345"]},
            kev={"listed": True}, epss={"score": 0.5, "percentile": 0.99},
            field_status={"cisa_kev": "已发布", "first_epss": "已发布"},
            threat_urgency=100,
        )
        current = Event(**prior.payload())
        current.kev = {}
        current.epss = {}
        current.field_status = {"cisa_kev": "获取失败", "first_epss": "获取失败"}
        current.threat_urgency = 45
        _restore_failed_enrichment(
            [current], {prior.event_id: prior}, ["cisa-kev", "first-epss"],
        )
        self.assertTrue(current.kev["listed"])
        self.assertEqual(0.5, current.epss["score"])
        self.assertEqual("已发布", current.field_status["cisa_kev"])
        self.assertEqual(100, current.threat_urgency)

    def test_incremental_window_overlaps_checkpoint(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "state.sqlite3", Path(folder) / "raw")
            store.source_success("source", "2026-09-07", 1)
            args = type("Args", (), {"mode": "incremental", "end": date(2026, 9, 8), "days": 7})()
            start, end = _source_window("source", args, {"overlap_hours": 72, "incremental_days": 7}, store)
        self.assertEqual(date(2026, 9, 4), start)
        self.assertEqual(date(2026, 9, 8), end)

    def test_dedupe_keeps_latest_and_merges_scope(self):
        first = Event(
            event_id="same", title="Issue", event_type="known issue", status="reported",
            source_id="test", source_tier="P0", source_url="https://example.test",
            updated_at="2026-09-01", products=["Windows 11"],
        )
        second = Event(
            event_id="same", title="Issue updated", event_type="known issue", status="resolved",
            source_id="test", source_tier="P0", source_url="https://example.test",
            updated_at="2026-09-02", products=["Windows Server 2022"],
        )
        merged = _dedupe([first, second])
        self.assertEqual(1, len(merged))
        self.assertEqual("resolved", merged[0].status)
        self.assertEqual(["Windows 11", "Windows Server 2022"], merged[0].products)

    def test_dedupe_keeps_all_official_page_references(self):
        first = Event(
            event_id="release-health:4981msgdesc", title="RDS issue",
            event_type="known issue", status="reported", source_id="release-health",
            source_tier="P0", source_url="https://example.test/active",
            source_references=[{"page_id": "active", "url": "https://example.test/active"}],
        )
        second = Event(
            event_id=first.event_id, title=first.title, event_type="known issue",
            status="resolved", source_id="release-health", source_tier="P0",
            source_url="https://example.test/resolved",
            source_references=[{"page_id": "resolved", "url": "https://example.test/resolved"}],
        )
        merged = _dedupe([first, second])[0]
        self.assertEqual(2, len(merged.source_references))

    def test_coverage_error_returns_partial_and_does_not_advance_checkpoint(self):
        class DriftedCollector:
            def collect(self, context, start: date, end: date, config):
                result = SourceResult("drifted")
                result.coverage_errors.append("标题结构已变化")
                return result

        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            config = workspace / "sources.json"
            config.write_text(json.dumps({"defaults": {}, "http": {}}), encoding="utf-8")
            output, errors = StringIO(), StringIO()
            with patch.dict("osintel.cli.COLLECTORS", {"drifted": DriftedCollector()}, clear=True), \
                    redirect_stdout(output), redirect_stderr(errors):
                result = run([
                    "--mode", "rolling", "--days", "1", "--end", "2026-09-07",
                    "--sources", "drifted", "--workspace", str(workspace),
                    "--config", str(config),
                    "--taxonomy", str(ROOT / "config/risk-taxonomy.json"),
                    "--environment", str(ROOT / "config/environment.example.json"),
                ])
            self.assertEqual(2, result)
            with sqlite3.connect(str(workspace / "data/state/os-intel.sqlite3")) as connection:
                row = connection.execute(
                    "SELECT checkpoint,last_error FROM source_state WHERE source_id='drifted'"
                ).fetchone()
            self.assertIsNone(row[0])
            self.assertIn("解析覆盖异常", row[1])
            self.assertIn("覆盖异常", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
