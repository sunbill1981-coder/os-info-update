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
from osintel.cli import _dedupe, _report_scope, _restore_failed_enrichment, _source_window  # noqa: E402
from osintel.model import Event, SourceResult  # noqa: E402
from osintel.store import Store  # noqa: E402


class CliTests(unittest.TestCase):
    def test_external_triage_and_discovery_gaps_survive_an_empty_environment(self):
        signal = {
            "title": "Windows users report session disconnects", "source_url": "https://example.test/session",
            "event_type": "known issue", "published_at": "2026-09-07",
            "products": ["Windows 11"], "components": ["RDP"],
            "affected_workflows": ["远程会话连接"], "symptoms": ["连接中断"],
            "evidence": "Users report session disconnects on the same build after reconnecting.",
            "summary": "用户报告重连后会话断开，根因尚未明确。", "confidence": 50,
        }
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            signals = workspace / "signals.ndjson"
            signals.write_text(json.dumps(signal) + "\n", encoding="utf-8")
            args = [
                "--mode", "incremental", "--days", "7", "--end", "2026-09-07",
                "--sources", "signals", "--no-enrichment", "--workspace", str(workspace),
                "--signals-file", str(signals), "--config", str(ROOT / "config/sources.json"),
                "--taxonomy", str(ROOT / "config/risk-taxonomy.json"),
                "--environment", str(ROOT / "config/environment.json"),
            ]
            with redirect_stdout(StringIO()):
                self.assertEqual(0, run(args))
            report = json.loads((workspace / "runtime/trial/reports/run-000001.json").read_text())
            triage = json.loads(Path(report["triage_report"]).read_text())
            self.assertEqual("not_planned", report["discovery_coverage"]["status"])
            self.assertTrue(report["warnings"])
            self.assertEqual(1, triage["summary"]["shown"])
            item = triage["queue"][0]
            self.assertTrue(item["high_attention"])
            self.assertFalse(item["review"]["scheduled"])
            stored = json.loads((workspace / "runtime/trial/data/normalized/events.ndjson").read_text())
            self.assertEqual(0, stored["environment_relevance"])
            self.assertNotEqual("正式告警", stored["alert_level"])
            self.assertNotIn("external_relevance", stored)
            self.assertIn(signal["source_url"], Path(report["html_report"]).read_text())
            with redirect_stdout(StringIO()):
                self.assertEqual(0, run(args))
            repeat = json.loads((workspace / "runtime/trial/reports/run-000002.json").read_text())
            self.assertEqual(0, repeat["triage_summary"]["shown"])
            self.assertNotIn(signal["source_url"], Path(repeat["html_report"]).read_text())
            self.assertEqual(1, repeat["stats"]["unchanged"])

    def test_monthly_report_excludes_historical_enrichment_refreshes(self):
        events = [Event(
            event_id=key, title=key, event_type="vulnerability", status="confirmed",
            source_id="msrc", source_tier="P0", source_url="https://example.test/" + key,
        ) for key in ("current", "historical")]
        stats = {
            "events": 2, "new": 1, "new_ids": ["current"],
            "assessment_changed": 1, "assessment_changed_ids": ["historical"],
            "fact_changed_ids": [], "display_changed_ids": [],
            "unchanged_ids": [], "changed": 1,
        }
        visible, result = _report_scope(events, stats, {"current"})
        self.assertEqual(["current"], [event.event_id for event in visible])
        self.assertEqual(1, result['events'])
        self.assertEqual(1, result['new'])
        self.assertEqual(0, result['changed'])
        self.assertEqual(0, result['assessment_changed'])
        self.assertEqual(1, stats['changed'])

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
            with sqlite3.connect(str(workspace / "runtime/trial/data/state/os-intel.sqlite3")) as connection:
                row = connection.execute(
                    "SELECT checkpoint,last_error FROM source_state WHERE source_id='drifted'"
                ).fetchone()
            self.assertIsNone(row[0])
            self.assertIn("解析覆盖异常", row[1])
            self.assertIn("覆盖异常", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
