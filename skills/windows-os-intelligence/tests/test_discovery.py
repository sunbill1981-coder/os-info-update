from contextlib import redirect_stdout
from datetime import date
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.cli import run as collect_run
from osintel.assessment import assess_event
from osintel.correlate import correlate_events
from osintel.discovery import (DiscoveryFetcher, build_plan, canonical_url, collect_candidates,
                               feed_items, import_snapshot, source_for, verified_event)
from osintel.guidance import build_cloud_desktop_guidance
from osintel.http import HttpClient, HttpSettings, FetchError
from osintel.model import Event, RawDocument
from osintel.model import stable_hash
from osintel.patches import risk_phase, phase_explanation
from osintel.signals import signal_event
from osintel.sources import CollectorContext
from osintel.store import Store

CONFIG = json.loads((ROOT / "config/discovery.json").read_text(encoding="utf-8"))
QUOTE = "After the Windows update, the display driver can cause a black screen when reconnecting a remote session on ARM64 devices."
BODY = ("<html><main><h1>Remote session display regression</h1><p>" + QUOTE + "</p><p>Windows 11 version 24H2. Updated September 20, 2026.</p></main></html>").encode()
START, END = date(2026, 9, 1), date(2026, 9, 30)


def reviewed(url, **extra):
    record = {"title": "ARM64 远程会话重连后黑屏的反馈", "claim_key": "display-reconnect",
              "source_url": url, "published_at": "2026-09-20", "status": "confirmed",
              "products": ["Windows 11, version 24H2"], "roles": ["guest"],
              "components": ["GPU/display", "RDP"], "identifiers": {"kb": ["KB5000010"]},
              "evidence": QUOTE, "summary": "来源指出 ARM64 设备更新后，显示驱动可能在远程会话重连时导致黑屏；其它架构范围未明确。",
              "reviewed_at": "2026-09-30T10:00:00+08:00", "review_note": "核对正文症状与架构；加域影响没有证据。",
              "risk_score": 85, "confidence": 99, "author": "tester-a",
              "independent_observation": True, "independence_note": "作者描述本环境观察，不是引用其它帖子。",
              "correlation_keys": ["fixture:display-reconnect"], "missing_evidence": ["驱动版本", "更新前后对照结果"]}
    record.update(extra)
    return record


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.workspace = Path(self.folder.name)
        self.store = Store(self.workspace / "data/state/os-intel.sqlite3", self.workspace / "data/raw")
        self.context = CollectorContext(HttpClient(HttpSettings(retries=0)), self.store)

    def tearDown(self):
        self.folder.cleanup()

    def persist(self, url, body=BODY):
        return self.store.persist_document(RawDocument("fixture", url, body, "text/html", "2026-09-30T00:00:00Z"))

    def event(self, url, **extra):
        doc = self.persist(url)
        return verified_event(reviewed(url, raw_hash=doc.sha256, **extra), self.context, CONFIG)

    def test_whitelist_does_not_trust_microsoft_qa_as_official(self):
        self.assertEqual("community", source_for("https://learn.microsoft.com/en-us/answers/questions/123/title", CONFIG)["kind"])
        self.assertEqual("official", source_for("https://learn.microsoft.com/en-us/troubleshoot/windows/issue", CONFIG)["kind"])
        for url in ("https://support.microsoft.com.evil.test/", "http://support.microsoft.com/topic/1", "https://user@support.microsoft.com/topic/1", "https://127.0.0.1/x", "https://techcommunity.microsoft.com/discussions/windows/x"):
            with self.assertRaises(ValueError):
                source_for(url, CONFIG)

    def test_query_plan_uses_window_entities_and_broad_workflow_queries(self):
        events = [{"published_at": "2026-09-10", "identifiers": {"kb": ["KB5000010"]}},
                  {"published_at": "2025-08-10", "identifiers": {"kb": ["KB4000001"]}}]
        plan = build_plan(events, START, END, CONFIG)
        self.assertIn("KB5000010", plan["seeds"])
        self.assertNotIn("KB4000001", plan["seeds"])
        self.assertLessEqual(len(plan["queries"]), CONFIG["max_queries"])
        self.assertTrue(any(item["source_id"] == "workflow" for item in plan["queries"]))
        self.assertTrue(any(item["source_id"] == "microsoft-qa" for item in plan["queries"]))

    def test_rss_and_atom_dates_and_html_challenge(self):
        rss = b'<rss><channel><item><title>Windows issue</title><link>https://support.microsoft.com/topic/a</link><pubDate>Sun, 20 Sep 2026 12:00:00 GMT</pubDate></item></channel></rss>'
        atom = b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Windows issue</title><link href="https://support.microsoft.com/topic/a"/><published>2026-09-20T00:00:00Z</published><updated>2026-09-22T00:00:00Z</updated></entry></feed>'
        self.assertEqual("2026-09-20", feed_items(rss)[0]["published_at"])
        self.assertEqual("2026-09-22", feed_items(atom)[0]["updated_at"])
        for body in (b"<html>Access denied</html>", b"<rss><channel/></rss>"):
            with self.assertRaises(ValueError):
                feed_items(body)

    def test_review_requires_snapshot_quote_date_and_stable_claim(self):
        url = "https://support.microsoft.com/topic/fixture"
        doc = self.persist(url)
        base = reviewed(url, raw_hash=doc.sha256)
        for extra in ({"raw_hash": "fake"}, {"evidence": "A fabricated quotation that does not occur in the original page."},
                      {"published_at": None}, {"claim_key": ""}, {"review_note": ""}, {"title": "English only"}):
            with self.assertRaises(ValueError):
                verified_event(dict(base, **extra), self.context, CONFIG)

    def test_community_cannot_self_certify_official_confirmation(self):
        event = self.event("https://learn.microsoft.com/en-us/answers/questions/123/display", source_tier="P0", authoritative_evidence=True, corroboration_count=100)
        self.assertEqual("P3", event.source_tier)
        self.assertEqual("reported", event.status)
        self.assertFalse(event.authoritative_evidence)
        self.assertLessEqual(event.confidence, 70)
        self.assertEqual("用户报告", event.evidence_review["proof_state"])
        guidance = build_cloud_desktop_guidance(event)
        self.assertIn("ARM64", guidance.problem_summary)
        self.assertNotIn("微软已记录", guidance.problem_summary)
        self.assertTrue(any("不自动执行论坛" in value for value in guidance.preventive_actions))

    def test_plain_inbox_cannot_inject_review_metadata(self):
        event = signal_event(reviewed("https://support.microsoft.com/topic/fixture", source_tier="P0", evidence_review={"source_kind": "official"}))
        self.assertFalse(event.authoritative_evidence)
        self.assertFalse(event.evidence_review)
        self.assertEqual("P2", event.source_tier)

    def test_explicit_export_retains_acquisition_and_does_not_promote_it(self):
        url = "https://www.reddit.com/r/Citrix/comments/aaa/issue"
        exported = {"source_url": url, "text": QUOTE + " Windows 11 version 24H2. Author describes a local test. More details still need checking.",
                    "acquisition_method": "authorized-tool-fulltext", "acquisition_note": "允许的原文读取工具导出；不是搜索摘要。"}
        candidate = import_snapshot(exported, self.context, CONFIG)
        self.assertEqual("待核验", candidate["review_state"])
        event = verified_event(reviewed(url, raw_hash=candidate["raw_hash"]), self.context, CONFIG)
        self.assertFalse(event.authoritative_evidence)
        self.assertEqual("P3", event.source_tier)
        with self.assertRaises(ValueError):
            import_snapshot(dict(exported, acquisition_method="search-snippet"), self.context, CONFIG)

    def test_official_provenance_and_stable_identity_across_quote_changes(self):
        url = "https://support.microsoft.com/topic/fixture"
        first = self.event(url)
        second = self.event(url, evidence=QUOTE + " Windows 11 version 24H2.")
        self.assertTrue(first.authoritative_evidence)
        self.assertEqual("P0", first.source_tier)
        self.assertEqual(first.event_id, second.event_id)
        self.assertNotEqual(first.fact_hash(), second.fact_hash())

    def test_patch_roles_require_official_or_vendor_quoted_relationship(self):
        url = "https://support.microsoft.com/topic/fixture"
        detail = {"relationship": "update_regression", "products": ["Windows 11, version 24H2"], "source_url": url, "evidence": QUOTE, "introduced_kb": []}
        event = self.event(url, update_details=[detail])
        self.assertEqual(1, len(event.update_details))
        with self.assertRaises(ValueError):
            self.event(url, update_details=[dict(detail, evidence="Invented relationship")])
        community = self.event("https://www.reddit.com/r/Citrix/comments/aaa/issue", update_details=[detail])
        self.assertFalse(community.update_details)

    def test_independent_users_same_forum_count_but_reposts_do_not(self):
        first = self.event("https://www.reddit.com/r/Citrix/comments/aaa/issue")
        second = self.event("https://www.reddit.com/r/Citrix/comments/bbb/issue", author="tester-b")
        repost = self.event("https://www.reddit.com/r/sysadmin/comments/ccc/issue", original_url=first.source_url, author="tester-c")
        for event in (first, second, repost):
            event.environment_relevance = 90
        correlate_events([first, second, repost])
        self.assertEqual(2, first.corroboration_count)
        self.assertEqual(2, repost.corroboration_count)
        self.assertEqual("调查预警", first.alert_level)
        correlate_events([first, repost])
        self.assertEqual(1, first.corroboration_count)

    def test_same_author_anonymous_and_multiple_official_pages(self):
        first = self.event("https://www.reddit.com/r/Citrix/comments/aaa/issue")
        second = self.event("https://www.reddit.com/r/Citrix/comments/bbb/issue")
        correlate_events([first, second])
        self.assertEqual(1, first.corroboration_count)
        first.evidence_review["independent_observation"] = False
        second.evidence_review["independent_observation"] = False
        second.evidence_review["author"] = "other"
        correlate_events([first, second])
        self.assertEqual(1, first.corroboration_count)
        official = [self.event("https://support.microsoft.com/topic/" + suffix) for suffix in ("first", "second")]
        correlate_events(official)
        self.assertEqual(1, official[0].corroboration_count)

    def test_unverified_report_cannot_add_to_verified_observer(self):
        first = self.event("https://www.reddit.com/r/Citrix/comments/aaa/issue")
        second = self.event("https://www.reddit.com/r/sysadmin/comments/bbb/issue", independent_observation=False)
        correlate_events([first, second])
        self.assertEqual(1, first.corroboration_count)

    def test_evidence_review_does_not_change_existing_fact_hash(self):
        event = Event("fixture", "title", "compatibility", "reported", "external-signal", "P3", "https://example.test/a")
        before = event.fact_hash()
        assessment = event.assessment_hash()
        event.evidence_review = {"proof_state": "用户报告"}
        self.assertEqual(before, event.fact_hash())
        self.assertNotEqual(assessment, event.assessment_hash())

    def test_empty_new_metadata_preserves_legacy_record_and_assessment_hashes(self):
        event = Event("fixture", "title", "compatibility", "reported", "external-signal", "P3", "https://example.test/a")
        old_record = event.payload()
        old_record.pop("evidence_review")
        old_record.pop("raw_hash")
        old_record.pop("source_activity")
        old_record.pop("fact_hash_aliases")
        self.assertEqual("record-v1:" + stable_hash(old_record), event.record_hash())
        self.assertNotIn("evidence_review", event.assessment_payload())

    def test_reviewed_incidental_reboot_does_not_become_boot_failure(self):
        event = self.event("https://www.reddit.com/r/Citrix/comments/aaa/issue")
        event.summary += " 必须重启设备，尚无启动失败或加域失败的证据。"
        event.affected_workflows = ["远程会话连接"]
        event.change_kinds = ["更新回归"]
        taxonomy = json.loads((ROOT / "config/risk-taxonomy.json").read_text())
        assess_event(event, taxonomy, {})
        self.assertEqual(["远程会话连接"], event.affected_workflows)
        self.assertEqual("regression", risk_phase(event)[0])
        self.assertIn("仍需核对", phase_explanation(event))
        guidance = build_cloud_desktop_guidance(event, {"scope_type": "product_portfolio", "delivery_architectures": ["VDI"]})
        self.assertFalse(any("可能无法启动" in value for value in guidance.potential_impacts))
        self.assertFalse(any("执行桌面创建、批量克隆" in value for value in guidance.recommended_tests))

    def test_candidate_fetch_failure_and_budget_are_visible(self):
        targets = [{"source_url": "https://support.microsoft.com/topic/" + str(i)} for i in range(5)]
        config = dict(CONFIG, max_candidates=2)
        with patch.object(DiscoveryFetcher, "fetch", side_effect=ValueError("访问受限")) as fetch:
            result = collect_candidates(self.context, config, START, END, targets, use_feeds=False)
        self.assertEqual(2, fetch.call_count)
        self.assertEqual("partial", result["status"])
        self.assertTrue(result["warnings"])

    def test_robots_failure_and_denial_stop_without_fetching_body(self):
        url = "https://support.microsoft.com/topic/fixture"
        with patch.object(self.context.http, "fetch", side_effect=FetchError(url, "403")) as fetch:
            with self.assertRaises(ValueError):
                DiscoveryFetcher(self.context, CONFIG).fetch(url, "microsoft-support")
            self.assertEqual(1, fetch.call_count)
        robots = RawDocument("fixture", "https://support.microsoft.com/robots.txt", b"User-agent: *\nDisallow: /\n", "text/plain", "2026-09-30")
        with patch.object(self.context.http, "fetch", return_value=robots) as fetch:
            with self.assertRaises(ValueError):
                DiscoveryFetcher(self.context, CONFIG).fetch(url, "microsoft-support")
            self.assertEqual(1, fetch.call_count)

    def test_reviewed_source_cli_to_history_html_and_coverage_gap(self):
        url = "https://www.reddit.com/r/Citrix/comments/aaa/issue"
        doc = self.persist(url)
        folder = self.workspace / "data/discovery"
        folder.mkdir(parents=True)
        path = folder / "reviewed.ndjson"
        path.write_text(json.dumps(reviewed(url, raw_hash=doc.sha256)) + "\n", encoding="utf-8")
        (folder / "latest-run.json").write_text(json.dumps({"window": {"start": "2026-09-01", "end": "2026-09-30"}, "failures": [{"source_id": "blocked-feed", "error": "403"}]}), encoding="utf-8")
        with redirect_stdout(StringIO()):
            result = collect_run(["--mode", "backfill", "--start", "2026-09-01", "--end", "2026-09-30", "--sources", "discovery", "--no-enrichment", "--workspace", str(self.workspace), "--config", str(ROOT / "config/sources.json"), "--taxonomy", str(ROOT / "config/risk-taxonomy.json"), "--environment", str(ROOT / "config/environment.example.json"), "--discovery-config", str(ROOT / "config/discovery.json")])
        self.assertEqual(2, result)
        html = (self.workspace / "reports/latest.html").read_text(encoding="utf-8")
        self.assertIn("用户报告", html)
        self.assertIn("ARM64", html)
        self.assertIn("blocked-feed", html)
        self.assertIn(url, html)
        stored = self.store.list_events()[0]
        self.assertEqual("P3", stored["source_tier"])
        self.assertNotEqual("正式告警", stored["alert_level"])


if __name__ == "__main__":
    unittest.main()
