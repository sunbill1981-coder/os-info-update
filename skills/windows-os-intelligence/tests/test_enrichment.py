import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.enrichment import enrich_events  # noqa: E402
from osintel.model import Event, RawDocument  # noqa: E402


def vulnerability(cve="CVE-2026-12345"):
    return Event(
        event_id=f"msrc:{cve}", title="漏洞", event_type="vulnerability",
        status="confirmed", source_id="msrc", source_tier="P0",
        source_url="https://example.test", identifiers={"cve": [cve]},
        risk_score=80, confidence=98, authoritative_evidence=True,
    )


class Context:
    def __init__(self, fail_epss=False):
        self.fail_epss = fail_epss

    def fetch(self, source_id, url, accept):
        if source_id == "cisa-kev":
            payload = {"vulnerabilities": [{
                "cveID": "CVE-2026-12345", "dateAdded": "2026-09-01",
                "dueDate": "2026-09-20", "knownRansomwareCampaignUse": "Known",
                "requiredAction": "Apply mitigations",
            }]}
        else:
            if self.fail_epss:
                raise RuntimeError("upstream unavailable")
            payload = {"data": [{
                "cve": "CVE-2026-12345", "epss": "0.75",
                "percentile": "0.997", "date": "2026-09-29",
            }]}
        return RawDocument(
            source_id=source_id, url=url, body=json.dumps(payload).encode(),
            content_type="application/json", fetched_at="2026-09-29T00:00:00+00:00",
        )


class NoFetchContext:
    def fetch(self, source_id, url, accept):
        raise AssertionError("无 CVE 事件不应请求威胁数据源")


class EnrichmentTests(unittest.TestCase):
    def test_non_vulnerability_event_does_not_fetch_threat_feeds(self):
        event = Event(
            event_id="signal:1", title="兼容性信号", event_type="signal",
            status="reported", source_id="signals-inbox", source_tier="P2",
            source_url="https://example.test/signal",
        )
        result = enrich_events([event], NoFetchContext(), {
            "cisa_kev": {"enabled": True}, "first_epss": {"enabled": True},
        })
        self.assertEqual([], result.warnings)
        self.assertEqual("不适用", event.field_status["cisa_kev"])
        self.assertEqual("不适用", event.field_status["first_epss"])

    def test_kev_and_epss_are_separate_from_confidence(self):
        event = vulnerability()
        result = enrich_events([event], Context(), {
            "cisa_kev": {"enabled": True}, "first_epss": {"enabled": True},
        })
        self.assertEqual([], result.warnings)
        self.assertTrue(event.kev["listed"])
        self.assertEqual(0.75, event.epss["score"])
        self.assertEqual(100, event.threat_urgency)
        self.assertEqual(98, event.confidence)
        self.assertEqual("已发布", event.field_status["cisa_kev"])

    def test_successful_feed_distinguishes_absence_from_failure(self):
        absent = vulnerability("CVE-2026-99999")
        enrich_events([absent], Context(), {
            "cisa_kev": {"enabled": True}, "first_epss": {"enabled": True},
        })
        self.assertEqual("明确无记录", absent.field_status["cisa_kev"])
        self.assertEqual("明确无记录", absent.field_status["first_epss"])

        failed = vulnerability()
        result = enrich_events([failed], Context(fail_epss=True), {
            "first_epss": {"enabled": True},
        })
        self.assertEqual("获取失败", failed.field_status["first_epss"])
        self.assertTrue(result.warnings)


if __name__ == "__main__":
    unittest.main()
