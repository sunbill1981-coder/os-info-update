import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.assessment import assess_event  # noqa: E402
from osintel.correlate import correlate_events  # noqa: E402
from osintel.model import Event  # noqa: E402


TAXONOMY = json.loads((ROOT / "config/risk-taxonomy.json").read_text(encoding="utf-8"))
ENVIRONMENT = json.loads((ROOT / "config/environment.json").read_text(encoding="utf-8"))


def candidate(event_id: str, text: str, confidence: int = 60) -> Event:
    return Event(
        event_id=event_id,
        title=text,
        event_type="compatibility",
        status="reported",
        source_id="external-signal",
        source_tier="P3",
        source_url=f"https://example.test/{event_id}",
        products=["Windows 11, version 24H2"],
        roles=["guest"],
        components=["authentication"],
        identifiers={"kb": ["KB5000000"]},
        confidence=confidence,
    )


class AssessmentTests(unittest.TestCase):
    def test_generic_security_enforcement_and_workflow_detection(self):
        event = candidate(
            "generic:enforcement",
            "The update adds strict checks and now requires managed devices to authenticate before sign-in.",
        )
        assess_event(event, TAXONOMY, ENVIRONMENT)
        self.assertIn("安全机制收紧", event.change_kinds)
        self.assertIn("身份认证与登录", event.affected_workflows)
        self.assertGreaterEqual(event.environment_relevance, 70)

    def test_version_mismatch_is_a_generic_precondition(self):
        event = candidate(
            "generic:mismatch",
            "Connections fail when a patched guest talks to an unpatched host; both host and guest must be fully updated.",
        )
        assess_event(event, TAXONOMY, ENVIRONMENT)
        self.assertIn("版本组合限制", event.change_kinds)
        self.assertIn("补丁状态不一致", event.preconditions)
        self.assertIn("连接中断", event.symptoms)

    def test_deprecation_and_upgrade_failure_are_detected(self):
        event = candidate(
            "generic:deprecation",
            "The legacy protocol is no longer supported and an upgrade may fail to install.",
        )
        assess_event(event, TAXONOMY, ENVIRONMENT)
        self.assertIn("弃用或移除", event.change_kinds)
        self.assertIn("安装或升级失败", event.symptoms)

    def test_case_example_uses_generic_dimensions_and_corroboration(self):
        text = (
            "After installing KB5065426, authentication can fail on cloned Windows devices with duplicate security identifiers "
            "when the image was created without running system preparation."
        )
        first = candidate("case:community-1", text, confidence=55)
        second = candidate("case:community-2", text, confidence=55)
        first.correlation_keys = ["case:duplicate-identity-authentication"]
        second.correlation_keys = ["case:duplicate-identity-authentication"]
        first.risk_score = second.risk_score = 85
        for event in (first, second):
            assess_event(event, TAXONOMY, ENVIRONMENT)
        correlate_events([first, second])
        self.assertEqual(2, first.corroboration_count)
        self.assertEqual("调查预警", first.alert_level)


if __name__ == "__main__":
    unittest.main()
