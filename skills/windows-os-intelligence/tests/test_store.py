from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.model import Event  # noqa: E402
from osintel.correlate import correlate_events  # noqa: E402
from osintel.store import Store  # noqa: E402


class StoreTests(unittest.TestCase):
    def test_upsert_is_idempotent_and_tracks_material_change(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "state.sqlite3", Path(folder) / "raw")
            event = Event(
                event_id="test:1", title="Initial", event_type="known issue", status="reported",
                source_id="test", source_tier="P0", source_url="https://example.test/1",
            )
            self.assertEqual(1, store.upsert_events([event])["new"])
            self.assertEqual(1, store.upsert_events([event])["unchanged"])
            event.status = "resolved"
            self.assertEqual(1, store.upsert_events([event])["changed"])
            with sqlite3.connect(str(store.db_path)) as connection:
                count = connection.execute("SELECT count(*) FROM event_changes WHERE event_id='test:1'").fetchone()[0]
            self.assertEqual(2, count)

    def test_assessment_change_does_not_become_fact_change(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "state.sqlite3", Path(folder) / "raw")
            event = Event(
                event_id="test:assessment", title="Issue", event_type="known issue",
                status="reported", source_id="test", source_tier="P0",
                source_url="https://example.test/assessment", risk_score=70,
            )
            store.upsert_events([event])
            event.risk_score = 85
            event.recommended_action = "更新评估建议"
            result = store.upsert_events([event])
            self.assertEqual(0, result["fact_changed"])
            self.assertEqual(1, result["assessment_changed"])

    def test_fact_change_records_changed_fields_and_evidence_index(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "state.sqlite3", Path(folder) / "raw")
            event = Event(
                event_id="test:fact", title="Issue", event_type="known issue",
                status="reported", source_id="test", source_tier="P0",
                source_url="https://example.test/fact", evidence="Original evidence",
            )
            store.upsert_events([event])
            event.status = "resolved"
            result = store.upsert_events([event])
            self.assertEqual(1, result["fact_changed"])
            with sqlite3.connect(str(store.db_path)) as connection:
                change = connection.execute(
                    "SELECT change_type,changed_fields_json FROM event_changes "
                    "WHERE event_id=? ORDER BY change_id DESC LIMIT 1", (event.event_id,),
                ).fetchone()
                evidence_count = connection.execute(
                    "SELECT count(*) FROM evidence WHERE event_id=?", (event.event_id,),
                ).fetchone()[0]
            self.assertEqual("fact_change", change[0])
            self.assertIn("status", change[1])
            self.assertEqual(2, evidence_count)

    def test_related_events_enable_cross_run_independent_corroboration(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "state.sqlite3", Path(folder) / "raw")
            early = Event(
                event_id="signal:early", title="Early signal", event_type="compatibility",
                status="reported", source_id="community", source_tier="P3",
                source_url="https://community.example.test/issue", publisher="Community",
                correlation_keys=["risk:shared"], confidence=55,
            )
            store.upsert_events([early])
            official = Event(
                event_id="official:later", title="Official advisory", event_type="known issue",
                status="confirmed", source_id="release-health", source_tier="P0",
                source_url="https://learn.microsoft.com/windows/issue", publisher="Microsoft",
                correlation_keys=["risk:shared"], confidence=97, authoritative_evidence=True,
            )
            related = [Event(**payload) for payload in store.related_events([official])]
            self.assertEqual([early.event_id], [event.event_id for event in related])
            correlate_events([official] + related)
            self.assertEqual(2, official.corroboration_count)
            self.assertEqual(2, related[0].corroboration_count)

    def test_source_zero_streak_preserves_last_nonzero_baseline(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "state.sqlite3", Path(folder) / "raw")
            store.source_success("source", "2026-09-01", 12)
            store.source_success("source", "2026-09-02", 0)
            store.source_success("source", "2026-09-03", 0)
            observation = store.source_observation("source")
            self.assertEqual(2, observation["zero_streak"])
            self.assertEqual(12, observation["last_nonzero_count"])


if __name__ == "__main__":
    unittest.main()
