from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.model import Event  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
