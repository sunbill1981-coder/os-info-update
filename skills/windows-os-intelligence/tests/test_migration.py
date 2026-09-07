import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.migration import apply_migration, inspect_database  # noqa: E402


class MigrationTests(unittest.TestCase):
    def test_migration_normalizes_dates_and_backs_up_legacy_database(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            db_path = workspace / "data/state/os-intel.sqlite3"
            db_path.parent.mkdir(parents=True)
            config_root = workspace / "skills/windows-os-intelligence/config"
            config_root.mkdir(parents=True)
            for name in ("risk-taxonomy.json", "environment.json"):
                (config_root / name).write_text(
                    (ROOT / "config" / name).read_text(encoding="utf-8"), encoding="utf-8",
                )
            payload = {
                "event_id": "msrc:CVE-TEST", "title": "Issue",
                "event_type": "vulnerability", "status": "confirmed",
                "source_id": "msrc", "source_tier": "P0",
                "source_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-TEST",
                "published_at": "0001-01-01T00:00:00", "confidence": 98,
            }
            with sqlite3.connect(str(db_path)) as connection:
                connection.executescript("""
                    CREATE TABLE events(
                        event_id TEXT PRIMARY KEY,payload_json TEXT NOT NULL,
                        content_hash TEXT NOT NULL,first_seen TEXT NOT NULL,last_seen TEXT NOT NULL
                    );
                    CREATE TABLE event_changes(
                        change_id INTEGER PRIMARY KEY,event_id TEXT,changed_at TEXT,
                        prior_hash TEXT,new_hash TEXT,payload_json TEXT
                    );
                    CREATE TABLE documents(
                        url TEXT PRIMARY KEY,source_id TEXT,etag TEXT,last_modified TEXT,
                        sha256 TEXT,raw_path TEXT,fetched_at TEXT
                    );
                    CREATE TABLE runs(
                        run_id INTEGER PRIMARY KEY,mode TEXT,window_start TEXT,window_end TEXT,
                        started_at TEXT,finished_at TEXT,status TEXT,stats_json TEXT,error TEXT
                    );
                    CREATE TABLE source_state(
                        source_id TEXT PRIMARY KEY,checkpoint TEXT,last_success TEXT,
                        last_error TEXT,last_count INTEGER DEFAULT 0
                    );
                """)
                connection.execute(
                    "INSERT INTO events VALUES(?,?,?,?,?)",
                    (payload["event_id"], json.dumps(payload), "legacy", "now", "now"),
                )
            self.assertEqual(1, inspect_database(db_path)["normalized_dates"])
            result = apply_migration(workspace)
            self.assertTrue(Path(result["backup"]).exists())
            with sqlite3.connect(str(db_path)) as connection:
                migrated = json.loads(connection.execute("SELECT payload_json FROM events").fetchone()[0])
                version = connection.execute("SELECT hash_schema_version FROM events").fetchone()[0]
                evidence_count = connection.execute("SELECT count(*) FROM evidence").fetchone()[0]
            self.assertIsNone(migrated["published_at"])
            self.assertTrue(migrated["authoritative_evidence"])
            self.assertEqual(2, version)
            self.assertEqual(1, evidence_count)


if __name__ == "__main__":
    unittest.main()
