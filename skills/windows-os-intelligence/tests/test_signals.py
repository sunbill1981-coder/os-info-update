from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.cli import run  # noqa: E402


class SignalIntegrationTests(unittest.TestCase):
    def test_signal_only_run_uses_generic_assessment(self):
        record = {
            "title": "New security hardening after installing an update",
            "source_url": "https://example.test/advisory",
            "published_at": "2026-08-20",
            "products": ["Windows 11, version 24H2"],
            "roles": ["guest"],
            "components": ["authentication"],
            "identifiers": {"kb": ["KB5000000"]},
            "summary": "The update adds strict checks and authentication can fail in managed environments.",
            "confidence": 88
        }
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            signals = workspace / "signals.ndjson"
            signals.write_text(json.dumps(record) + "\n", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                result = run([
                    "--mode", "rolling", "--days", "31", "--end", "2026-08-31",
                    "--sources", "signals", "--signals-file", str(signals),
                    "--workspace", str(workspace),
                    "--config", str(ROOT / "config/sources.json"),
                    "--taxonomy", str(ROOT / "config/risk-taxonomy.json"),
                    "--environment", str(ROOT / "config/environment.json"),
                ])
            self.assertEqual(0, result)
            self.assertIn("运行完成", output.getvalue())
            with sqlite3.connect(str(workspace / "data/state/os-intel.sqlite3")) as connection:
                payload = json.loads(connection.execute("SELECT payload_json FROM events").fetchone()[0])
            self.assertIn("安全机制收紧", payload["change_kinds"])
            self.assertIn("身份认证与登录", payload["affected_workflows"])
            self.assertGreater(payload["environment_relevance"], 0)
            self.assertGreater(payload["action_priority"], 0)


if __name__ == "__main__":
    unittest.main()
