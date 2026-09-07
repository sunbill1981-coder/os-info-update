from email.message import Message
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.http import HttpClient, HttpSettings, _retry_after_seconds  # noqa: E402


class _Response:
    def __init__(self, body=b"ok"):
        self.body = body
        self.headers = Message()
        self.status = 200

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def geturl(self):
        return "https://example.test/data"

    def read(self):
        return self.body


class HttpTests(unittest.TestCase):
    def test_retry_after_seconds_is_capped(self):
        self.assertEqual(60, _retry_after_seconds("120", 60))
        self.assertIsNone(_retry_after_seconds("not-a-date", 60))

    def test_429_honors_retry_after_before_retry(self):
        headers = Message()
        headers["Retry-After"] = "5"
        error = HTTPError("https://example.test/data", 429, "busy", headers, None)
        client = HttpClient(HttpSettings(retries=1, max_retry_delay_seconds=10))
        with patch("osintel.http.urlopen", side_effect=[error, _Response()]), \
                patch("osintel.http.random.uniform", return_value=0), \
                patch("osintel.http.time.sleep") as sleep:
            result = client.fetch("test", "https://example.test/data")
        self.assertEqual(200, result.status)
        sleep.assert_called_once_with(5.0)


if __name__ == "__main__":
    unittest.main()
