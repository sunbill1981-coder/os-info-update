from email.message import Message
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.http import FetchError, HttpClient, HttpSettings, _retry_after_seconds  # noqa: E402


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

    def read(self, limit=None):
        return self.body if limit is None else self.body[:limit]


class HttpTests(unittest.TestCase):
    def test_discovery_guard_rejects_initial_and_final_destinations(self):
        client = HttpClient(HttpSettings(retries=0))
        with self.assertRaises(FetchError):
            client.fetch("test", "https://evil.test/", allowed_url=lambda value: False)
        opener = MagicMock()
        opener.open.return_value = _Response()
        with patch("osintel.http.build_opener", return_value=opener):
            with self.assertRaises(FetchError):
                client.fetch("test", "https://allowed.test/data", allowed_url=lambda value: value.startswith("https://allowed.test/"))

    def test_discovery_size_budget_and_redirect_guard(self):
        client = HttpClient(HttpSettings(retries=0))
        opener = MagicMock()
        opener.open.return_value = _Response(b"12345")
        with patch("osintel.http.build_opener", return_value=opener) as factory:
            with self.assertRaises(FetchError):
                client.fetch("test", "https://example.test/data", allowed_url=lambda value: value.startswith("https://example.test/"), max_bytes=4)
            handler = factory.call_args.args[0]
            with self.assertRaises(FetchError):
                handler.redirect_request(None, None, 302, "redirect", {}, "http://127.0.0.1/private")

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
