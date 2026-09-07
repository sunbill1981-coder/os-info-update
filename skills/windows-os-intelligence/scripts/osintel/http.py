from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import random
import time
from typing import Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .model import RawDocument, utc_now


class FetchError(RuntimeError):
    def __init__(self, url: str, message: str, status: Optional[int] = None):
        super().__init__(f"{url}: {message}")
        self.url = url
        self.status = status


@dataclass
class HttpSettings:
    timeout_seconds: int = 45
    retries: int = 2
    user_agent: str = "os-info-update/0.1"
    max_retry_delay_seconds: int = 60


def _retry_after_seconds(value: Optional[str], maximum: int) -> Optional[float]:
    if not value:
        return None
    try:
        return min(maximum, max(0.0, float(value)))
    except ValueError:
        try:
            target = parsedate_to_datetime(value)
            if target.tzinfo is None:
                target = target.replace(tzinfo=timezone.utc)
            seconds = (target - datetime.now(timezone.utc)).total_seconds()
            return min(maximum, max(0.0, seconds))
        except (TypeError, ValueError, OverflowError):
            return None


class HttpClient:
    def __init__(self, settings: HttpSettings):
        self.settings = settings

    def fetch(
        self,
        source_id: str,
        url: str,
        accept: str = "text/html,application/json,application/xml,text/xml;q=0.9,*/*;q=0.8",
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
    ) -> RawDocument:
        headers: Dict[str, str] = {
            "User-Agent": self.settings.user_agent,
            "Accept": accept,
            "Accept-Encoding": "identity",
        }
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

        last_error: Optional[Exception] = None
        for attempt in range(self.settings.retries + 1):
            retry_after: Optional[float] = None
            try:
                request = Request(url, headers=headers)
                with urlopen(request, timeout=self.settings.timeout_seconds) as response:
                    return RawDocument(
                        source_id=source_id,
                        url=response.geturl(),
                        body=response.read(),
                        content_type=response.headers.get("Content-Type", "application/octet-stream"),
                        fetched_at=utc_now(),
                        etag=response.headers.get("ETag"),
                        last_modified=response.headers.get("Last-Modified"),
                        status=getattr(response, "status", 200),
                    )
            except HTTPError as exc:
                if exc.code == 304:
                    return RawDocument(
                        source_id=source_id,
                        url=url,
                        body=b"",
                        content_type=exc.headers.get("Content-Type", "application/octet-stream"),
                        fetched_at=utc_now(),
                        etag=etag,
                        last_modified=last_modified,
                        status=304,
                    )
                if exc.code == 404:
                    raise FetchError(url, "not found", 404) from exc
                last_error = exc
                if exc.code < 500 and exc.code != 429:
                    break
                if exc.code in {429, 503}:
                    retry_after = _retry_after_seconds(
                        exc.headers.get("Retry-After"), self.settings.max_retry_delay_seconds,
                    )
            except (URLError, TimeoutError, OSError) as exc:
                last_error = exc
            if attempt < self.settings.retries:
                base_delay = retry_after if retry_after is not None else min(2 ** attempt, 8)
                jitter = random.uniform(0, min(0.5, base_delay * 0.1)) if base_delay else 0
                time.sleep(min(self.settings.max_retry_delay_seconds, base_delay + jitter))
        status = last_error.code if isinstance(last_error, HTTPError) else None
        raise FetchError(url, str(last_error or "unknown fetch error"), status)
