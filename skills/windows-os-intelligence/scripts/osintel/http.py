from __future__ import annotations

from dataclasses import dataclass
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
            except (URLError, TimeoutError, OSError) as exc:
                last_error = exc
            if attempt < self.settings.retries:
                time.sleep(min(2 ** attempt, 4))
        status = last_error.code if isinstance(last_error, HTTPError) else None
        raise FetchError(url, str(last_error or "unknown fetch error"), status)

