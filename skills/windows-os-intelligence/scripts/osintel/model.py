from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_hash(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def parse_date(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
    candidate = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(candidate).date()
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d", "%B %d, %Y", "%b %d, %Y", "%m/%d/%Y"):
        try:
            return datetime.strptime(value.strip(), fmt).date()
        except ValueError:
            continue
    return None


@dataclass
class Event:
    event_id: str
    title: str
    event_type: str
    status: str
    source_id: str
    source_tier: str
    source_url: str
    publisher: str = "Microsoft"
    published_at: Optional[str] = None
    updated_at: Optional[str] = None
    products: List[str] = field(default_factory=list)
    editions: List[str] = field(default_factory=lambda: ["not specified"])
    builds: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=lambda: ["unknown"])
    components: List[str] = field(default_factory=list)
    identifiers: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    evidence: str = ""
    recommended_action: str = "Review applicability and validate in a representative image."
    risk_score: int = 0
    confidence: int = 0
    preview: bool = False
    raw_hash: str = ""

    def normalized(self) -> "Event":
        for name in ("products", "editions", "builds", "roles", "components"):
            values = sorted({str(item).strip() for item in getattr(self, name) if str(item).strip()})
            setattr(self, name, values)
        self.risk_score = max(0, min(100, int(self.risk_score)))
        self.confidence = max(0, min(100, int(self.confidence)))
        return self

    def payload(self) -> Dict[str, Any]:
        return asdict(self.normalized())

    def content_hash(self) -> str:
        value = self.payload()
        value.pop("raw_hash", None)
        return stable_hash(value)


@dataclass
class RawDocument:
    source_id: str
    url: str
    body: bytes
    content_type: str
    fetched_at: str
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    status: int = 200
    sha256: str = ""
    raw_path: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.sha256:
            self.sha256 = hashlib.sha256(self.body).hexdigest()


@dataclass
class SourceResult:
    source_id: str
    events: List[Event] = field(default_factory=list)
    documents: List[RawDocument] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

