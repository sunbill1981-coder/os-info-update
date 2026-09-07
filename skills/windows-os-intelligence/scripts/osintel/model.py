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
        parsed = datetime.fromisoformat(candidate).date()
        return parsed if parsed.year >= 1900 else None
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d", "%B %d, %Y", "%b %d, %Y", "%m/%d/%Y"):
        try:
            parsed = datetime.strptime(value.strip(), fmt).date()
            return parsed if parsed.year >= 1900 else None
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
    change_kinds: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    affected_workflows: List[str] = field(default_factory=list)
    symptoms: List[str] = field(default_factory=list)
    correlation_keys: List[str] = field(default_factory=list)
    identifiers: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    evidence: str = ""
    recommended_action: str = "Review applicability and validate in a representative image."
    risk_score: int = 0
    environment_relevance: int = 0
    action_priority: int = 0
    confidence: int = 0
    corroboration_count: int = 1
    alert_level: str = "留档"
    authoritative_evidence: bool = False
    preview: bool = False
    raw_hash: str = ""

    def normalized(self) -> "Event":
        for name in (
            "products", "editions", "builds", "roles", "components", "change_kinds",
            "preconditions", "affected_workflows", "symptoms",
            "correlation_keys",
        ):
            values = sorted({str(item).strip() for item in getattr(self, name) if str(item).strip()})
            setattr(self, name, values)
        self.risk_score = max(0, min(100, int(self.risk_score)))
        self.environment_relevance = max(0, min(100, int(self.environment_relevance)))
        self.action_priority = max(0, min(100, int(self.action_priority)))
        self.confidence = max(0, min(100, int(self.confidence)))
        self.corroboration_count = max(1, int(self.corroboration_count))
        self.published_at = self._normalized_date(self.published_at)
        self.updated_at = self._normalized_date(self.updated_at)
        return self

    @staticmethod
    def _normalized_date(value: Optional[str]) -> Optional[str]:
        parsed = parse_date(value)
        return parsed.isoformat() if parsed else None

    def payload(self) -> Dict[str, Any]:
        return asdict(self.normalized())

    def content_hash(self) -> str:
        """兼容旧调用方：记录指纹反映整条可展示记录。"""
        return self.record_hash()

    def fact_payload(self) -> Dict[str, Any]:
        value = self.payload()
        names = (
            "event_id", "title", "event_type", "status", "source_id", "source_tier",
            "source_url", "publisher", "published_at", "updated_at", "products",
            "editions", "builds", "roles", "identifiers", "summary", "evidence",
        )
        return {name: value[name] for name in names}

    def assessment_payload(self) -> Dict[str, Any]:
        value = self.payload()
        names = (
            "components", "change_kinds", "preconditions", "affected_workflows",
            "symptoms", "correlation_keys", "recommended_action", "risk_score",
            "environment_relevance", "action_priority", "confidence",
            "corroboration_count", "alert_level", "authoritative_evidence", "preview",
        )
        return {name: value[name] for name in names}

    def fact_hash(self) -> str:
        return "fact-v2:" + stable_hash(self.fact_payload())

    def evidence_id(self) -> str:
        return "evidence:" + self.fact_hash().split(":", 1)[1][:24]

    def assessment_hash(self) -> str:
        return "assessment-v1:" + stable_hash(self.assessment_payload())

    def record_hash(self) -> str:
        value = self.payload()
        value.pop("raw_hash", None)
        return "record-v1:" + stable_hash(value)


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
    coverage_errors: List[str] = field(default_factory=list)
    metrics: Dict[str, int] = field(default_factory=dict)
