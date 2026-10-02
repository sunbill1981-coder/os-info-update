from __future__ import annotations

from datetime import date
import json
from pathlib import Path
from typing import Dict, List

from .model import Event, parse_date, stable_hash


def signal_event(record: dict) -> Event:
    """Inbox conversion is deliberately untrusted; provenance is not self-certified."""
    source_url = str(record.get("source_url") or "")
    title = str(record.get("title") or "").strip()
    if not source_url or not title:
        raise ValueError("缺少 title 或 source_url")
    requested_tier = str(record.get("source_tier") or "P3").upper()
    fields = {name: record[name] for name in (
        "published_at", "updated_at", "products", "editions", "builds", "roles", "components",
        "change_kinds", "preconditions", "affected_workflows", "symptoms", "correlation_keys", "identifiers",
        "summary", "evidence", "recommended_action", "risk_score", "preview",
    ) if name in record and record[name] is not None}
    fields.setdefault("recommended_action", "核验适用范围并安排代表性环境测试。")
    return Event(
        event_id=str(record.get("event_id") or f"signal:{stable_hash([source_url, title])[:24]}"),
        title=title, event_type=str(record.get("event_type") or "compatibility"),
        status=str(record.get("status") or "reported"),
        source_id=str(record.get("source_id") or "external-signal"),
        source_tier=requested_tier if requested_tier in {"P2", "P3"} else "P2",
        source_url=source_url, publisher=str(record.get("publisher") or "未知发布者"),
        confidence=min(84, int(record.get("confidence") or 50)),
        corroboration_count=1, authoritative_evidence=False,
        raw_hash=str(record.get("raw_hash") or stable_hash(record)), **fields,
    )


def load_signal_events(path: Path, start: date, end: date) -> List[Event]:
    if not path.exists():
        return []
    events: List[Event] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        record = json.loads(line)
        observed_dates = [parse_date(record.get(name)) for name in ("published_at", "updated_at")]
        observed_dates = [value for value in observed_dates if value]
        if observed_dates and not any(start <= value <= end for value in observed_dates):
            continue
        try:
            events.append(signal_event(record))
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number} {exc}") from exc
    return events
