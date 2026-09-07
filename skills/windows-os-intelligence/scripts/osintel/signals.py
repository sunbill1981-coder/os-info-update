from __future__ import annotations

from datetime import date
import json
from pathlib import Path
from typing import Dict, List

from .model import Event, parse_date, stable_hash


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
        source_url = str(record.get("source_url") or "")
        title = str(record.get("title") or "").strip()
        if not source_url or not title:
            raise ValueError(f"{path}:{line_number} 缺少 title 或 source_url")
        event_id = str(record.get("event_id") or f"signal:{stable_hash([source_url, title])[:24]}")
        requested_tier = str(record.get("source_tier") or "P3").upper()
        # 收件箱是候选证据入口，不能通过自报 P0/P1 或佐证数越过权威性闸门。
        source_tier = requested_tier if requested_tier in {"P2", "P3"} else "P2"
        confidence = min(84, int(record.get("confidence") or 50))
        event = Event(
            event_id=event_id,
            title=title,
            event_type=str(record.get("event_type") or "compatibility"),
            status=str(record.get("status") or "reported"),
            source_id=str(record.get("source_id") or "external-signal"),
            source_tier=source_tier,
            source_url=source_url,
            publisher=str(record.get("publisher") or "未知发布者"),
            published_at=record.get("published_at"),
            updated_at=record.get("updated_at"),
            products=list(record.get("products") or []),
            editions=list(record.get("editions") or ["not specified"]),
            builds=list(record.get("builds") or []),
            roles=list(record.get("roles") or ["unknown"]),
            components=list(record.get("components") or []),
            change_kinds=list(record.get("change_kinds") or []),
            preconditions=list(record.get("preconditions") or []),
            affected_workflows=list(record.get("affected_workflows") or []),
            symptoms=list(record.get("symptoms") or []),
            correlation_keys=list(record.get("correlation_keys") or []),
            identifiers=dict(record.get("identifiers") or {}),
            summary=str(record.get("summary") or ""),
            evidence=str(record.get("evidence") or ""),
            recommended_action=str(record.get("recommended_action") or "核验适用范围并安排代表性环境测试。"),
            risk_score=int(record.get("risk_score") or 0),
            confidence=confidence,
            corroboration_count=1,
            authoritative_evidence=False,
            preview=bool(record.get("preview", False)),
            raw_hash=str(record.get("raw_hash") or stable_hash(record)),
        )
        events.append(event)
    return events
