from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict
from urllib.parse import urlparse

from .assessment import assess_event
from .model import Event
from .report import write_ndjson
from .store import Store


TRUSTED_MICROSOFT_HOSTS = {
    "api.msrc.microsoft.com", "msrc.microsoft.com", "learn.microsoft.com",
    "support.microsoft.com", "blogs.windows.com",
}


def infer_authoritative(payload: Dict[str, Any]) -> bool:
    host = (urlparse(str(payload.get("source_url") or "")).hostname or "").casefold()
    tier = str(payload.get("source_tier") or "").upper()
    source_id = str(payload.get("source_id") or "")
    return (
        host in TRUSTED_MICROSOFT_HOSTS
        and tier in {"P0", "P1"}
        and source_id not in {"external-signal", "windows-insider-sitemap"}
    )


def inspect_database(db_path: Path) -> Dict[str, int]:
    result = {"events": 0, "normalized_dates": 0, "authority_updates": 0}
    with sqlite3.connect(str(db_path)) as connection:
        rows = connection.execute("SELECT payload_json FROM events").fetchall()
    for row in rows:
        payload = json.loads(row[0])
        result["events"] += 1
        before_dates = (payload.get("published_at"), payload.get("updated_at"))
        event = Event(**payload)
        event.authoritative_evidence = infer_authoritative(payload)
        normalized = event.payload()
        if before_dates != (normalized.get("published_at"), normalized.get("updated_at")):
            result["normalized_dates"] += 1
        if bool(payload.get("authoritative_evidence", False)) != event.authoritative_evidence:
            result["authority_updates"] += 1
    return result


def apply_migration(workspace: Path) -> Dict[str, Any]:
    db_path = workspace / "data/state/os-intel.sqlite3"
    if not db_path.exists():
        raise FileNotFoundError(f"找不到状态库：{db_path}")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = db_path.with_name(f"{db_path.name}.before-v2-{timestamp}.bak")
    with sqlite3.connect(str(db_path)) as source, sqlite3.connect(str(backup_path)) as target:
        source.backup(target)

    store = Store(db_path, workspace / "data/raw")
    config_root = workspace / "skills/windows-os-intelligence/config"
    taxonomy = json.loads((config_root / "risk-taxonomy.json").read_text(encoding="utf-8"))
    local_environment = config_root / "environment.local.json"
    environment_path = local_environment if local_environment.exists() else config_root / "environment.json"
    environment = json.loads(environment_path.read_text(encoding="utf-8"))
    updated = 0
    with store.connect() as connection:
        rows = connection.execute("SELECT event_id,payload_json FROM events").fetchall()
        collected_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        for row in rows:
            payload = json.loads(row["payload_json"])
            event = Event(**payload)
            event.authoritative_evidence = infer_authoritative(payload)
            assess_event(event, taxonomy, environment)
            normalized = event.payload()
            connection.execute(
                """
                UPDATE events SET payload_json=?,content_hash=?,fact_hash=?,assessment_hash=?,
                    hash_schema_version=2 WHERE event_id=?
                """,
                (
                    json.dumps(normalized, ensure_ascii=False, sort_keys=True),
                    event.record_hash(), event.fact_hash(), event.assessment_hash(), event.event_id,
                ),
            )
            store._upsert_evidence(connection, event, collected_at)
            updated += 1

    write_ndjson(workspace / "data/normalized/events.ndjson", store.list_events())
    return {"updated": updated, "backup": str(backup_path)}
