from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, Iterable, Iterator, List, Optional

from .model import Event, RawDocument, utc_now


class Store:
    def __init__(self, db_path: Path, raw_root: Path):
        self.db_path = db_path
        self.raw_root = raw_root
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.raw_root.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(str(self.db_path))
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def _init_schema(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS runs (
                    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mode TEXT NOT NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    status TEXT NOT NULL,
                    stats_json TEXT NOT NULL DEFAULT '{}',
                    error TEXT
                );
                CREATE TABLE IF NOT EXISTS source_state (
                    source_id TEXT PRIMARY KEY,
                    checkpoint TEXT,
                    last_success TEXT,
                    last_error TEXT,
                    last_count INTEGER NOT NULL DEFAULT 0,
                    zero_streak INTEGER NOT NULL DEFAULT 0,
                    last_nonzero_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS documents (
                    url TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    etag TEXT,
                    last_modified TEXT,
                    sha256 TEXT NOT NULL,
                    raw_path TEXT NOT NULL,
                    fetched_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    fact_hash TEXT,
                    assessment_hash TEXT,
                    hash_schema_version INTEGER NOT NULL DEFAULT 2,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS event_changes (
                    change_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    changed_at TEXT NOT NULL,
                    prior_hash TEXT,
                    new_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    change_type TEXT NOT NULL DEFAULT 'fact_change',
                    changed_fields_json TEXT NOT NULL DEFAULT '[]'
                );
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    source_tier TEXT NOT NULL,
                    publisher TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    excerpt TEXT NOT NULL,
                    raw_hash TEXT,
                    raw_path TEXT,
                    collected_at TEXT NOT NULL,
                    FOREIGN KEY(event_id) REFERENCES events(event_id)
                );
                """
            )
            self._ensure_column(connection, "events", "fact_hash", "TEXT")
            self._ensure_column(connection, "events", "assessment_hash", "TEXT")
            self._ensure_column(connection, "events", "hash_schema_version", "INTEGER NOT NULL DEFAULT 2")
            self._ensure_column(connection, "event_changes", "change_type", "TEXT NOT NULL DEFAULT 'fact_change'")
            self._ensure_column(connection, "event_changes", "changed_fields_json", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(connection, "source_state", "zero_streak", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(connection, "source_state", "last_nonzero_count", "INTEGER NOT NULL DEFAULT 0")

    @staticmethod
    def _ensure_column(connection: sqlite3.Connection, table: str, name: str, declaration: str) -> None:
        existing = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
        if name not in existing:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    def start_run(self, mode: str, window_start: str, window_end: str) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO runs(mode, window_start, window_end, started_at, status) VALUES(?,?,?,?,?)",
                (mode, window_start, window_end, utc_now(), "running"),
            )
            return int(cursor.lastrowid)

    def finish_run(self, run_id: int, status: str, stats: Dict[str, Any], error: Optional[str] = None) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE runs SET finished_at=?, status=?, stats_json=?, error=? WHERE run_id=?",
                (utc_now(), status, json.dumps(stats, sort_keys=True), error, run_id),
            )

    def source_checkpoint(self, source_id: str) -> Optional[str]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT checkpoint FROM source_state WHERE source_id=?", (source_id,)
            ).fetchone()
            return row["checkpoint"] if row else None

    def source_success(self, source_id: str, checkpoint: str, count: int) -> None:
        with self.connect() as connection:
            prior = connection.execute(
                "SELECT zero_streak,last_nonzero_count FROM source_state WHERE source_id=?",
                (source_id,),
            ).fetchone()
            zero_streak = (int(prior["zero_streak"]) if prior else 0) + 1 if count == 0 else 0
            last_nonzero = count if count > 0 else (int(prior["last_nonzero_count"]) if prior else 0)
            connection.execute(
                """
                INSERT INTO source_state(
                    source_id,checkpoint,last_success,last_error,last_count,zero_streak,last_nonzero_count
                ) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(source_id) DO UPDATE SET
                    checkpoint=excluded.checkpoint,
                    last_success=excluded.last_success,
                    last_error=NULL,
                    last_count=excluded.last_count,
                    zero_streak=excluded.zero_streak,
                    last_nonzero_count=excluded.last_nonzero_count
                """,
                (source_id, checkpoint, utc_now(), None, count, zero_streak, last_nonzero),
            )

    def source_observation(self, source_id: str) -> Dict[str, int]:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT last_count,zero_streak,last_nonzero_count FROM source_state WHERE source_id=?",
                (source_id,),
            ).fetchone()
        if not row:
            return {"last_count": 0, "zero_streak": 0, "last_nonzero_count": 0}
        return {name: int(row[name]) for name in ("last_count", "zero_streak", "last_nonzero_count")}

    def source_failure(self, source_id: str, error: str) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO source_state(source_id, last_error) VALUES(?,?)
                ON CONFLICT(source_id) DO UPDATE SET last_error=excluded.last_error
                """,
                (source_id, error[:2000]),
            )

    def document_meta(self, url: str) -> Optional[sqlite3.Row]:
        with self.connect() as connection:
            return connection.execute("SELECT * FROM documents WHERE url=?", (url,)).fetchone()

    def persist_document(self, document: RawDocument) -> RawDocument:
        extension = ".json" if "json" in document.content_type else ".xml" if "xml" in document.content_type else ".html"
        source_dir = self.raw_root / document.source_id
        source_dir.mkdir(parents=True, exist_ok=True)
        path = source_dir / f"{document.sha256}{extension}"
        if not path.exists():
            path.write_bytes(document.body)
        document.raw_path = str(path)
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO documents(url, source_id, etag, last_modified, sha256, raw_path, fetched_at)
                VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(url) DO UPDATE SET
                    source_id=excluded.source_id,
                    etag=excluded.etag,
                    last_modified=excluded.last_modified,
                    sha256=excluded.sha256,
                    raw_path=excluded.raw_path,
                    fetched_at=excluded.fetched_at
                """,
                (document.url, document.source_id, document.etag, document.last_modified,
                 document.sha256, document.raw_path, document.fetched_at),
            )
        return document

    def cached_document(self, url: str) -> Optional[RawDocument]:
        meta = self.document_meta(url)
        if not meta:
            return None
        path = Path(meta["raw_path"])
        if not path.exists():
            return None
        return RawDocument(
            source_id=meta["source_id"], url=url, body=path.read_bytes(),
            content_type="application/octet-stream", fetched_at=meta["fetched_at"],
            etag=meta["etag"], last_modified=meta["last_modified"], sha256=meta["sha256"],
            raw_path=str(path), status=304,
        )

    @staticmethod
    def _changed_fields(prior: Dict[str, Any], current: Dict[str, Any]) -> List[str]:
        return sorted(
            name for name in set(prior).union(current)
            if prior.get(name) != current.get(name)
        )

    def _upsert_evidence(self, connection: sqlite3.Connection, event: Event, now: str) -> None:
        raw_path = ""
        if event.raw_hash:
            row = connection.execute(
                "SELECT raw_path FROM documents WHERE sha256=? ORDER BY fetched_at DESC LIMIT 1",
                (event.raw_hash,),
            ).fetchone()
            raw_path = str(row["raw_path"]) if row else ""
        evidence_id = event.evidence_id()
        connection.execute(
            """
            INSERT INTO evidence(
                evidence_id,event_id,source_id,source_tier,publisher,source_url,
                excerpt,raw_hash,raw_path,collected_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(evidence_id) DO UPDATE SET
                excerpt=excluded.excerpt, raw_hash=excluded.raw_hash,
                raw_path=excluded.raw_path, collected_at=excluded.collected_at
            """,
            (
                evidence_id, event.event_id, event.source_id, event.source_tier,
                event.publisher, event.source_url, event.evidence, event.raw_hash,
                raw_path, now,
            ),
        )

    def upsert_events(self, events: Iterable[Event]) -> Dict[str, Any]:
        stats: Dict[str, Any] = {
            "new": 0, "changed": 0, "fact_changed": 0,
            "assessment_changed": 0, "display_changed": 0, "unchanged": 0,
            "new_ids": [], "fact_changed_ids": [], "assessment_changed_ids": [],
            "display_changed_ids": [], "unchanged_ids": [],
        }
        now = utc_now()
        with self.connect() as connection:
            for event in events:
                payload = event.payload()
                payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
                content_hash = event.record_hash()
                fact_hash = event.fact_hash()
                assessment_hash = event.assessment_hash()
                row = connection.execute(
                    "SELECT payload_json,content_hash,fact_hash,assessment_hash FROM events WHERE event_id=?",
                    (event.event_id,),
                ).fetchone()
                if not row:
                    connection.execute(
                        """
                        INSERT INTO events(
                            event_id,payload_json,content_hash,fact_hash,assessment_hash,
                            hash_schema_version,first_seen,last_seen
                        ) VALUES(?,?,?,?,?,2,?,?)
                        """,
                        (event.event_id, payload_json, content_hash, fact_hash, assessment_hash, now, now),
                    )
                    connection.execute(
                        """
                        INSERT INTO event_changes(
                            event_id,changed_at,prior_hash,new_hash,payload_json,
                            change_type,changed_fields_json
                        ) VALUES(?,?,?,?,?,?,?)
                        """,
                        (event.event_id, now, None, fact_hash, payload_json, "fact_change", json.dumps(sorted(payload))),
                    )
                    stats["new"] += 1
                    stats["new_ids"].append(event.event_id)
                else:
                    prior_payload = json.loads(row["payload_json"])
                    prior_event = Event(**prior_payload)
                    prior_fact_hash = row["fact_hash"] or prior_event.fact_hash()
                    prior_assessment_hash = row["assessment_hash"] or prior_event.assessment_hash()
                    changed_fields = self._changed_fields(prior_payload, payload)
                    if prior_fact_hash != fact_hash:
                        change_type = "fact_change"
                        stats["fact_changed"] += 1
                        stats["fact_changed_ids"].append(event.event_id)
                    elif prior_assessment_hash != assessment_hash:
                        change_type = "assessment_change"
                        stats["assessment_changed"] += 1
                        stats["assessment_changed_ids"].append(event.event_id)
                    elif row["content_hash"] != content_hash:
                        change_type = "display_change"
                        stats["display_changed"] += 1
                        stats["display_changed_ids"].append(event.event_id)
                    else:
                        change_type = ""

                    if change_type:
                        connection.execute(
                            """
                            UPDATE events SET payload_json=?,content_hash=?,fact_hash=?,
                                assessment_hash=?,hash_schema_version=2,last_seen=?
                            WHERE event_id=?
                            """,
                            (payload_json, content_hash, fact_hash, assessment_hash, now, event.event_id),
                        )
                        connection.execute(
                            """
                            INSERT INTO event_changes(
                                event_id,changed_at,prior_hash,new_hash,payload_json,
                                change_type,changed_fields_json
                            ) VALUES(?,?,?,?,?,?,?)
                            """,
                            (
                                event.event_id, now,
                                prior_fact_hash if change_type == "fact_change" else row["content_hash"],
                                fact_hash if change_type == "fact_change" else content_hash,
                                payload_json, change_type,
                                json.dumps(changed_fields, ensure_ascii=False),
                            ),
                        )
                        stats["changed"] += 1
                    else:
                        connection.execute(
                            """
                            UPDATE events SET fact_hash=?,assessment_hash=?,hash_schema_version=2,last_seen=?
                            WHERE event_id=?
                            """,
                            (fact_hash, assessment_hash, now, event.event_id),
                        )
                        stats["unchanged"] += 1
                        stats["unchanged_ids"].append(event.event_id)
                self._upsert_evidence(connection, event, now)
        return stats

    def list_events(self, limit: Optional[int] = None) -> List[Dict[str, object]]:
        with self.connect() as connection:
            events = [
                json.loads(row["payload_json"])
                for row in connection.execute("SELECT payload_json FROM events")
            ]
        events.sort(key=lambda event: (-int(event.get("risk_score", 0)), str(event.get("event_id", ""))))
        return events[:limit] if limit else events

    def related_events(self, events: Iterable[Event], days: int = 30) -> List[Dict[str, object]]:
        current = list(events)
        wanted_keys = {key for event in current for key in event.correlation_keys if key}
        excluded_ids = {event.event_id for event in current}
        if not wanted_keys:
            return []
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(1, days))).replace(microsecond=0).isoformat()
        related: List[Dict[str, object]] = []
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT event_id,payload_json FROM events WHERE last_seen>=?", (cutoff,)
            ).fetchall()
        for row in rows:
            if row["event_id"] in excluded_ids:
                continue
            payload = json.loads(row["payload_json"])
            if wanted_keys.intersection(payload.get("correlation_keys", []) or []):
                related.append(payload)
        return related

    def list_source_failures(self) -> List[Dict[str, str]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT source_id, last_error FROM source_state WHERE last_error IS NOT NULL ORDER BY source_id"
            ).fetchall()
            return [{"source_id": row["source_id"], "error": row["last_error"]} for row in rows]
