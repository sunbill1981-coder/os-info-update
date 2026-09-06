from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Dict, Iterable, Iterator, List, Optional

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
                    last_count INTEGER NOT NULL DEFAULT 0
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
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS event_changes (
                    change_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    changed_at TEXT NOT NULL,
                    prior_hash TEXT,
                    new_hash TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                """
            )

    def start_run(self, mode: str, window_start: str, window_end: str) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT INTO runs(mode, window_start, window_end, started_at, status) VALUES(?,?,?,?,?)",
                (mode, window_start, window_end, utc_now(), "running"),
            )
            return int(cursor.lastrowid)

    def finish_run(self, run_id: int, status: str, stats: Dict[str, int], error: Optional[str] = None) -> None:
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
            connection.execute(
                """
                INSERT INTO source_state(source_id, checkpoint, last_success, last_error, last_count)
                VALUES(?,?,?,?,?)
                ON CONFLICT(source_id) DO UPDATE SET
                    checkpoint=excluded.checkpoint,
                    last_success=excluded.last_success,
                    last_error=NULL,
                    last_count=excluded.last_count
                """,
                (source_id, checkpoint, utc_now(), None, count),
            )

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

    def upsert_events(self, events: Iterable[Event]) -> Dict[str, int]:
        stats = {"new": 0, "changed": 0, "unchanged": 0}
        now = utc_now()
        with self.connect() as connection:
            for event in events:
                payload = event.payload()
                payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
                content_hash = event.content_hash()
                row = connection.execute(
                    "SELECT content_hash FROM events WHERE event_id=?", (event.event_id,)
                ).fetchone()
                if not row:
                    connection.execute(
                        "INSERT INTO events VALUES(?,?,?,?,?)",
                        (event.event_id, payload_json, content_hash, now, now),
                    )
                    connection.execute(
                        "INSERT INTO event_changes(event_id, changed_at, prior_hash, new_hash, payload_json) VALUES(?,?,?,?,?)",
                        (event.event_id, now, None, content_hash, payload_json),
                    )
                    stats["new"] += 1
                elif row["content_hash"] != content_hash:
                    connection.execute(
                        "UPDATE events SET payload_json=?, content_hash=?, last_seen=? WHERE event_id=?",
                        (payload_json, content_hash, now, event.event_id),
                    )
                    connection.execute(
                        "INSERT INTO event_changes(event_id, changed_at, prior_hash, new_hash, payload_json) VALUES(?,?,?,?,?)",
                        (event.event_id, now, row["content_hash"], content_hash, payload_json),
                    )
                    stats["changed"] += 1
                else:
                    connection.execute("UPDATE events SET last_seen=? WHERE event_id=?", (now, event.event_id))
                    stats["unchanged"] += 1
        return stats

    def list_events(self, limit: Optional[int] = None) -> List[Dict[str, object]]:
        with self.connect() as connection:
            events = [
                json.loads(row["payload_json"])
                for row in connection.execute("SELECT payload_json FROM events")
            ]
        events.sort(key=lambda event: (-int(event.get("risk_score", 0)), str(event.get("event_id", ""))))
        return events[:limit] if limit else events

    def list_source_failures(self) -> List[Dict[str, str]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT source_id, last_error FROM source_state WHERE last_error IS NOT NULL ORDER BY source_id"
            ).fetchall()
            return [{"source_id": row["source_id"], "error": row["last_error"]} for row in rows]
