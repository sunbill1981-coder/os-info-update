from __future__ import annotations

import argparse
from datetime import date, timedelta
import json
from pathlib import Path
import sys
from typing import Dict, List, Optional, Sequence, Tuple

from .http import HttpClient, HttpSettings
from .model import Event, parse_date
from .report import write_ndjson, write_run_json, write_run_report
from .sources import COLLECTORS, CollectorContext
from .store import Store


def _date_arg(value: str) -> date:
    parsed = parse_date(value)
    if parsed is None:
        raise argparse.ArgumentTypeError("日期必须为 YYYY-MM-DD")
    return parsed


def build_parser(default_workspace: Path) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect and normalize Windows OS intelligence.")
    parser.add_argument("--mode", choices=("backfill", "rolling", "incremental"), default="incremental")
    parser.add_argument("--start", type=_date_arg, help="Inclusive start date for backfill")
    parser.add_argument("--end", type=_date_arg, help="Inclusive end date; defaults to today")
    parser.add_argument("--days", type=int, help="Rolling/fallback window length")
    parser.add_argument("--sources", help="Comma-separated source IDs")
    parser.add_argument("--workspace", type=Path, default=default_workspace)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--report-limit", type=int)
    return parser


def _global_window(args: argparse.Namespace, defaults: Dict[str, object]) -> Tuple[date, date]:
    end = args.end or date.today()
    if args.mode == "backfill":
        if not args.start:
            raise ValueError("backfill 模式必须提供 --start")
        start = args.start
    else:
        days = args.days or int(defaults.get("incremental_days", 7))
        if days < 1:
            raise ValueError("--days 必须大于 0")
        start = end - timedelta(days=days - 1)
    if start > end:
        raise ValueError("开始日期不能晚于结束日期")
    return start, end


def _source_window(source_id: str, args: argparse.Namespace, defaults: Dict[str, object], store: Store) -> Tuple[date, date]:
    start, end = _global_window(args, defaults)
    if args.mode != "incremental":
        return start, end
    checkpoint = parse_date(store.source_checkpoint(source_id))
    if checkpoint:
        overlap_days = max(1, (int(defaults.get("overlap_hours", 72)) + 23) // 24)
        start = min(end, checkpoint - timedelta(days=overlap_days))
    return start, end


def _dedupe(events: Sequence[Event]) -> List[Event]:
    by_id: Dict[str, Event] = {}
    for event in events:
        existing = by_id.get(event.event_id)
        if existing is None:
            by_id[event.event_id] = event
            continue
        event_key = event.updated_at or event.published_at or ""
        existing_key = existing.updated_at or existing.published_at or ""
        winner, other = (event, existing) if event_key >= existing_key else (existing, event)
        for field in ("products", "editions", "builds", "roles", "components"):
            setattr(winner, field, sorted(set(getattr(winner, field) + getattr(other, field))))
        for key, value in other.identifiers.items():
            if key not in winner.identifiers:
                winner.identifiers[key] = value
            elif isinstance(value, list) and isinstance(winner.identifiers[key], list):
                winner.identifiers[key] = sorted(set(winner.identifiers[key] + value))
        if len(other.summary) > len(winner.summary):
            winner.summary = other.summary
        if len(other.evidence) > len(winner.evidence):
            winner.evidence = other.evidence
        winner.risk_score = max(winner.risk_score, other.risk_score)
        winner.confidence = max(winner.confidence, other.confidence)
        by_id[event.event_id] = winner
    return list(by_id.values())


def run(argv: Optional[Sequence[str]] = None) -> int:
    default_workspace = Path(__file__).resolve().parents[4]
    parser = build_parser(default_workspace)
    args = parser.parse_args(argv)
    workspace = args.workspace.resolve()
    config_path = args.config or workspace / "skills/windows-os-intelligence/config/sources.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    defaults = config.get("defaults", {})
    try:
        global_start, global_end = _global_window(args, defaults)
    except ValueError as exc:
        parser.error(str(exc))

    selected = list(COLLECTORS)
    if args.sources:
        selected = [value.strip() for value in args.sources.split(",") if value.strip()]
        unknown = sorted(set(selected) - set(COLLECTORS))
        if unknown:
            parser.error(f"未知来源：{', '.join(unknown)}")

    store = Store(workspace / "data/state/os-intel.sqlite3", workspace / "data/raw")
    http_config = config.get("http", {})
    http = HttpClient(HttpSettings(
        timeout_seconds=int(http_config.get("timeout_seconds", 45)),
        retries=int(http_config.get("retries", 2)),
        user_agent=str(http_config.get("user_agent", "os-info-update/0.1")),
    ))
    context = CollectorContext(http, store)
    run_id = store.start_run(args.mode, global_start.isoformat(), global_end.isoformat())
    collected: List[Event] = []
    warnings: List[str] = []
    failures: List[Dict[str, str]] = []

    for source_id in selected:
        source_start, source_end = _source_window(source_id, args, defaults, store)
        print(f"[{source_id}] {source_start.isoformat()}..{source_end.isoformat()}", flush=True)
        try:
            result = COLLECTORS[source_id].collect(context, source_start, source_end, config)
            collected.extend(result.events)
            warnings.extend(f"{source_id}: {warning}" for warning in result.warnings)
            store.source_success(source_id, source_end.isoformat(), len(result.events))
            print(f"[{source_id}] events={len(result.events)} documents={len(result.documents)} warnings={len(result.warnings)}", flush=True)
        except Exception as exc:  # Keep independent sources running and expose partial coverage.
            message = f"{type(exc).__name__}: {exc}"
            store.source_failure(source_id, message)
            failures.append({"source_id": source_id, "error": message})
            print(f"[{source_id}] failed: {message}", file=sys.stderr, flush=True)

    events = _dedupe(collected)
    stats = store.upsert_events(events)
    stats.update({"events": len(events), "sources_ok": len(selected) - len(failures), "sources_failed": len(failures)})
    status = "partial" if failures else "success"
    store.finish_run(run_id, status, stats, "; ".join(item["error"] for item in failures) or None)

    normalized_path = workspace / "data/normalized/events.ndjson"
    write_ndjson(normalized_path, store.list_events())
    report_limit = args.report_limit or int(defaults.get("report_limit", 100))
    report_path = workspace / f"reports/run-{run_id:06d}.md"
    result_path = workspace / f"reports/run-{run_id:06d}.json"
    current_failures = store.list_source_failures()
    write_run_report(report_path, run_id, args.mode, global_start.isoformat(), global_end.isoformat(), events, stats, warnings, current_failures, report_limit)
    output = {
        "run_id": run_id,
        "status": status,
        "window": {"start": global_start.isoformat(), "end": global_end.isoformat()},
        "stats": stats,
        "warnings": warnings,
        "failures": failures,
        "report": str(report_path),
        "normalized": str(normalized_path),
    }
    write_run_json(result_path, output)
    print(json.dumps(output, ensure_ascii=False, indent=2), flush=True)
    return 2 if failures else 0


def main() -> None:
    raise SystemExit(run())
