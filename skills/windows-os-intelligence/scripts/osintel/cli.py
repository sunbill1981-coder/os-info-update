from __future__ import annotations

import argparse
from datetime import date, timedelta
import json
from pathlib import Path
import sys
from typing import Dict, List, Optional, Sequence, Tuple

from .http import HttpClient, HttpSettings
from .model import Event, parse_date
from .assessment import assess_event
from .correlate import correlate_events
from .report import write_ndjson, write_run_json, write_run_report
from .signals import load_signal_events
from .sources import COLLECTORS, CollectorContext
from .store import Store


class ChineseArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}：参数错误：{message}\n")


def _date_arg(value: str) -> date:
    parsed = parse_date(value)
    if parsed is None:
        raise argparse.ArgumentTypeError("日期必须为 YYYY-MM-DD")
    return parsed


def build_parser(default_workspace: Path) -> argparse.ArgumentParser:
    parser = ChineseArgumentParser(
        description="采集、规范化并评估 Windows 操作系统情报。",
        usage="%(prog)s [选项]",
        add_help=False,
    )
    parser._optionals.title = "选项"
    parser.add_argument("-h", "--help", action="help", help="显示帮助信息并退出")
    parser.add_argument("--mode", choices=("backfill", "rolling", "incremental"), default="incremental")
    parser.add_argument("--start", type=_date_arg, help="历史回填的开始日期（含当日）")
    parser.add_argument("--end", type=_date_arg, help="结束日期（含当日），默认今天")
    parser.add_argument("--days", type=int, help="滚动窗口或首次增量采集的天数")
    parser.add_argument("--sources", help="以英文逗号分隔的来源标识；外部信号使用 signals")
    parser.add_argument("--workspace", type=Path, default=default_workspace, help="项目工作目录")
    parser.add_argument("--config", type=Path, help="来源配置文件路径")
    parser.add_argument("--report-limit", type=int, help="每个报告分组最多展示的事件数")
    parser.add_argument("--taxonomy", type=Path, help="通用风险分类配置文件路径")
    parser.add_argument("--environment", type=Path, help="内部环境画像配置文件路径")
    parser.add_argument("--signals-file", type=Path, help="外部发现信号的 NDJSON 文件")
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
        for field in (
            "products", "editions", "builds", "roles", "components", "change_kinds",
            "preconditions", "affected_workflows", "symptoms", "correlation_keys",
        ):
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
    taxonomy_path = args.taxonomy or workspace / "skills/windows-os-intelligence/config/risk-taxonomy.json"
    environment_path = args.environment or workspace / "skills/windows-os-intelligence/config/environment.json"
    taxonomy = json.loads(taxonomy_path.read_text(encoding="utf-8"))
    environment = json.loads(environment_path.read_text(encoding="utf-8"))
    defaults = config.get("defaults", {})
    try:
        global_start, global_end = _global_window(args, defaults)
    except ValueError as exc:
        parser.error(str(exc))

    selected = list(COLLECTORS)
    include_signals = True
    if args.sources:
        requested = [value.strip() for value in args.sources.split(",") if value.strip()]
        include_signals = "signals" in requested
        selected = [value for value in requested if value != "signals"]
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
    sources_ok = 0

    for source_id in selected:
        source_start, source_end = _source_window(source_id, args, defaults, store)
        print(f"[{source_id}] 采集范围：{source_start.isoformat()} 至 {source_end.isoformat()}", flush=True)
        try:
            result = COLLECTORS[source_id].collect(context, source_start, source_end, config)
            collected.extend(result.events)
            warnings.extend(f"{source_id}: {warning}" for warning in result.warnings)
            store.source_success(source_id, source_end.isoformat(), len(result.events))
            sources_ok += 1
            print(f"[{source_id}] 完成：事件 {len(result.events)} 条，原始文档 {len(result.documents)} 份，警告 {len(result.warnings)} 条", flush=True)
        except Exception as exc:  # Keep independent sources running and expose partial coverage.
            message = f"{type(exc).__name__}: {exc}"
            store.source_failure(source_id, message)
            failures.append({"source_id": source_id, "error": message})
            print(f"[{source_id}] 失败：{message}", file=sys.stderr, flush=True)

    if include_signals:
        signals_path = args.signals_file or workspace / "data/inbox/signals.ndjson"
        try:
            external_events = load_signal_events(signals_path, global_start, global_end)
            collected.extend(external_events)
            store.source_success("external-signals", global_end.isoformat(), len(external_events))
            sources_ok += 1
            print(f"[外部信号] 已载入 {len(external_events)} 条候选情报", flush=True)
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            failures.append({"source_id": "external-signals", "error": message})
            store.source_failure("external-signals", message)
            print(f"[外部信号] 读取失败：{message}", file=sys.stderr, flush=True)

    events = _dedupe(collected)
    for event in events:
        assess_event(event, taxonomy, environment)
    correlate_events(events)
    stats = store.upsert_events(events)
    stats.update({"events": len(events), "sources_ok": sources_ok, "sources_failed": len(failures)})
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
    print(
        f"运行完成：状态={'部分成功' if failures else '成功'}，事件 {len(events)} 条，"
        f"新增 {stats['new']} 条，变化 {stats['changed']} 条，未变 {stats['unchanged']} 条。\n"
        f"中文报告：{report_path}\n规范化数据：{normalized_path}",
        flush=True,
    )
    return 2 if failures else 0


def main() -> None:
    raise SystemExit(run())
