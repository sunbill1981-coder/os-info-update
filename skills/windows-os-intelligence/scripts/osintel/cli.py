from __future__ import annotations

import argparse
from datetime import date, timedelta
import json
from pathlib import Path
import sys
from typing import Dict, List, Optional, Sequence, Tuple

from .http import HttpClient, HttpSettings
from .model import Event, parse_date, utc_now
from .assessment import assess_event
from .correlate import correlate_events
from .enrichment import enrich_events, threat_urgency
from .report import write_ndjson, write_run_html, write_run_json, write_run_report
from .signals import load_signal_events
from .sources import COLLECTORS, CollectorContext
from .store import Store
from .scope import merge_scopes
from .discovery import DiscoveryCollector, read_discovery_coverage
from .triage import build_triage
from .runtime import RunSpace, PURPOSES
from .continuity import build_context
from .themes import store_themes
from .engineer_report import write_engineer_bundle, write_latest_entry


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
    parser.add_argument("--sources", help="以英文逗号分隔；外部信号 signals，已核验专项／社区 discovery")
    parser.add_argument("--workspace", type=Path, default=default_workspace, help="项目工作目录")
    parser.add_argument("--purpose", choices=PURPOSES, default="trial", help="隔离运行用途，默认 trial；旧数据不会自动导入")
    parser.add_argument("--config", type=Path, help="来源配置文件路径")
    parser.add_argument("--report-limit", type=int, help="每个报告分组最多展示的事件数")
    parser.add_argument("--taxonomy", type=Path, help="通用风险分类配置文件路径")
    parser.add_argument("--triage-config", type=Path, help="外部核验摘要的通用分诊与展示配置")
    parser.add_argument("--environment", type=Path, help="内部环境画像配置文件路径")
    parser.add_argument("--signals-file", type=Path, help="外部发现信号的 NDJSON 文件")
    parser.add_argument("--discovery-reviewed-file", type=Path, help="已核对正文的专项／社区 NDJSON 文件")
    parser.add_argument("--discovery-config", type=Path, help="专项／社区来源白名单配置")
    parser.add_argument("--no-enrichment", action="store_true", help="跳过 KEV、EPSS 等外部增强来源")
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
        event.normalized()
        existing = by_id.get(event.event_id)
        if existing is None:
            by_id[event.event_id] = event
            continue
        event_key = (event.updated_at or event.published_at or "", event.source_activity.get("document_updated_at", ""), event.source_url)
        existing_key = (existing.updated_at or existing.published_at or "", existing.source_activity.get("document_updated_at", ""), existing.source_url)
        winner, other = (event, existing) if event_key >= existing_key else (existing, event)
        if winner.source_id == other.source_id == "msrc":
            # Different CVRF documents are successive full observations of
            # this CVE. Unioning an older scope could undo an explicit removal.
            by_id[event.event_id] = winner
            continue
        for field in (
            "products", "editions", "builds", "roles", "components", "change_kinds",
            "preconditions", "affected_workflows", "symptoms", "correlation_keys",
        ):
            setattr(winner, field, sorted(set(getattr(winner, field) + getattr(other, field))))
        for field in ("source_references", "update_details"):
            combined = getattr(winner, field) + getattr(other, field)
            unique = {json.dumps(value, ensure_ascii=False, sort_keys=True): value for value in combined}
            setattr(winner, field, [unique[key] for key in sorted(unique)])
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
        winner.affected_scope = merge_scopes([winner.affected_scope, other.affected_scope])
        winner.confidence = max(winner.confidence, other.confidence)
        by_id[event.event_id] = winner
    return list(by_id.values())


def _restore_failed_enrichment(
    events: Sequence[Event], stored: Dict[str, Event], failed_sources: Sequence[str],
) -> None:
    """Keep the last known enrichment for existing events after a transient outage."""
    failed = set(failed_sources)
    for event in events:
        prior = stored.get(event.event_id)
        if prior is None:
            continue
        if "cisa-kev" in failed:
            event.kev = dict(prior.kev)
            if "cisa_kev" in prior.field_status:
                event.field_status["cisa_kev"] = prior.field_status["cisa_kev"]
            else:
                event.field_status.pop("cisa_kev", None)
        if "first-epss" in failed:
            event.epss = dict(prior.epss)
            if "first_epss" in prior.field_status:
                event.field_status["first_epss"] = prior.field_status["first_epss"]
            else:
                event.field_status.pop("first_epss", None)
        event.threat_urgency = threat_urgency(event)


def _report_scope(
    events: Sequence[Event], stats: Dict[str, object], window_event_ids: set,
) -> Tuple[List[Event], Dict[str, object]]:
    """Historical threat-feed refreshes belong in storage, not in the monthly report."""
    visible = [event for event in events if event.event_id in window_event_ids]
    report_stats = dict(stats)
    for key, value in stats.items():
        if key.endswith('_ids') and isinstance(value, list):
            matching = [event_id for event_id in value if event_id in window_event_ids]
            report_stats[key] = matching
            report_stats[key[:-4]] = len(matching)
    report_stats['changed'] = len(set(report_stats.get('fact_changed_ids', [])) | set(report_stats.get('assessment_changed_ids', [])) | set(report_stats.get('display_changed_ids', [])))
    report_stats['events'] = len(visible)
    return visible, report_stats


def run(argv: Optional[Sequence[str]] = None) -> int:
    default_workspace = Path(__file__).resolve().parents[4]
    parser = build_parser(default_workspace)
    args = parser.parse_args(argv)
    workspace = args.workspace.resolve()
    space = RunSpace(workspace, args.purpose)
    signals_path = space.input(args.signals_file, "data/inbox/signals.ndjson")
    config_path = args.config or workspace / "skills/windows-os-intelligence/config/sources.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["discovery_config"] = str(args.discovery_config or workspace / "skills/windows-os-intelligence/config/discovery.json")
    config["discovery_reviewed_file"] = str(space.input(args.discovery_reviewed_file, "data/discovery/reviewed.ndjson"))
    collectors = dict(COLLECTORS, discovery=DiscoveryCollector())
    taxonomy_path = args.taxonomy or workspace / "skills/windows-os-intelligence/config/risk-taxonomy.json"
    local_environment = workspace / "skills/windows-os-intelligence/config/environment.local.json"
    environment_path = args.environment or (
        local_environment if local_environment.exists()
        else workspace / "skills/windows-os-intelligence/config/environment.json"
    )
    taxonomy = json.loads(taxonomy_path.read_text(encoding="utf-8"))
    environment = json.loads(environment_path.read_text(encoding="utf-8"))
    triage_path = args.triage_config or Path(__file__).resolve().parents[2] / "config/triage.json"
    triage_config = json.loads(triage_path.read_text(encoding="utf-8"))
    # Validate the reading policy before collection or state changes begin.
    try:
        build_triage([], run_at=utc_now(), config=triage_config)
    except (ValueError, TypeError, KeyError) as exc:
        parser.error(f"外部分诊配置无效：{exc}")
    defaults = config.get("defaults", {})
    try:
        global_start, global_end = _global_window(args, defaults)
    except ValueError as exc:
        parser.error(str(exc))

    selected = list(COLLECTORS)
    discovery_folder = space.root / "data/discovery"
    if Path(config["discovery_reviewed_file"]).exists() or (discovery_folder / "latest-run.json").exists():
        selected.append("discovery")
    include_signals = True
    if args.sources:
        requested = [value.strip() for value in args.sources.split(",") if value.strip()]
        include_signals = "signals" in requested
        selected = [value for value in requested if value != "signals"]
        unknown = sorted(set(selected) - set(collectors))
        if unknown:
            parser.error(f"未知来源：{', '.join(unknown)}")

    space.ensure()
    runtime = space.metadata()
    store = Store(space.db, space.root / "data/raw")
    runtime.update(active_dataset=store.metadata("active-dataset"), active_dataset_status="approved" if store.metadata("active-dataset") else None)
    store.set_metadata("runtime", runtime)
    http_config = config.get("http", {})
    http = HttpClient(HttpSettings(
        timeout_seconds=int(http_config.get("timeout_seconds", 45)),
        retries=int(http_config.get("retries", 2)),
        user_agent=str(http_config.get("user_agent", "os-info-update/0.1")),
        max_retry_delay_seconds=int(http_config.get("max_retry_delay_seconds", 60)),
    ))
    context = CollectorContext(http, store)
    run_id = store.start_run(args.mode, global_start.isoformat(), global_end.isoformat())
    collected: List[Event] = []
    warnings: List[str] = []
    failures: List[Dict[str, str]] = []
    sources_ok = 0
    source_coverage: Dict[str, object] = {}

    for source_id in selected:
        source_start, source_end = _source_window(source_id, args, defaults, store)
        print(f"[{source_id}] 采集范围：{source_start.isoformat()} 至 {source_end.isoformat()}", flush=True)
        try:
            result = collectors[source_id].collect(context, source_start, source_end, config)
            source_coverage[source_id] = {
                "metrics": result.metrics,
                "documents": [{"url": raw.url, "sha256": raw.sha256} for raw in result.documents],
            }
            collected.extend(result.events)
            warnings.extend(f"{source_id}: {warning}" for warning in result.warnings)
            if result.coverage_errors:
                message = "解析覆盖异常：" + "；".join(result.coverage_errors)
                store.source_failure(source_id, message)
                failures.append({"source_id": source_id, "error": message})
                warnings.extend(f"{source_id}: {value}" for value in result.coverage_errors)
                print(f"[{source_id}] 覆盖异常：{message}", file=sys.stderr, flush=True)
            else:
                observation = store.source_observation(source_id)
                if not result.events and observation["last_nonzero_count"] > 0:
                    streak = observation["zero_streak"] + 1
                    warnings.append(
                        f"{source_id}: 本轮产出为 0；过去非零产出为 "
                        f"{observation['last_nonzero_count']}，已连续 {streak} 轮为 0，"
                        "请关注覆盖趋势。"
                    )
                store.source_success(source_id, source_end.isoformat(), len(result.events))
                sources_ok += 1
            print(
                f"[{source_id}] 完成：事件 {len(result.events)} 条，"
                f"原始文档 {len(result.documents)} 份，警告 {len(result.warnings)} 条，"
                f"覆盖异常 {len(result.coverage_errors)} 条",
                flush=True,
            )
        except Exception as exc:  # Keep independent sources running and expose partial coverage.
            message = f"{type(exc).__name__}: {exc}"
            store.source_failure(source_id, message)
            failures.append({"source_id": source_id, "error": message})
            print(f"[{source_id}] 失败：{message}", file=sys.stderr, flush=True)

    if include_signals:
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
    window_event_ids = {event.event_id for event in events}
    for event in events:
        assess_event(event, taxonomy, environment)
    correlate_events(events)
    historical_related = [Event(**payload) for payload in store.related_events(events, days=30)]
    if historical_related:
        events = _dedupe(events + historical_related)
        for event in events:
            assess_event(event, taxonomy, environment)
        correlate_events(events)
    if not args.no_enrichment and config.get("enrichment"):
        current_ids = {event.event_id for event in events}
        stored_vulnerabilities = [
            Event(**payload) for payload in store.list_events()
            if payload.get("event_type") == "vulnerability"
        ]
        stored_by_id = {event.event_id: event for event in stored_vulnerabilities}
        # Current source observations supersede stored ones. Only append
        # historical identities that were not fetched in this run.
        candidates = events + [event for event in stored_vulnerabilities if event.event_id not in current_ids]
        before = {event.event_id: event.record_hash() for event in candidates}
        enrichment_result = enrich_events(candidates, context, config.get("enrichment", {}))
        _restore_failed_enrichment(
            candidates, stored_by_id,
            [item["source_id"] for item in enrichment_result.failures],
        )
        warnings.extend(enrichment_result.warnings)
        failures.extend(enrichment_result.failures)
        for item in enrichment_result.failures:
            store.source_failure(item["source_id"], item["error"])
        for source_id, count in enrichment_result.successful_sources.items():
            store.source_success(source_id, global_end.isoformat(), count)
            sources_ok += 1
        for event in candidates:
            assess_event(event, taxonomy, environment)
        events = [
            event for event in candidates
            if event.event_id in current_ids or event.record_hash() != before[event.event_id]
        ]
    stats = store.upsert_events(events)
    store.set_metadata("live-event-ids", sorted(set(store.metadata("live-event-ids", [])) | window_event_ids))
    stats.update({"events": len(events), "sources_ok": sources_ok, "sources_failed": len(failures)})
    status = "partial" if failures else "success"
    store.finish_run(run_id, status, stats, "; ".join(item["error"] for item in failures) or None)
    storage_stats = stats
    events, stats = _report_scope(events, stats, window_event_ids)
    discovery_coverage = read_discovery_coverage(discovery_folder, global_start, global_end)
    warnings = list(dict.fromkeys(warnings + discovery_coverage["coverage_gaps"]))
    delta_ids = set(stats.get("new_ids", [])) | set(stats.get("fact_changed_ids", [])) | set(stats.get("assessment_changed_ids", []))
    triage_events = events if args.mode != "incremental" else [event for event in events if event.event_id in delta_ids]
    triage = build_triage(triage_events, run_at=utc_now(), config=triage_config)
    continuity_config = json.loads((Path(__file__).resolve().parents[2] / "config/continuity.json").read_text())
    continuity = build_context(store, events, budget=continuity_config["candidate_budget"])
    triage["runtime"] = runtime
    triage["continuity"] = continuity
    triage["themes"] = store_themes(store, [Event(**row) for row in store.list_events()])
    warnings.extend(continuity["coverage_gaps"])

    normalized_path = space.root / "data/normalized/events.ndjson"
    write_ndjson(normalized_path, store.list_events())
    report_limit = args.report_limit or int(defaults.get("report_limit", 100))
    report_path = space.root / f"reports/run-{run_id:06d}.md"
    html_report_path = space.root / f"reports/run-{run_id:06d}.html"
    latest_html_path = space.root / "reports/latest.html"
    result_path = space.root / f"reports/run-{run_id:06d}.json"
    report_data_path = space.root / f"reports/run-{run_id:06d}.ndjson"
    triage_path = space.root / f"reports/run-{run_id:06d}.triage.json"
    write_ndjson(report_data_path, (event.payload() for event in events))
    write_run_json(triage_path, triage)
    current_failures = store.list_source_failures()
    write_run_report(report_path, run_id, args.mode, global_start.isoformat(), global_end.isoformat(), events, stats, warnings, current_failures, report_limit, environment, triage)
    template_path = Path(__file__).resolve().parents[2] / "assets/report-template.html"
    write_run_html(
        html_report_path, template_path, run_id, args.mode,
        global_start.isoformat(), global_end.isoformat(), events,
        stats, warnings, current_failures, environment, triage,
    )
    latest_html_path.write_bytes(html_report_path.read_bytes())
    engineer_report = write_engineer_bundle(space.root / f"reports/run-{run_id:06d}.engineer",
        [Event(**row) for row in store.list_events()], triage, global_start.isoformat(), global_end.isoformat(), warnings, current_failures, environment)
    latest_engineer = write_latest_entry(space.root / 'reports', engineer_report['index'])
    output = {
        **runtime,
        "origin": "collection",
        "mode": args.mode,
        "run_id": run_id,
        "status": "partial" if failures or discovery_coverage["coverage_gaps"] or continuity["coverage_gaps"] else "success",
        "acquisition_status": status,
        "window": {"start": global_start.isoformat(), "end": global_end.isoformat()},
        "stats": stats,
        "storage_stats": storage_stats,
        "warnings": warnings,
        "failures": failures,
        "source_coverage": source_coverage,
        "discovery_coverage": discovery_coverage,
        "triage_report": str(triage_path),
        "triage_summary": triage["summary"],
        "report": str(report_path),
        "html_report": str(html_report_path),
        "engineer_report": engineer_report,
        "latest_engineer_report": latest_engineer,
        "latest_html_report": str(latest_html_path),
        "normalized": str(normalized_path),
        "report_data": str(report_data_path),
    }
    write_run_json(result_path, output)
    store.set_metadata("latest-report", str(result_path))
    store.set_metadata("continuity-report-state", continuity["state"])
    print(
        f"运行完成：采集状态={'部分成功' if failures else '成功'}，事件 {len(events)} 条，"
        f"新增 {stats['new']} 条，变化 {stats['changed']} 条，未变 {stats['unchanged']} 条。\n"
        f"工程师首页：{engineer_report['index']}\n离线报告包：{engineer_report['zip']}\n"
        f"中文报告：{report_path}\n全量 HTML：{html_report_path}\n"
        f"最新 HTML：{latest_html_path}\n外部核验清单：{triage_path}\n"
        f"外部发现：计划 {discovery_coverage['planned']} 项，完成 {discovery_coverage['completed']} 项；"
        f"覆盖缺口 {len(discovery_coverage['coverage_gaps'])} 项（采集成功不等于发现完成）。\n"
        f"规范化数据：{normalized_path}",
        flush=True,
    )
    return 2 if failures else 0


def main() -> None:
    raise SystemExit(run())
