#!/usr/bin/env python3
"""Local lifecycle operations. This command never sends messages or uploads files."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
from uuid import uuid4

from osintel.continuity import build_context, validate_review
from osintel.datasets import (approve_package, import_package, make_package, read_package,
                              reprocess, write_package)
from osintel.model import Event, utc_now
from osintel.report import write_ndjson, write_run_html, write_run_json, write_run_report
from osintel.runtime import PURPOSES, RunSpace, report_resources
from osintel.store import Store
from osintel.triage import build_triage
from osintel.themes import validate_theme, store_themes
from osintel.engineer_report import write_engineer_bundle, write_latest_entry

SKILL = Path(__file__).resolve().parents[1]


def read_rows(path):
    text = path.read_text(encoding="utf-8")
    try:
        value = json.loads(text)
        rows = value if isinstance(value, list) else [value]
    except json.JSONDecodeError:
        rows = [json.loads(s) for s in text.splitlines() if s.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("输入必须为 JSON 对象、数组或 NDJSON")
    return rows


@contextmanager
def open_store(space, preview=False):
    if not preview:
        space.ensure()
        yield Store(space.db, space.root / "data/raw")
        return
    # Preview never creates or migrates the target database.
    with tempfile.TemporaryDirectory() as folder:
        db = Path(folder) / "preview.sqlite3"
        if space.db.exists():
            with sqlite3.connect(space.db.as_uri() + "?mode=ro", uri=True) as source, sqlite3.connect(db) as dest:
                source.backup(dest)
        yield Store(db, Path(folder) / "raw")


def render(space, store, origin="review", limitations=None):
    events = [Event(**e) for e in store.list_events()]
    context = build_context(store, events)
    triage = build_triage(events, run_at=utc_now())
    runtime = dict(space.metadata(), active_dataset=store.metadata("active-dataset"),
                   active_dataset_status="approved" if store.metadata("active-dataset") else None)
    triage.update(runtime=runtime, continuity=context, themes=store_themes(store, events))
    dates = sorted(e.published_at for e in events if e.published_at)
    start, end = (dates[0][:10], dates[-1][:10]) if dates else (utc_now()[:10], utc_now()[:10])
    label = "analysis-" + uuid4().hex[:12]
    base = space.root / "reports" / label
    paths = {suffix: Path(str(base) + "." + suffix) for suffix in ("html", "md", "json", "ndjson", "triage.json")}
    warnings = list(limitations or []) + context["coverage_gaps"] + ["本地重评/复核视图，不是窗口内实时采集；不得补发历史告警。"]
    write_ndjson(paths["ndjson"], (e.payload() for e in events))
    write_ndjson(space.root / "data/normalized/events.ndjson", store.list_events())
    write_run_json(paths["triage.json"], triage)
    write_run_html(paths["html"], SKILL / "assets/report-template.html", label, "rolling", start, end,
                   events, {}, warnings, [], triage=triage)
    write_run_report(paths["md"], label, "rolling", start, end, events, {}, warnings, [], 25, triage=triage)
    output = {**runtime, "run_id": label, "origin": origin, "mode": "review",
              "status": "partial", "warnings": warnings,
              "window": {"start": start, "end": end}, "report_data": str(paths["ndjson"]),
              "html_report": str(paths["html"]), "triage_report": str(paths["triage.json"]),
              "active_dataset": store.metadata("active-dataset"), "product_tests_executed": False}
    output["engineer_report"] = write_engineer_bundle(Path(str(base) + ".engineer"), events, triage, start, end, warnings, [])
    output['latest_engineer_report'] = write_latest_entry(space.root / 'reports', output['engineer_report']['index'])
    write_run_json(paths["json"], output)
    (space.root / "reports/latest.html").write_bytes(paths["html"].read_bytes())
    store.set_metadata("latest-report", str(paths["json"]))
    store.set_metadata("continuity-report-state", context["state"])
    return output


def run(argv=None):
    parser = argparse.ArgumentParser(description="隔离空间、跨期评审、历史数据版本和本地反馈管理；不群发。")
    parser.add_argument("--workspace", type=Path, default=SKILL.parents[1])
    parser.add_argument("--purpose", choices=PURPOSES, default="trial")
    commands = parser.add_subparsers(dest="command", required=True)
    review = commands.add_parser("review", help="保存经过原文核对的约束、组合风险、报告主题或私有反馈")
    review.add_argument("--kind", choices=("constraint", "risk", "feedback", "theme"), required=True)
    review.add_argument("--input", type=Path, required=True)
    legacy = commands.add_parser("stage-legacy", help="显式复制未分类旧 NDJSON 到 trial/debug，保持原目录")
    legacy.add_argument("--input", type=Path, required=True)
    commands.add_parser("report", help="生成带跨期时间线与持续跟进的本地报告")
    export = commands.add_parser("export", help="导出公共候选数据包，不能直接发布")
    export.add_argument("--dataset-id", required=True)
    export.add_argument("--version", required=True)
    export.add_argument("--coverage", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    approve = commands.add_parser("approve", help="验收候选包并另存不可变新版")
    approve.add_argument("--input", type=Path, required=True)
    approve.add_argument("--output", type=Path, required=True)
    approve.add_argument("--reviewer", required=True)
    approve.add_argument("--note", required=True)
    load = commands.add_parser("import", help="校验并激活已验收基线；保留现场观察与反馈，不更新检查点")
    load.add_argument("--input", type=Path, required=True)
    load.add_argument("--dry-run", action="store_true")
    active = commands.add_parser("activate", help="切换/回退缓存的已发布基线版本，现场观察继续优先")
    active.add_argument("--dataset", required=True)
    active.add_argument("--dry-run", action="store_true")
    redo = commands.add_parser("reprocess", help="在非 production 空间重评已有事实；不重新解析网页或改变人工结果")
    redo.add_argument("--events", help="可选逗号分隔事件标识；关联评估可能使相连事件也更新")
    redo.add_argument("--dataset", help="要求当前活动基线匹配该 dataset_id:version；先 import/activate 再重评")
    redo.add_argument("--taxonomy", type=Path, help="评估规则；默认仓库通用规则")
    feedback = commands.add_parser("export-feedback", help="显式导出私有反馈，不能作为公共基线")
    feedback.add_argument("--output", type=Path, required=True)
    publication = commands.add_parser("approve-publication", help="本地审阅签收当前报告，为显式发布生成凭据")
    publication.add_argument("--report", type=Path)
    publication.add_argument("--target", choices=("pilot", "formal"), required=True)
    publication.add_argument("--reviewer", required=True)
    publication.add_argument("--note", required=True)
    publication.add_argument("--allow-partial", action="store_true")
    args = parser.parse_args(argv)
    try:
        space = RunSpace(args.workspace, args.purpose)
        if args.command == "approve":
            write_package(args.output, approve_package(read_package(args.input), args.reviewer, args.note))
            result = {"approved_package": str(args.output), "uploaded": False}
        else:
            if args.command in {"stage-legacy", "reprocess"} and space.purpose == "production":
                raise ValueError("旧数据试导入/历史重评必须在 trial 或 debug；验收包再导入 production")
            if args.command == "import":
                package = read_package(args.input, approved=True)  # Validate before target writes.
            with open_store(space, getattr(args, "dry_run", False)) as store:
                if args.command == "stage-legacy":
                    events = [Event(**row) for row in read_rows(args.input)]
                    if len({e.event_id for e in events}) != len(events):
                        raise ValueError("旧输入含重复身份，请先去重")
                    result = store.upsert_events(events)
                    store.set_metadata("live-event-ids", sorted(set(store.metadata("live-event-ids", [])) | {e.event_id for e in events}))
                    result["report"] = render(space, store, "legacy-stage", ["旧数据已显式放入隔离空间，仍未验收；尚未重读原文或证明历史提前预警能力。"])
                elif args.command == "review":
                    events = {r["event_id"]: Event(**r) for r in store.list_events()}
                    constraints = {r["id"]: r for r in store.records("constraint")}
                    targets = {r["id"]: r for r in store.records("risk")} if args.kind == "feedback" else constraints
                    rows = [validate_theme(row, events) if args.kind == "theme" else validate_review(args.kind, row, events, targets) for row in read_rows(args.input)]
                    live = store.metadata("live-record-ids", {})
                    if args.kind == "theme" and len({row["id"] for row in rows}) != len(rows):
                        raise ValueError("同一次主题评审不能包含重复claim_key")
                    pending = store.metadata("pending-semantic-review", {})
                    with store.connect() as connection:
                        changes = sum(store.upsert_record(args.kind, row, connection) for row in rows)
                        live[args.kind] = sorted(set(live.get(args.kind, [])) | {r["id"] for r in rows})
                        store.set_metadata("live-record-ids", live, connection)
                        for row in rows:
                            pending.get(args.kind, {}).pop(row["id"], None)
                        store.set_metadata("pending-semantic-review", pending, connection)
                    result = {"changed": changes, "ids": [r["id"] for r in rows], "report": render(space, store)}
                elif args.command == "report":
                    result = render(space, store)
                elif args.command == "export":
                    package = make_package(store, space, args.dataset_id, args.version, json.loads(args.coverage.read_text()))
                    write_package(args.output, package)
                    result = package["manifest"]
                elif args.command in {"import", "activate"}:
                    if args.command == "activate":
                        package = store.metadata("dataset:" + args.dataset)
                        if not package:
                            raise ValueError("未缓存该已发布版本")
                    result = import_package(store, package, dry_run=args.dry_run)
                    if not args.dry_run:
                        result["report"] = render(space, store, "baseline")
                elif args.command == "export-feedback":
                    private = {"schema": "private-feedback-v1", "visibility": "private", "run_purpose": space.purpose,
                               "records": store.records("feedback")}
                    write_package(args.output, private)
                    result = {"private_export": str(args.output), "uploaded": False, "count": len(private["records"])}
                elif args.command == "reprocess":
                    if args.dataset and store.metadata("active-dataset") != args.dataset:
                        raise ValueError("活动数据版本不匹配；先显式 import/activate 后再重评")
                    taxonomy = json.loads((args.taxonomy or SKILL / "config/risk-taxonomy.json").read_text())
                    environment = json.loads((SKILL / "config/environment.json").read_text())
                    result = reprocess(store, taxonomy, environment, event_ids=set(args.events.split(",")) if args.events else None)
                    result["report"] = render(space, store, "reprocess", result["limitations"])
                    diff_path = space.root / "reports" / (str(result["report"]["run_id"]) + ".changes.json")
                    write_run_json(diff_path, {k: v for k, v in result.items() if k != "report"})
                    result["diff_report"] = str(diff_path)
                elif args.command == "approve-publication":
                    if space.purpose == "debug" or (space.purpose == "trial" and args.target != "pilot"):
                        raise ValueError("debug 禁止外发；trial 只能签收 pilot")
                    path = space.input(args.report, "reports/missing.json") if args.report else Path(store.metadata("latest-report") or "")
                    if str(path) != store.metadata("latest-report"):
                        raise ValueError("只能签收当前最新报告；旧报告的签收不能用于发布")
                    report = json.loads(path.read_text())
                    if report.get("run_purpose") != space.purpose or report.get("run_space") != str(space.root):
                        raise ValueError("报告与运行空间不一致")
                    if report["status"] != "success" and not args.allow_partial:
                        raise ValueError("存在覆盖缺口；核对后明确 --allow-partial 才能签收")
                    if not args.note.strip() or not args.reviewer.strip():
                        raise ValueError("必须记录审阅者与审阅说明")
                    data_path = space.input(Path(report["report_data"]), "")
                    triage_path = space.input(Path(report["triage_report"]), "")
                    result = {"schema": "publication-review-v1", "active_dataset": store.metadata("active-dataset"), "run_purpose": space.purpose,
                              "target": args.target, "report": str(path), "input": str(data_path),
                              "sha256": hashlib.sha256(data_path.read_bytes()).hexdigest(),
                              "triage": str(triage_path), "triage_sha256": hashlib.sha256(triage_path.read_bytes()).hexdigest(),
                              "report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                              "resources": report_resources(space, report),
                              "send_alerts_allowed": report.get("origin") == "collection" and report.get("mode") != "backfill",
                              "risk_message_mode": "manual-reviewed-report",
                              "reviewer": args.reviewer, "note": args.note, "reviewed_at": utc_now()}
                    write_run_json(space.root / "publication.json", result)
                else:
                    raise ValueError("未知操作")
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError, TypeError, KeyError, sqlite3.Error) as exc:
        print("管理操作中止：" + str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
