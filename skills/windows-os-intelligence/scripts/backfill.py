#!/usr/bin/env python3
"""Monthly, resumable history acquisition; deliberately no publication."""
from __future__ import annotations
import argparse
from datetime import date, timedelta
import json
from pathlib import Path
from osintel import cli
from osintel.model import stable_hash, utc_now
from osintel.runtime import RunSpace
from osintel.store import Store


def chunks(start, end):
    if start > end:
        raise ValueError("开始日期不能晚于结束日期")
    while start <= end:
        following = date(start.year + (start.month == 12), start.month % 12 + 1, 1)
        finish = min(end, following - timedelta(days=1))
        yield start, finish
        start = finish + timedelta(days=1)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def run(argv=None):
    parser = argparse.ArgumentParser(description="按月分批回填并记录覆盖；默认 trial，不群发。失败月份下次重试。")
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--purpose", choices=("trial", "debug"), default="trial")
    parser.add_argument("--start", type=date.fromisoformat, required=True)
    parser.add_argument("--end", type=date.fromisoformat, required=True)
    parser.add_argument("--sources", default="msrc,release-health,lifecycle,windows-insider")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--retry-all", action="store_true", help="显式重跑已完成批次；不会改写已发布包")
    args = parser.parse_args(argv)
    try:
        space = RunSpace(args.workspace, args.purpose)
        config = args.config or space.project / "skills/windows-os-intelligence/config/sources.json"
        identity = {"start": str(args.start), "end": str(args.end), "sources": args.sources,
                    "config": stable_hash(json.loads(config.read_text()))}
        unknown = set(args.sources.split(",")) - (set(cli.COLLECTORS) | {"signals", "discovery"})
        if unknown:
            raise ValueError("未知来源：" + ",".join(sorted(unknown)))
        windows = list(chunks(args.start, args.end))
        path = space.root / "data/backfill" / stable_hash(identity)[:20] / "ledger.json"
        ledger = json.loads(path.read_text()) if path.exists() else {"schema": "backfill-v1", "identity": identity, "months": {}}
        if args.plan_only:
            print(json.dumps({"ledger": str(path), "windows": [[str(a), str(b)] for a, b in windows],
                              "scope": "仅计划，尚未采集；社区/专项搜索与语义评审须另行完成"}, ensure_ascii=False, indent=2))
            return 0
        space.ensure()
        failed = False
        for start, end in windows:
            key = str(start) + "_" + str(end)
            previous = ledger["months"].get(key, {})
            if previous.get("acquisition") == "success" and not args.retry_all:
                print(f"跳过已完成采集批次 {key}（不代表所有风险发现完成）", flush=True)
                continue
            ledger["months"][key] = {"acquisition": "running", "started_at": utc_now()}
            save(path, ledger)
            before = Store(space.db, space.root / "data/raw").metadata("latest-report")
            try:
                code = cli.run(["--workspace", str(space.project), "--purpose", args.purpose,
                                "--mode", "backfill", "--start", str(start), "--end", str(end),
                                "--sources", args.sources, "--config", str(config), "--no-enrichment"])
                latest = Store(space.db, space.root / "data/raw").metadata("latest-report")
                report = json.loads(Path(latest).read_text()) if latest and latest != before else {}
                if not report or report.get("window") != {"start": str(start), "end": str(end)}:
                    raise ValueError("未产出匹配月份的独立报告")
                row = {"acquisition": "success" if code == 0 else "partial", "report": latest,
                       "source_coverage": report.get("source_coverage"), "discovery_coverage": report.get("discovery_coverage"),
                       "warnings": report.get("warnings", []), "facts": report.get("stats", {}).get("events", 0)}
                failed |= code != 0
            except Exception as exc:
                row = {"acquisition": "failed", "error": str(exc)}
                failed = True
            row["finished_at"] = utc_now()
            ledger["months"][key] = row
            save(path, ledger)
        print(f"回填账本：{path}；未发布、未群发。采集完成仍需检查发现覆盖和跨期评审。")
        return 2 if failed else 0
    except (ValueError, OSError, KeyError) as exc:
        print("回填中止：" + str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
