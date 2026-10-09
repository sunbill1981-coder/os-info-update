#!/usr/bin/env python3
"""Offline frozen-data sample; no Store, checkpoints, collection or publication."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from osintel.model import Event, utc_now, parse_date
from osintel.themes import validate_theme, build_themes
from osintel.triage import build_triage
from osintel.engineer_report import write_engineer_bundle


def run(argv=None):
    parser = argparse.ArgumentParser(description='从冻结NDJSON生成工程师报告包；不入库、不联网。')
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--themes', type=Path)
    parser.add_argument('--source-report', type=Path)
    parser.add_argument('--start', required=True)
    parser.add_argument('--end', required=True)
    parser.add_argument('--purpose', choices=('debug', 'trial'), default='debug')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if not parse_date(args.start) or not parse_date(args.end) or args.start > args.end:
            raise ValueError('日期范围无效')
        events = [Event(**json.loads(line)) for line in args.input.read_text().splitlines() if line.strip()]
        event_map = {e.event_id: e for e in events}
        if len(events) != len(event_map): raise ValueError('冻结数据含重复事件')
        records = json.loads(args.themes.read_text()) if args.themes else []
        if not isinstance(records, list): raise ValueError('主题文件须为JSON数组')
        records = [validate_theme(r, event_map) for r in records]
        if len({r['id'] for r in records}) != len(records): raise ValueError('主题身份重复')
        triage = build_triage(events, run_at=utc_now())
        triage.update(themes=build_themes(records, event_map), runtime={'run_purpose': args.purpose, 'dataset_status': 'candidate'})
        source = json.loads(args.source_report.read_text()) if args.source_report else {}
        if source.get('window') and source['window'] != {'start': args.start, 'end': args.end}:
            raise ValueError('冻结原报告窗口与所请求窗口不一致')
        warnings = source.get('warnings', []) + ['离线冻结数据样板，未采集、未入库、未执行产品测试；来源覆盖以原报告为准。']
        result = write_engineer_bundle(args.output, events, triage, args.start, args.end, warnings, source.get('failures', []))
        print(json.dumps(result, ensure_ascii=False, indent=2)); return 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print('报告生成中止：' + str(exc)); return 2


if __name__ == '__main__': raise SystemExit(run())
