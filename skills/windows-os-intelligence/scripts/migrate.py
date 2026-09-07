#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from osintel.migration import apply_migration, inspect_database  # noqa: E402


class ChineseArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}：参数错误：{message}\n")


def main() -> int:
    parser = ChineseArgumentParser(description="Windows 情报数据 v2 安全迁移工具")
    parser._optionals.title = "选项"
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[3])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="只显示迁移影响，不修改数据")
    mode.add_argument("--apply", action="store_true", help="备份后执行迁移")
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    db_path = workspace / "data/state/os-intel.sqlite3"
    if not db_path.exists():
        print(f"迁移中止：找不到状态库 {db_path}", file=sys.stderr)
        return 2
    summary = inspect_database(db_path)
    print(
        f"待检查事件 {summary['events']} 条；待归一化日期 "
        f"{summary['normalized_dates']} 条；待补齐权威性 {summary['authority_updates']} 条。"
    )
    if args.dry_run:
        print("演练完成：未修改数据库或规范化数据。")
        return 0
    result = apply_migration(workspace)
    print(f"迁移完成：已更新 {result['updated']} 条事件。")
    print(f"备份位置：{result['backup']}")
    print("启用群告警前，请先不带 --send-alerts 运行一次飞书同步以建立 v2 基线。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
