#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Optional, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from osintel.feishu import FeishuApiError, FeishuConfigurationError, load_events  # noqa: E402
from osintel.feishu_wizard import preview_events, run_check, run_interactive  # noqa: E402


class ChineseArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}：参数错误：{message}\n")


def run(argv: Optional[Sequence[str]] = None) -> int:
    default_workspace = Path(__file__).resolve().parents[3]
    parser = ChineseArgumentParser(
        description="Windows 操作系统情报飞书接入向导。",
        usage="%(prog)s [选项]",
        add_help=False,
    )
    parser._optionals.title = "选项"
    parser.add_argument("-h", "--help", action="help", help="显示帮助信息并退出")
    parser.add_argument("--workspace", type=Path, default=default_workspace, help="项目工作目录")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--preview", action="store_true", help="只预览待发布的中文飞书字段")
    mode.add_argument("--check", action="store_true", help="只检查已配置的飞书连接和表结构")
    args = parser.parse_args(argv)
    workspace = args.workspace.resolve()
    try:
        if args.preview:
            events = load_events(workspace / "data/normalized/events.ndjson")
            preview_events(events, sys.stdout, limit=5)
            return 0
        if args.check:
            return run_check(workspace)
        if not sys.stdin.isatty():
            raise FeishuConfigurationError(
                "交互向导需要在终端中运行；当前可使用 --preview 或 --check。"
            )
        return run_interactive(workspace)
    except (FeishuConfigurationError, FeishuApiError, OSError, ValueError) as exc:
        print(f"飞书接入向导中止：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(run())
