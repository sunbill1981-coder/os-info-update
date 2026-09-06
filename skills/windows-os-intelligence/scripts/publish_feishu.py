#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from osintel.feishu import (  # noqa: E402
    FeishuApiError, FeishuClient, FeishuConfigurationError, FeishuSettings, publish_events,
)


class ChineseArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}：参数错误：{message}\n")


def _load_events(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not path.exists():
        raise FeishuConfigurationError(f"找不到规范化情报文件：{path}")
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise FeishuConfigurationError(f"第 {line_number} 行不是有效 JSON：{exc.msg}") from exc
            if not isinstance(payload, dict):
                raise FeishuConfigurationError(f"第 {line_number} 行必须是 JSON 对象。")
            events.append(payload)
    return events


def _load_env(path: Path) -> Dict[str, str]:
    values = dict(os.environ)
    if not path.exists():
        return values
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise FeishuConfigurationError(f"环境文件第 {line_number} 行缺少等号。")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if key and key not in values:
            values[key] = value
    return values


def run(argv: Optional[Sequence[str]] = None) -> int:
    workspace = Path(__file__).resolve().parents[3]
    parser = ChineseArgumentParser(
        description="将 Windows 情报幂等发布到飞书多维表格。",
        usage="%(prog)s [选项]",
        add_help=False,
    )
    parser._optionals.title = "选项"
    parser.add_argument("-h", "--help", action="help", help="显示帮助信息并退出")
    parser.add_argument("--workspace", type=Path, default=workspace, help="项目工作目录")
    parser.add_argument("--config", type=Path, help="飞书本地配置文件")
    parser.add_argument("--input", type=Path, help="规范化 NDJSON 文件")
    parser.add_argument("--env-file", type=Path, help="本地环境变量文件，默认为项目根目录下的 .env")
    parser.add_argument("--dry-run", action="store_true", help="只校验和统计，不连接飞书")
    parser.add_argument("--send-alerts", action="store_true", help="向已配置群聊发送新增或变化预警")
    parser.add_argument("--allow-bulk-alerts", action="store_true", help="确认允许超过单次安全上限的群告警")
    args = parser.parse_args(argv)
    root = args.workspace.resolve()
    config_path = args.config or root / "skills/windows-os-intelligence/config/feishu.local.json"
    input_path = args.input or root / "data/normalized/events.ndjson"
    env_path = args.env_file or root / ".env"
    try:
        if not config_path.exists():
            raise FeishuConfigurationError(
                f"找不到飞书本地配置：{config_path}。"
                "请复制 skill 目录中的 config/feishu.example.json，不要将本地副本提交到 Git。"
            )
        settings = FeishuSettings.load(
            config_path, environ=_load_env(env_path), require_remote=not args.dry_run,
        )
        events = _load_events(input_path)
        client = FeishuClient(settings)
        summary = publish_events(
            client, events, dry_run=args.dry_run, send_alerts=args.send_alerts,
            allow_bulk_alerts=args.allow_bulk_alerts,
        )
    except (FeishuConfigurationError, FeishuApiError, OSError, json.JSONDecodeError) as exc:
        print(f"飞书发布失败：{exc}", file=sys.stderr)
        return 2
    print("飞书发布完成：" + json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
