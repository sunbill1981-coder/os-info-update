#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()


def tracked_files(root: Path) -> Iterable[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=str(root), check=True, capture_output=True,
    )
    for name in result.stdout.decode("utf-8").split("\0"):
        if name:
            yield root / name


def patterns() -> List[Tuple[str, re.Pattern[str]]]:
    return [
        ("飞书群机器人 Webhook", re.compile(r"open\.feishu\.cn/open-apis/bot/v2/hook/[A-Za-z0-9_-]{10,}")),
        ("飞书应用编号", re.compile(r"\bcli_[A-Za-z0-9]{10,}\b")),
        ("飞书多维表格标识", re.compile(r"\bbascn[A-Za-z0-9]{10,}\b")),
        ("飞书 Base 标识", re.compile(r"\bbas(?!e)[A-Za-z0-9]{10,}\b")),
        ("飞书数据表标识", re.compile(r"\btbl[A-Za-z0-9]{10,}\b")),
        ("飞书群标识", re.compile(r"\boc_[A-Za-z0-9]{10,}\b")),
        ("飞书用户标识", re.compile(r"\bou_[A-Za-z0-9]{10,}\b")),
        ("可疑的飞书密钥字面量", re.compile(
            r"(?i)(?:app_secret|verification_token|encrypt_key)\s*[:=]\s*['\"](?!\$\{|<|\*|CHANGE_ME)[^'\"]{8,}['\"]"
        )),
    ]


def scan(root: Path) -> List[str]:
    findings: List[str] = []
    for path in tracked_files(root):
        if path.resolve() == SELF or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        relative = path.relative_to(root)
        for line_number, line in enumerate(text.splitlines(), 1):
            for label, pattern in patterns():
                if pattern.search(line):
                    findings.append(f"{relative}:{line_number}：{label}")
    return findings


def main() -> int:
    findings = scan(ROOT)
    if findings:
        print("公开仓库安全检查失败：", file=sys.stderr)
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return 1
    print("公开仓库安全检查通过：未发现已跟踪的飞书密钥或真实资源标识。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
