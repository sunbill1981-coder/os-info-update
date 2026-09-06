from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

from .model import Event, utc_now


def write_ndjson(path: Path, events: Iterable[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def _event_line(event: Event) -> str:
    visible_products = event.products[:6]
    products = "、".join(visible_products) or "产品未明确"
    if len(event.products) > len(visible_products):
        products += f" 等 {len(event.products)} 项"
    roles = "、".join(event.roles) or "角色未明确"
    date_value = event.updated_at or event.published_at or "日期未明确"
    return (
        f"- **[{event.title}]({event.source_url})**（风险 {event.risk_score}，置信度 {event.confidence}）  \n"
        f"  {date_value} · {products} · {roles} · {event.status}  \n"
        f"  {event.summary or event.evidence or '暂无摘要'}  \n"
        f"  建议：{event.recommended_action}"
    )


def _section(lines: List[str], title: str, events: Sequence[Event], empty: str, limit: int) -> None:
    lines.extend([f"## {title}", ""])
    if not events:
        lines.extend([empty, ""])
        return
    for event in events[:limit]:
        lines.extend([_event_line(event), ""])
    if len(events) > limit:
        lines.extend([f"> 另有 {len(events) - limit} 条未在本摘要展开，可在 NDJSON 或 SQLite 中查询。", ""])


def write_run_report(
    path: Path,
    run_id: int,
    mode: str,
    window_start: str,
    window_end: str,
    events: Sequence[Event],
    stats: Dict[str, int],
    warnings: Sequence[str],
    failures: Sequence[Dict[str, str]],
    limit: int,
) -> None:
    ordered = sorted(events, key=lambda event: (-event.risk_score, event.event_id))
    event_types = Counter(event.event_type for event in events)
    sources = Counter(event.source_id for event in events)
    high = [event for event in ordered if event.risk_score >= 75]
    changed = [event for event in ordered if event.event_type in {"vulnerability", "known issue"}]
    lifecycle = [event for event in ordered if event.event_type in {"lifecycle", "compatibility"}]
    preview = [event for event in ordered if event.preview or event.confidence < 80]

    lines = [
        "# Windows OS 情报采集报告",
        "",
        f"- 运行编号：{run_id}",
        f"- 模式：{mode}",
        f"- 时间范围：{window_start} 至 {window_end}（含首尾日期）",
        f"- 生成时间：{utc_now()}",
        f"- 本轮候选：{len(events)}；新增 {stats.get('new', 0)}；变化 {stats.get('changed', 0)}；未变 {stats.get('unchanged', 0)}",
        f"- 类型：{dict(sorted(event_types.items())) or '{}'}",
        f"- 来源：{dict(sorted(sources.items())) or '{}'}",
        "",
    ]
    _section(lines, "高优先级云桌面风险", high, "本轮没有风险分达到 75 的事件。", limit)
    _section(lines, "漏洞与已知问题", changed, "本轮没有采集到漏洞或已知问题。", limit)
    _section(lines, "兼容性与生命周期", lifecycle, "本轮没有采集到兼容性或生命周期事件。", limit)
    _section(lines, "预览与待确认信号", preview, "本轮没有预览或低置信度信号。", limit)
    lines.extend(["## 覆盖缺口与来源异常", ""])
    gaps = list(warnings) + [f"{item['source_id']}: {item['error']}" for item in failures]
    if gaps:
        lines.extend(f"- {value}" for value in gaps)
    else:
        lines.append("未记录来源异常。")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def write_run_json(path: Path, payload: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
