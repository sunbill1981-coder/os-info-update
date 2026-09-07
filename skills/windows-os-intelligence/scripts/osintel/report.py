from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Sequence, Set

from .model import Event, utc_now


MODE_ZH = {"backfill": "历史回填", "rolling": "滚动窗口", "incremental": "增量采集"}
TYPE_ZH = {
    "vulnerability": "安全漏洞", "known issue": "已知问题", "lifecycle": "生命周期",
    "compatibility": "兼容性", "feature preview": "预览版本动态",
}
STATUS_ZH = {
    "confirmed": "已确认", "reported": "已报告", "investigating": "调查中",
    "mitigated": "已缓解", "resolved": "已解决",
}
ROLE_ZH = {
    "guest": "来宾系统", "host": "宿主机", "directory": "目录服务",
    "profile/file service": "配置文件与文件服务", "unknown": "角色未明确",
}
EDITION_ZH = {"not specified": "版本类型未明确", "Pro": "专业版", "Enterprise": "企业版", "Education": "教育版", "Home": "家庭版"}
CHANGE_ZH = {
    "behavior change": "行为变化", "security enforcement": "安全策略收紧",
    "compatibility change": "兼容性变化", "deprecation": "弃用变化",
    "servicing change": "更新维护变化",
}
PRECONDITION_ZH = {
    "managed environment": "受管理环境", "domain joined": "已加入域",
    "after update": "安装更新后", "cloned image": "克隆镜像",
}
WORKFLOW_ZH = {
    "desktop provisioning": "桌面交付", "domain join": "加入域",
    "image deployment": "镜像部署", "user logon": "用户登录",
    "patch deployment": "补丁部署", "in-place upgrade": "就地升级",
}
SYMPTOM_ZH = {
    "operation blocked": "操作被阻止", "authentication failure": "身份认证失败",
    "installation failure": "安装失败", "connection failure": "连接失败",
    "performance degradation": "性能下降",
}
COMPONENT_ZH = {
    "RDP": "远程桌面协议（RDP）", "RDS": "远程桌面服务（RDS）", "Hyper-V": "Hyper-V 虚拟化",
    "VBS": "虚拟化安全（VBS）", "Credential Guard": "凭据保护", "GPU/display": "显卡与显示",
    "FSLogix/profile": "FSLogix 与用户配置文件", "authentication": "身份认证",
    "networking": "网络", "printing": "打印", "peripheral redirection": "外设重定向",
    "Windows Update": "Windows 更新", "image/recovery": "镜像与恢复",
}
SOURCE_ZH = {
    "msrc": "微软安全响应中心", "release-health": "Windows 发布健康",
    "windows-insider-sitemap": "Windows 预览体验计划", "lifecycle": "微软生命周期",
    "external-signal": "外部发现信号",
}


def _labels(values: Sequence[str], mapping: Dict[str, str]) -> str:
    return "、".join(mapping.get(value, value) for value in values)


def _product_zh(value: str) -> str:
    text = value
    text = re.sub(r",?\s+[Vv]ersion\s+", " 版本 ", text)
    text = text.replace(" for ARM64-based Systems", "（ARM64 系统）")
    text = text.replace(" for x64-based Systems", "（x64 系统）")
    text = text.replace(" for 32-bit Systems", "（32 位系统）")
    text = text.replace(" (Server Core installation)", "（服务器核心安装）")
    text = text.replace("Home and Pro", "家庭版和专业版")
    text = text.replace("Enterprise and Education", "企业版和教育版")
    text = text.replace(" preview", " 预览版")
    return text


def _impact_zh(event: Event) -> str:
    text = f"{event.title} {event.summary}".casefold()
    for token, label in (
        ("remote code execution", "远程代码执行"), ("elevation of privilege", "权限提升"),
        ("information disclosure", "信息泄露"), ("denial of service", "拒绝服务"),
        ("security feature bypass", "安全功能绕过"), ("spoofing", "欺骗"),
        ("tampering", "篡改"),
    ):
        if token in text:
            return label
    return "安全风险"


def _display_title(event: Event) -> str:
    components = _labels(event.components[:2], COMPONENT_ZH) or "Windows"
    cves = event.identifiers.get("cve", [])
    kbs = event.identifiers.get("kb", [])
    if event.event_type == "vulnerability":
        identifier = cves[0] if cves else "Windows 漏洞"
        return f"{identifier}：{components}{_impact_zh(event)}漏洞"
    if event.event_type == "known issue":
        identifier = f"（{kbs[0]}）" if kbs else ""
        return f"{components}已知问题{identifier}"
    if event.event_type == "lifecycle":
        return f"{_product_zh(event.products[0]) if event.products else 'Windows'} 生命周期节点"
    if event.event_type == "feature preview":
        return f"Windows 预览版本动态（{event.published_at or '日期未明确'}）"
    return TYPE_ZH.get(event.event_type, "Windows 情报事件")


def _display_summary(event: Event) -> str:
    components = _labels(event.components, COMPONENT_ZH) or "未识别到特定组件"
    identifiers = []
    for key in ("cve", "kb", "build"):
        identifiers.extend(event.identifiers.get(key, []) or [])
    identifier_text = "、".join(identifiers) or "无额外标识"
    if event.event_type == "vulnerability":
        return f"微软已确认该漏洞，主要风险为{_impact_zh(event)}；关联组件：{components}；标识：{identifier_text}。"
    if event.event_type == "known issue":
        return f"微软发布健康页面记录的已知问题；当前状态：{STATUS_ZH.get(event.status, event.status)}；关联组件：{components}；标识：{identifier_text}。"
    if event.event_type == "lifecycle":
        return f"微软生命周期页面记录的产品支持节点；应与内部镜像和版本清单核对；标识：{identifier_text}。"
    if event.event_type == "feature preview":
        return "该信息来自 Windows 预览体验计划官方站点地图，目前仅作为早期信号，尚未抓取并核验文章正文。"
    return f"Windows 情报事件；关联组件：{components}；标识：{identifier_text}。"


def _display_action(event: Event) -> str:
    if event.event_type == "vulnerability":
        return "核对补丁适用范围，并在有代表性的云桌面来宾镜像和宿主机上完成安装、回滚及业务兼容性验证。"
    if event.event_type == "known issue":
        return "核对关联 KB、影响平台、临时缓解措施和修复版本，在镜像推广前完成复现与验证。"
    if event.event_type == "lifecycle":
        return "与内部镜像清单对照，并为受影响版本安排升级或退役计划。"
    return "先作为预警线索跟踪；若涉及内部云桌面组件，再补充正文核验和专项测试。"


def display_title(event: Event) -> str:
    return _display_title(event)


def display_summary(event: Event) -> str:
    return _display_summary(event)


def display_action(event: Event) -> str:
    return _display_action(event)


def display_values(values: Sequence[str], mapping: Dict[str, str]) -> str:
    return _labels(values, mapping)


def display_product(value: str) -> str:
    return _product_zh(value)


def write_ndjson(path: Path, events: Iterable[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def _event_line(event: Event) -> str:
    visible_products = event.products[:6]
    products = "、".join(_product_zh(value) for value in visible_products) or "产品未明确"
    if len(event.products) > len(visible_products):
        products += f" 等 {len(event.products)} 项"
    roles = _labels(event.roles, ROLE_ZH) or "角色未明确"
    date_value = event.updated_at or event.published_at or "日期未明确"
    return (
        f"- **[{_display_title(event)}]({event.source_url})**（{event.alert_level}）  \n"
        f"  技术风险 {event.risk_score} · 环境相关度 {event.environment_relevance} · 处置优先级 {event.action_priority} · 置信度 {event.confidence}  \n"
        f"  {date_value} · {products} · {roles} · {STATUS_ZH.get(event.status, event.status)}  \n"
        f"  变化：{_labels(event.change_kinds, CHANGE_ZH) or '未明确'}；"
        f"前置条件：{_labels(event.preconditions, PRECONDITION_ZH) or '未明确'}；"
        f"影响流程：{_labels(event.affected_workflows, WORKFLOW_ZH) or '未明确'}  \n"
        f"  {_display_summary(event)}  \n"
        f"  建议：{_display_action(event)}  \n"
        f"  证据索引：{event.evidence_id()}；来源级别 {event.source_tier}；"
        f"[查看原文]({event.source_url})；原始文档指纹 "
        f"{event.raw_hash[:16] if event.raw_hash else '未提供'}"
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
    stats: Dict[str, Any],
    warnings: Sequence[str],
    failures: Sequence[Dict[str, str]],
    limit: int,
) -> None:
    ordered = sorted(events, key=lambda event: (-event.action_priority, -event.risk_score, event.event_id))
    event_types = Counter(event.event_type for event in events)
    sources = Counter(event.source_id for event in events)
    alerts = Counter(event.alert_level for event in events)
    new_ids: Set[str] = set(stats.get("new_ids", []))
    fact_changed_ids: Set[str] = set(stats.get("fact_changed_ids", []))
    assessment_changed_ids: Set[str] = set(stats.get("assessment_changed_ids", []))
    delta_ids = new_ids | fact_changed_ids | assessment_changed_ids
    visible = ordered if mode != "incremental" else [event for event in ordered if event.event_id in delta_ids]
    high = [event for event in visible if event.alert_level in {"正式告警", "调查预警"} or event.action_priority >= 75]
    changed = [event for event in ordered if event.event_type in {"vulnerability", "known issue"}]
    lifecycle = [event for event in ordered if event.event_type in {"lifecycle", "compatibility"}]
    preview = [event for event in ordered if event.preview or event.confidence < 80]

    lines = [
        "# Windows 操作系统情报采集报告",
        "",
        f"- 运行编号：{run_id}",
        f"- 模式：{MODE_ZH.get(mode, mode)}",
        f"- 时间范围：{window_start} 至 {window_end}（含首尾日期）",
        f"- 生成时间：{utc_now()}",
        f"- 本轮候选：{len(events)}；新增 {stats.get('new', 0)}；"
        f"事实变化 {stats.get('fact_changed', 0)}；"
        f"仅评估变化 {stats.get('assessment_changed', 0)}；"
        f"未变 {stats.get('unchanged', 0)}",
        f"- 类型：{dict(sorted((TYPE_ZH.get(key, key), value) for key, value in event_types.items())) or '{}'}",
        f"- 来源：{dict(sorted((SOURCE_ZH.get(key, key), value) for key, value in sources.items())) or '{}'}",
        f"- 告警：{dict(sorted(alerts.items())) or '{}'}",
        "",
    ]
    _section(lines, "预警与高优先级风险", high, "本轮没有新增或实质变化的高优先级风险。", limit)
    if mode == "incremental":
        _section(lines, "本轮新增", [event for event in ordered if event.event_id in new_ids], "本轮无新增事件。", limit)
        _section(lines, "本轮事实变化", [event for event in ordered if event.event_id in fact_changed_ids], "本轮无来源事实变化。", limit)
        _section(lines, "本轮仅评估变化", [event for event in ordered if event.event_id in assessment_changed_ids], "本轮无单纯评估变化。", limit)
        if not delta_ids:
            lines.extend([">本轮无实质变化，无需人工处置。", ""])
    else:
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
