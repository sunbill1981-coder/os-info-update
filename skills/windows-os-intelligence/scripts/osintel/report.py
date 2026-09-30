from __future__ import annotations

from collections import Counter
import html
import json
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set
from urllib.parse import urlsplit

from .guidance import build_cloud_desktop_guidance
from .model import Event, utc_now
from .patches import patch_rows, phase_explanation, phase_tests, risk_phase
from .scoring import infer_components


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
    "应用启动与兼容": "应用启动与兼容",
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
    "audio/media": "音频与多媒体", "application compatibility": "应用兼容性",
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
    if event.event_type == "vulnerability":
        identifier = cves[0] if cves else "Windows 漏洞"
        return f"{identifier}：{components}{_impact_zh(event)}漏洞"
    if event.event_type == "known issue":
        focal = infer_components(event.title)
        if "RDS" in focal:
            focal = ["RDS"]
        components = _labels(focal[:2], COMPONENT_ZH) or "Windows"
        return f"{components}已知问题：{risk_phase(event)[1]}"
    if event.event_type == "lifecycle":
        return f"{_product_zh(event.products[0]) if event.products else 'Windows'} 生命周期节点"
    if event.event_type == "feature preview":
        return f"Windows 预览版本动态（{event.published_at or '日期未明确'}）"
    return TYPE_ZH.get(event.event_type, "Windows 情报事件")


def _display_summary(event: Event) -> str:
    return build_cloud_desktop_guidance(event).problem_summary


def _display_action(event: Event) -> str:
    guidance = build_cloud_desktop_guidance(event)
    return guidance.preventive_actions[0] if guidance.preventive_actions else "先核对内部适用性，再安排专项验证。"


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


def _update_details_summary(event: Event) -> str:
    restart_labels = {"yes": "需要", "no": "不需要", "true": "需要", "false": "不需要"}
    rows = []
    for detail in event.update_details:
        if detail.get("relationship"):
            values = ["、".join(_product_zh(value) for value in detail.get("products", []))]
            for key, label in (("introduced_kb", "引入"), ("fixed_kb", "修复"), ("mitigation_kb", "缓解措施引用")):
                if detail.get(key):
                    values.append(label + " " + "、".join(detail[key]))
            if detail.get("fix_scope") == "partial":
                values.append("仅部分修复")
            rows.append("，".join(values))
            continue
        if str(detail.get("type") or "") not in {"", "2"}:
            continue
        values = ["/".join(str(value) for value in detail.get("kb", []) or []) or "KB 未明确"]
        if detail.get("fixed_build"):
            values.append(f"修复 Build {detail['fixed_build']}")
        if detail.get("supercedence"):
            values.append(f"取代 {detail['supercedence']}")
        if detail.get("restart_required"):
            restart = str(detail["restart_required"])
            values.append(f"重启要求 {restart_labels.get(restart.casefold(), restart)}")
        rows.append("，".join(values))
    return "；".join(rows)


def _event_line(event: Event, environment: Optional[Mapping[str, object]] = None) -> str:
    guidance = build_cloud_desktop_guidance(event, environment)
    visible_products = event.products[:6]
    products = "、".join(_product_zh(value) for value in visible_products) or "产品未明确"
    if len(event.products) > len(visible_products):
        products += f" 等 {len(event.products)} 项"
    roles = _labels(event.roles, ROLE_ZH) or "角色未明确"
    date_value = event.updated_at or event.published_at or "日期未明确"
    kev = "已收录" if event.kev.get("listed") else event.field_status.get("cisa_kev", "未查询")
    epss = (
        f"{float(event.epss.get('score')) * 100:.2f}%"
        if event.epss.get("score") is not None else event.field_status.get("first_epss", "未查询")
    )
    assets = "、".join(event.asset_matches) or "未命中已配置资产队列"
    update_details = _update_details_summary(event)
    update_line = f"  补丁关系：{update_details}  \n" if update_details else ""
    reference_line = (
        f"  官方页面：{len(event.source_references)} 个（已合并为同一逻辑事件）  \n"
        if len(event.source_references) > 1 else ""
    )
    return (
        f"- **[{_display_title(event)}]({event.source_url})**（{event.alert_level}）  \n"
        f"  技术风险 {event.risk_score} · 环境相关度 {event.environment_relevance} · 处置优先级 {event.action_priority} · 置信度 {event.confidence}  \n"
        f"  威胁紧迫度 {event.threat_urgency} · 利用状态：{event.exploitation_status} · CISA KEV：{kev} · EPSS：{epss}  \n"
        f"  资产队列：{assets}；候选影响数量：{event.affected_asset_count or '未配置'}  \n"
        f"{update_line}"
        f"{reference_line}"
        f"  {date_value} · {products} · {roles} · {STATUS_ZH.get(event.status, event.status)}  \n"
        f"  风险阶段：{risk_phase(event)[1]}。{phase_explanation(event)}  \n"
        f"  分阶段验证：{' '.join(label + '：' + action for label, action in phase_tests(event))}  \n"
        f"  变化：{_labels(event.change_kinds, CHANGE_ZH) or '未明确'}；"
        f"前置条件：{_labels(event.preconditions, PRECONDITION_ZH) or '未明确'}；"
        f"影响流程：{_labels(event.affected_workflows, WORKFLOW_ZH) or '未明确'}  \n"
        f"  公开事实：{guidance.problem_summary}  \n"
        f"  潜在影响（工程推演）：{' '.join(guidance.potential_impacts)}  \n"
        f"  建议测试：{' '.join(guidance.recommended_tests)}  \n"
        f"  预防与上线门禁：{' '.join(guidance.preventive_actions)}  \n"
        f"  针对性探索：{' '.join(guidance.exploration_questions)}  \n"
        f"  适用性：{guidance.applicability}  \n"
        f"  证据索引：{event.evidence_id()}；来源级别 {event.source_tier}；"
        f"[查看原文]({event.source_url})；原始文档指纹 "
        f"{event.raw_hash[:16] if event.raw_hash else '未提供'}"
    )


def _section(
    lines: List[str], title: str, events: Sequence[Event], empty: str, limit: int,
    environment: Optional[Mapping[str, object]] = None,
) -> None:
    lines.extend([f"## {title}", ""])
    if not events:
        lines.extend([empty, ""])
        return
    for event in events[:limit]:
        lines.extend([_event_line(event, environment), ""])
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
    environment: Optional[Mapping[str, object]] = None,
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
    high = [
        event for event in visible
        if event.risk_score >= 75 or event.alert_level in {"正式告警", "调查预警"}
    ]
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
    _section(lines, "高技术风险与预警", high, "本轮没有高技术风险或预警。", limit, environment)
    if mode == "incremental":
        _section(lines, "本轮新增", [event for event in ordered if event.event_id in new_ids], "本轮无新增事件。", limit, environment)
        _section(lines, "本轮事实变化", [event for event in ordered if event.event_id in fact_changed_ids], "本轮无来源事实变化。", limit, environment)
        _section(lines, "本轮仅评估变化", [event for event in ordered if event.event_id in assessment_changed_ids], "本轮无单纯评估变化。", limit, environment)
        if not delta_ids:
            lines.extend([">本轮无实质变化，无需人工处置。", ""])
    else:
        _section(lines, "漏洞与已知问题", changed, "本轮没有采集到漏洞或已知问题。", limit, environment)
        _section(lines, "兼容性与生命周期", lifecycle, "本轮没有采集到兼容性或生命周期事件。", limit, environment)
        _section(lines, "预览与待确认信号", preview, "本轮没有预览或低置信度信号。", limit, environment)
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


def _h(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _safe_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "#"
    return value if parsed.scheme in {"http", "https"} and parsed.netloc else "#"


def _html_metric(label: str, value: int, tone: str = "blue") -> str:
    safe_value = max(0, min(100, int(value)))
    return (
        '<div class="metric">'
        f'<div class="metric-label"><span>{_h(label)}</span><strong>{safe_value}</strong></div>'
        f'<div class="metric-track" role="meter" aria-label="{_h(label)}" aria-valuemin="0" '
        f'aria-valuemax="100" aria-valuenow="{safe_value}">'
        f'<span class="metric-fill tone-{_h(tone)}" style="width:{safe_value}%"></span></div></div>'
    )


def _html_link(url: str, label: str, css_class: str = "source-link") -> str:
    safe_url = _safe_url(url)
    if safe_url == "#":
        return f'<span class="source-unavailable">{_h(label)}（链接不可用）</span>'
    return (
        f'<a class="{_h(css_class)}" href="{_h(safe_url)}" target="_blank" '
        f'rel="noopener noreferrer">{_h(label)}<span aria-hidden="true">↗</span></a>'
    )


def _event_references(event: Event) -> List[Dict[str, str]]:
    references: List[Dict[str, str]] = []
    seen = set()
    values = event.source_references or [{"page_id": event.source_id, "url": event.source_url}]
    for value in values:
        url = str(value.get("url") or "")
        key = (str(value.get("page_id") or ""), url)
        if url and key not in seen:
            seen.add(key)
            references.append({"page_id": key[0], "url": url})
    return references


def _html_action_list(values: Sequence[str], source_url: str, citation_label: str) -> str:
    return "".join(
        f'<li><span>{_h(value)}</span>{_html_link(source_url, citation_label, "inline-citation")}</li>'
        for value in values
    )


def _html_patch_context(event: Event) -> str:
    phase, label = risk_phase(event)
    rows = patch_rows(event)
    table_rows = []
    for row in rows:
        product = "、".join(_product_zh(value) for value in row.get("products", [])) or "适用版本未明确"
        source_url = str(row.get("source_url") or event.source_url)
        introduced = "、".join(row.get("introduced_kb", [])) or ("不适用：本条为安全漏洞" if phase == "security" else "原文未明确 KB")
        fixed = "、".join(row.get("fixed_kb", [])) or "修复 KB 未明确"
        if row.get("fixed_build"):
            fixed += " · Build " + str(row["fixed_build"])
        mitigation = "、".join(row.get("mitigation_kb", [])) or "未单列 KB"
        scope = "部分修复，仍需验证剩余症状" if row.get("fix_scope") == "partial" else ""
        table_rows.append(
            f'<tr><th scope="row">{_h(product)}</th><td>{_h(introduced)}</td>'
            f'<td>{_h(fixed)}<small class="patch-caution">{_h(scope)}</small></td>'
            f'<td>{_h(mitigation)}</td><td>{_html_link(source_url, "版本依据", "inline-citation")}</td></tr>'
        )
    table = (
        '<div class="patch-table-wrap"><table class="patch-table"><thead><tr>'
        '<th>Windows 版本／架构</th><th>引入问题的更新</th><th>修复更新／Build</th>'
        '<th>缓解措施引用</th><th>原文</th></tr></thead><tbody>'
        + "".join(table_rows) + '</tbody></table></div>'
    ) if table_rows else '<p class="patch-note">未提取到可靠的版本—补丁对应关系，关联标识仅供检索。</p>'
    if len(rows) > 5 and phase == "security":
        table = f'<details class="patch-details"><summary>展开 {len(rows)} 组版本与漏洞修复更新对应关系</summary>{table}</details>'
    conditions = sorted({str(value) for row in rows for value in row.get("conditions", [])})
    condition_text = "、".join(conditions) or "需核对官方适用版本、组件与配置前提"
    stages = "".join(
        f'<div class="patch-stage"><strong>{_h(stage)}</strong><p>{_h(action)} '
        f'{_html_link(event.source_url, "触发依据", "inline-citation")}</p></div>'
        for stage, action in phase_tests(event)
    )
    return (
        f'<section class="patch-context patch-{_h(phase)}" aria-label="风险发生阶段与补丁关系">'
        f'<div class="patch-heading"><span class="risk-phase">{_h(label)}</span>'
        '<span>当前镜像补丁状态：待核对</span></div>'
        f'<p>{_h(phase_explanation(event))} {_html_link(event.source_url, "判断依据", "inline-citation")}</p>'
        f'<p class="patch-note">需核对的触发条件（原文线索）：{_h(condition_text)}。'
        f'{_html_link(event.source_url, "完整条件与排除范围", "inline-citation")}</p>'
        + table + '<div class="patch-stages" aria-label="不同补丁阶段应该测什么">' + stages + '</div></section>'
    )


def _html_event_card(
    event: Event, index: int, delta_ids: Set[str],
    environment: Optional[Mapping[str, object]] = None,
) -> str:
    event.normalized()
    guidance = build_cloud_desktop_guidance(event, environment)
    title = _display_title(event)
    products = "、".join(_product_zh(value) for value in event.products) or "产品未明确"
    roles = _labels(event.roles, ROLE_ZH) or "角色未明确"
    components = _labels(event.components, COMPONENT_ZH) or "组件未明确"
    status = "官方已发布修复" if event.status == "resolved" else STATUS_ZH.get(event.status, event.status)
    event_type = TYPE_ZH.get(event.event_type, event.event_type)
    source = SOURCE_ZH.get(event.source_id, event.source_id)
    date_value = event.updated_at or event.published_at or "日期未明确"
    identifiers = []
    for key in ("cve", "kb", "build", "safeguard_hold"):
        identifiers.extend(str(value) for value in event.identifiers.get(key, []) or [])
    identifiers_text = "、".join(identifiers) or "无额外标识"
    references = _event_references(event)
    reference_items = []
    for number, value in enumerate(references, 1):
        page_label = value["page_id"] or "原始页面"
        reference_items.append(
            f'<li>{_html_link(value["url"], "官方页面 {}：{}".format(number, page_label))}</li>'
        )
    reference_links = "".join(reference_items) or (
        '<li><span class="source-unavailable">暂无可用原文链接</span></li>'
    )
    changes = _labels(event.change_kinds, CHANGE_ZH) or "未明确"
    preconditions = _labels(event.preconditions, PRECONDITION_ZH) or "未明确"
    workflows = _labels(event.affected_workflows, WORKFLOW_ZH) or "未明确"
    assets = "、".join(event.asset_matches) or "未命中已配置资产队列"
    delta = event.event_id in delta_ids
    tone = "red" if event.alert_level == "正式告警" else "amber" if (
        event.alert_level == "调查预警" or event.action_priority >= 75
    ) else "blue"
    search_text = " ".join((title, products, roles, components, identifiers_text, status, event.alert_level, risk_phase(event)[1], workflows))
    update_details = _update_details_summary(event) or "未记录补丁取代或重启关系"
    raw_hash = event.raw_hash[:16] if event.raw_hash else "未提供"
    return f"""
<article class="event-card tone-border-{tone}" id="event-{index}"
  data-search="{_h(search_text.casefold())}" data-alert="{_h(event.alert_level)}"
  data-type="{_h(event_type)}" data-status="{_h(status)}" data-source="{_h(source)}"
  data-phase="{_h(risk_phase(event)[0])}"
  data-product="{_h(products)}" data-delta="{'1' if delta else '0'}">
  <header class="event-head">
    <div class="event-heading">
      <div class="chips">
        <span class="chip chip-{tone}">{_h(event.alert_level)}</span>
        <span class="chip chip-phase">{_h(risk_phase(event)[1])}</span>
        <span class="chip">{_h(event_type)}</span><span class="chip">{_h(status)}</span>
        {'<span class="chip chip-delta">本轮变化</span>' if delta else ''}
      </div>
      <h2>{_html_link(event.source_url, title, 'title-link')}</h2>
      <p class="event-meta">{_h(date_value)} · {_h(source)} · 来源级别 {_h(event.source_tier)} · {_h(roles)}</p>
    </div>
    <div class="priority-score" aria-label="处置优先级">
      <strong>{event.action_priority}</strong><span>处置优先级</span>
    </div>
  </header>
  {_html_patch_context(event)}
  <div class="metrics-grid">
    {_html_metric('技术风险', event.risk_score, tone)}
    {_html_metric('环境相关度', event.environment_relevance, 'blue')}
    {_html_metric('置信度', event.confidence, 'green')}
    {_html_metric('威胁紧迫度', event.threat_urgency, 'purple')}
  </div>
  <div class="fact-grid">
    <div><span>影响产品</span><strong>{_h(products)}</strong></div>
    <div><span>关联组件</span><strong>{_h(components)}</strong></div>
    <div><span>关联标识</span><strong>{_h(identifiers_text)}</strong></div>
    <div><span>资产队列</span><strong>{_h(assets)}</strong></div>
  </div>
  <section class="decision-analysis" aria-label="云桌面影响与行动分析">
    <div class="fact-summary">
      <div class="analysis-heading"><span class="section-kicker">公开事实摘要</span><span class="evidence-badge">已有来源支持</span></div>
      <p>{_h(guidance.problem_summary)} {_html_link(event.source_url, '直达原文', 'inline-citation')}</p>
    </div>
    <div class="applicability-note"><strong>适用性判断</strong><span>{_h(guidance.applicability)}</span></div>
    <div class="analysis-grid">
      <section class="analysis-panel impact-panel">
        <div class="analysis-heading"><span class="section-kicker">对云桌面的潜在影响</span><span class="inference-badge">工程推演 · 需验证</span></div>
        <ul class="action-list">{_html_action_list(guidance.potential_impacts, event.source_url, '触发依据')}</ul>
      </section>
      <section class="analysis-panel test-panel">
        <div class="analysis-heading"><span class="section-kicker">建议测试</span><span class="inference-badge">可执行清单</span></div>
        <ul class="action-list">{_html_action_list(guidance.recommended_tests, event.source_url, '触发依据')}</ul>
      </section>
      <section class="analysis-panel prevention-panel">
        <div class="analysis-heading"><span class="section-kicker">预防与上线门禁</span><span class="inference-badge">建议措施</span></div>
        <ul class="action-list">{_html_action_list(guidance.preventive_actions, event.source_url, '触发依据')}</ul>
      </section>
      <section class="analysis-panel explore-panel">
        <div class="analysis-heading"><span class="section-kicker">针对性探索</span><span class="inference-badge">待回答</span></div>
        <ul class="action-list">{_html_action_list(guidance.exploration_questions, event.source_url, '触发依据')}</ul>
      </section>
    </div>
  </section>
  <details>
    <summary>展开适用条件、补丁关系与全部证据</summary>
    <div class="details-grid">
      <div><span>变化类型</span><p>{_h(changes)}</p></div>
      <div><span>前置条件</span><p>{_h(preconditions)}</p></div>
      <div><span>影响流程</span><p>{_h(workflows)}</p></div>
      <div><span>补丁关系</span><p>{_h(update_details)}</p></div>
    </div>
    <div class="evidence-box">
      <div><span>证据索引</span><code>{_h(event.evidence_id())}</code></div>
      <div><span>原始文档指纹</span><code>{_h(raw_hash)}</code></div>
      <div><span>官方页面</span><strong>{len(references)} 个</strong></div>
    </div>
    <ol class="reference-list">{reference_links}</ol>
  </details>
</article>"""


def write_run_html(
    path: Path,
    template_path: Path,
    run_id: int,
    mode: str,
    window_start: str,
    window_end: str,
    events: Sequence[Event],
    stats: Dict[str, Any],
    warnings: Sequence[str],
    failures: Sequence[Dict[str, str]],
    environment: Optional[Mapping[str, object]] = None,
) -> None:
    """Write a self-contained, offline HTML report with direct source links."""
    ordered = sorted(events, key=lambda event: (-event.action_priority, -event.risk_score, event.event_id))
    new_ids = set(stats.get("new_ids", []))
    fact_changed_ids = set(stats.get("fact_changed_ids", []))
    assessment_changed_ids = set(stats.get("assessment_changed_ids", []))
    delta_ids = new_ids | fact_changed_ids | assessment_changed_ids
    visible = ordered if mode != "incremental" else [event for event in ordered if event.event_id in delta_ids]
    alerts = Counter(event.alert_level for event in events)
    high_count = sum(event.risk_score >= 75 for event in visible)
    gaps = list(warnings) + [f"{item['source_id']}：{item['error']}" for item in failures]
    gaps_html = "".join(f"<li>{_h(value)}</li>" for value in gaps) or "<li>未记录来源异常。</li>"
    cards = "".join(
        _html_event_card(event, index, delta_ids, environment)
        for index, event in enumerate(visible, 1)
    )
    if not cards:
        cards = '<div class="empty-state"><strong>本轮无实质变化</strong><p>没有需要展开的新增或变化事件。</p></div>'

    def options(values: Iterable[str]) -> str:
        return "".join(f'<option value="{_h(value)}">{_h(value)}</option>' for value in sorted(set(values)))

    replacements = {
        "{{RUN_ID}}": str(run_id),
        "{{MODE}}": _h(MODE_ZH.get(mode, mode)),
        "{{WINDOW_START}}": _h(window_start),
        "{{WINDOW_END}}": _h(window_end),
        "{{GENERATED_AT}}": _h(utc_now()),
        "{{TOTAL}}": str(len(events)),
        "{{VISIBLE_TOTAL}}": str(len(visible)),
        "{{NEW}}": str(stats.get("new", 0)),
        "{{FACT_CHANGED}}": str(stats.get("fact_changed", 0)),
        "{{UNCHANGED}}": str(stats.get("unchanged", 0)),
        "{{HIGH_COUNT}}": str(high_count),
        "{{FORMAL_COUNT}}": str(alerts.get("正式告警", 0)),
        "{{INVESTIGATION_COUNT}}": str(alerts.get("调查预警", 0)),
        "{{WATCH_COUNT}}": str(alerts.get("持续观察", 0)),
        "{{ARCHIVE_COUNT}}": str(alerts.get("留档", 0)),
        "{{PRODUCT_OPTIONS}}": options(_product_zh(value) for event in visible for value in event.products),
        "{{TYPE_OPTIONS}}": options(TYPE_ZH.get(event.event_type, event.event_type) for event in visible),
        "{{STATUS_OPTIONS}}": options("官方已发布修复" if event.status == "resolved" else STATUS_ZH.get(event.status, event.status) for event in visible),
        "{{SOURCE_OPTIONS}}": options(SOURCE_ZH.get(event.source_id, event.source_id) for event in visible),
        "{{EVENT_CARDS}}": cards,
        "{{GAPS_HTML}}": gaps_html,
    }
    document = template_path.read_text(encoding="utf-8")
    for marker, value in replacements.items():
        document = document.replace(marker, value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
