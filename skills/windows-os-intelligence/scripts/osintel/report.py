from __future__ import annotations

from collections import Counter
import html
import json
from pathlib import Path
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set
from urllib.parse import urlsplit

from .guidance import build_cloud_desktop_guidance, needs_external_verification
from .model import Event, utc_now
from .patches import patch_rows, phase_explanation, phase_tests, risk_phase
from .scoring import infer_components
from .scope import extract_scope, review_applicability, scope_prefix
from .triage import build_triage
from .verification import build_verification_plan


MODE_ZH = {"backfill": "历史回填", "rolling": "滚动窗口", "incremental": "增量采集"}
TYPE_ZH = {
    "vulnerability": "安全漏洞", "known issue": "已知问题", "lifecycle": "生命周期",
    "compatibility": "兼容性", "feature preview": "预览版本动态",
    "feature": "新特性", "release": "版本发布", "update": "更新",
    "regression": "回归故障", "limitation": "使用限制", "deprecation": "弃用变化",
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
    "microsoft-support": "微软支持专项公告", "microsoft-troubleshoot": "微软故障排查文档",
    "windows-itpro": "Windows IT Pro 官方博客", "citrix-support": "Citrix 厂商公告",
    "microsoft-qa": "Microsoft Q&A 用户反馈", "reddit-sysadmin": "系统管理员社区",
    "reddit-citrix": "Citrix 用户社区",
    "windows-insider-body": "Windows Insider 官方正文",
    "windows-whats-new": "Windows 新特性官方文档",
    "azure-virtual-desktop": "Azure Virtual Desktop 官方文档", "fslogix": "FSLogix 官方文档",
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
    # Reviewed action advice alone does not replace source-text localization.
    if event.evidence_review and re.search(r"[\u4e00-\u9fff]", event.title):
        return event.title
    components = _labels(event.components[:2], COMPONENT_ZH) or "Windows"
    cves = event.identifiers.get("cve", [])
    if event.event_type == "vulnerability":
        identifier = cves[0] if cves else "Windows 漏洞"
        return f"{identifier}：{components}{_impact_zh(event)}漏洞"
    if event.event_type == "known issue":
        scope = event.affected_scope or extract_scope(event)
        if scope.get("applications") and scope.get("symptoms"):
            cpu = " / ".join(scope.get("cpu_architectures", []))
            return f"{'、'.join(scope['applications'])}：{'、'.join(scope['symptoms'])}" + (f"（{cpu}）" if cpu else "")
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


def _proof_state(event: Event) -> str:
    return str(event.evidence_review.get("proof_state") or (
        "官方说明" if event.authoritative_evidence else "来源报告／待核验"
    ))


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
        f"  分阶段验证：{'先补充外部证据，再确定验证阶段。' if needs_external_verification(event) else ' '.join(label + '：' + action for label, action in phase_tests(event))}  \n"
        f"  变化：{_labels(event.change_kinds, CHANGE_ZH) or '未明确'}；"
        f"前置条件：{_labels(event.preconditions, PRECONDITION_ZH) or '未明确'}；"
        f"影响流程：{_labels(event.affected_workflows, WORKFLOW_ZH) or '未明确'}  \n"
        f"  公开事实：{guidance.problem_summary}  \n"
        f"  证据状态：{_proof_state(event)}；独立佐证 {event.corroboration_count} 组（不等于内部复现）。  \n"
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


def _triage_note(triage: Mapping[str, object]) -> str:
    counts = triage["summary"]
    return (
        f"本次纳入分诊 {counts['total']} 条，候选 {counts['eligible']} 条，"
        f"摘要展示 {counts['shown']} 条，候选中另有 {counts['eligible_not_shown']} 条未展开，"
        f"另有 {counts['low_signal_retained']} 条关联不足的线索留存待查。"
        f"其中高关注共 {counts['high_attention_total']} 条，"
        f"摘要未展开的高关注 {counts['high_attention_overflow']} 条。"
        "展示预算不是风险上限，未展开不表示可忽略。"
    )


def _verification_markdown(plan: Mapping[str, object]) -> List[str]:
    lines = [
        f"  - **先做这一件事：{plan['first_action']}**",
        f"  - 建议承接：{plan.get('suggested_role') or plan['owner']}；工程建议，待执行。",
    ]
    for label, key in (("适用条件", "scope"), ("操作步骤", "steps"), ("交付记录", "record")):
        lines.append(f"  - {label}：")
        lines.extend(f"    {index}. {value}" for index, value in enumerate(plan[key], 1))
    lines.append("  - 结果怎么处理：")
    lines.extend(f"    - {row['when']}：{row['then']}" for row in plan["decisions"])
    if plan["missing_inputs"]:
        lines.append("  - 缺少输入：" + "；".join(plan["missing_inputs"]))
    lines.append("  - 方案依据：" + "、".join(
        f"[{row['label']}]({_safe_url(row['url'])})" for row in plan["basis"]
    ))
    return lines


def _item_verification(item: Mapping[str, object], event: Event) -> Mapping[str, object]:
    return item.get("verification_plan") or build_verification_plan(
        event, category=str(item["category"]),
        body_missing=(event.source_id == "windows-insider-sitemap" or not event.evidence.strip()
                      or event.evidence.strip() == event.title.strip()),
    )


def _triage_markdown(triage: Mapping[str, object], events: Sequence[Event]) -> List[str]:
    by_id = {event.event_id: event for event in events}
    lines = ["## 外部风险核验摘要", "", _triage_note(triage), "",
             "按外部证据及通用云桌面流程筛选，不依赖内部画像。潜在关联不等于产品已受影响；复查日期只是建议，尚未自动调度。", ""]
    for item in triage["queue"]:
        event = by_id[item["event_id"]]
        review = item["review"]
        lines.extend([
            f"- **[{_display_title(event)}]({_safe_url(event.source_url)})** · {item.get('direction_label') or item['category_label']} · {item['evidence_state']}",
            f"  - 公开信息：{_display_summary(event)}",
            f"  - {item['priority']}；{item['external_relevance']['label']}：{'；'.join(item['reasons'])}",
        ])
        lines.extend(_verification_markdown(_item_verification(item, event)))
        lines.extend([
            f"  - 未知项：{'；'.join(item['unknowns']) or '暂无额外记录'}",
            f"  - 建议复查：{review['suggested_at']}；触发条件：{'；'.join(review['triggers'])}", "",
        ])
    if not triage["queue"]:
        lines.extend(["本轮没有进入摘要的候选；请同时检查发现覆盖情况及保留事件，不能据此认定没有风险。", ""])
    overflow = triage.get("high_attention_overflow_ids", [])
    if overflow:
        lines.extend(["<details>", f"<summary>摘要未展开的高关注信号：{len(overflow)} 条</summary>", ""])
        lines.extend(f"- [{_display_title(by_id[event_id])}]({_safe_url(by_id[event_id].source_url)})" for event_id in overflow)
        lines.extend(["", "</details>", ""])
    return lines


def _continuity_markdown(context: Mapping[str, object]) -> List[str]:
    if not context:
        return []
    lines = ["## 跨期风险与持续跟进", "", "以下为有来源引用的评审判断，内部适用性未知；不计作本期新增来源事实。", ""]
    changed = set(context["changed_risk_ids"])
    for risk in context["risks"]:
        lines.extend([f"- **{_h(risk['title'])}** · {risk['id']} · {'本次新增/重评' if risk['id'] in changed else '持续跟进'}",
                      f"  - 判断：{_h(risk['mechanism'])}；状态 {risk['status']}；共同生效条件：{_h(risk['coexistence_basis'])}",
                      f"  - 先做：{_h(risk['first_action'])}"])
        lines.extend(f"  - 操作 {i}：{_h(s)}" for i, s in enumerate(risk["steps"], 1))
        lines.extend(f"  - 交付：{_h(s)}" for s in risk["record"])
        lines.extend(f"  - {_h(d['when'])}：{_h(d['then'])}" for d in risk["decisions"])
        lines.extend(f"  - 依据：[{_h(b['event_id'])}]({_safe_url(b['url'])})：{_h(b['quote'])}" for b in risk["basis"])
        lines.extend(f"  - 需重审：{_h(g)}" for g in risk["review_gaps"])
    lines.append(f"\n关联候选 {context['candidate_total']} 条，当前展开 {len(context['candidates'])} 条；其余 {context['candidate_overflow']} 条待评审。")
    lines.extend(f"- {_h(c['title'])} ↔ {_h(c['historical_title'])}：待评审，共享维度不证明组合风险。" for c in context["candidates"])
    lines.extend("- 覆盖缺口：" + _h(g) for g in context["coverage_gaps"])
    lines.append(f"\n私有反馈 {len(context['feedback'])} 条；{sum(f['needs_review'] for f in context['feedback'])} 条引用的对象已修订，需复查。\n")
    return lines


def _html_continuity(context: Mapping[str, object]) -> str:
    if not context:
        return ''
    changed = set(context["changed_risk_ids"])
    states = {"hypothesis": "待验证假设", "supported": "公开证据支持的判断", "dismissed": "已排除组合", "closed": "已关闭"}
    cards = {}
    for risk in context["risks"]:
        body = ''.join(f'<li>{_h(s)}</li>' for s in risk['steps'])
        records = ''.join(f'<li>{_h(s)}</li>' for s in risk['record'])
        decisions = ''.join(f'<li><strong>{_h(d["when"])}</strong>：{_h(d["then"])}</li>' for d in risk['decisions'])
        sources = ''.join(f'<li>{_html_link(b["url"], b["event_id"])}：{_h(b["quote"])}</li>' for b in risk['basis'])
        gaps = ''.join(f'<li>{_h(g)}</li>' for g in risk['review_gaps'] + risk['missing_inputs'])
        previous = risk.get('previous_conclusion')
        previous_html = f'<p><strong>上次结论：</strong>{_h(previous.get("mechanism"))} · {_h(states.get(previous.get("status"), previous.get("status")))}</p>' if previous else '<p>首次建立评审记录。</p>'
        field_names = {"title": "标题", "mechanism": "作用机制", "status": "判断状态", "coexistence": "共同生效判定", "coexistence_basis": "共同生效依据", "constraint_refs": "依赖约束修订", "event_refs": "来源事实修订", "basis": "原文证据", "missing_inputs": "缺失信息", "first_action": "首个动作", "steps": "具体操作", "record": "交付记录", "decisions": "结果处理", "review_note": "评审说明", "suggested_role": "建议承接角色"}
        changes_html = '<ul>'  + ''.join(f'<li>{_h(field_names.get(c["field"], c["field"]))}：{_h(c["before"])} → {_h(c["after"])}</li>' for c in risk.get('changes', [])) + '</ul>'
        history = ''.join(f'<li>{_h(r["updated_at"])} · {_h(states.get(r["status"], r["status"]))} · {_h(r["mechanism"])}</li>' for r in risk['history'])
        cards[risk["id"]] = (f'<div class="triage-card" id="{_h(risk["id"])}"><h3>{_h(risk["title"])}</h3>'
                     f'<p>{"本次新增/重评" if risk["id"] in changed else "持续跟进"} · {_h(states[risk["status"]])} · 内部适用性未知</p>'
                     f'<p>{_h(risk["mechanism"])}</p><p>共同生效条件：{_h(risk["coexistence_basis"])}</p>'
                     f'<p class="verification-first"><strong>先做这一件事：</strong>{_h(risk["first_action"])}</p>'
                     f'<p>建议承接：{_h(risk.get("suggested_role") or "相关组件的工程核验负责人")}</p>' + previous_html +
                     '<details><summary>最近两次评审修订的字段差异</summary>' + changes_html + '</details>'
                     f'<details><summary>展开操作、结果处理与证据时间线</summary><ol>{body}</ol>'
                     f'<strong>交付记录</strong><ul>{records}</ul><strong>结果处理</strong><ul>{decisions}</ul>'
                     f'<strong>缺失/需重审</strong><ul>{gaps}</ul><strong>原始依据</strong><ul>{sources}</ul>'
                     f'<strong>判断修订历史</strong><ol>{history}</ol><code>{_h(risk["id"])}</code></details></div>')
    displayed = context.get('display_risk_ids', list(cards))
    archive = ''.join(body for key, body in cards.items() if key not in displayed)
    candidates = ''.join(f'<li>{_h(c["title"])} ↔ {_h(c["historical_title"])}；待评审，共享维度不是组合风险证明。</li>' for c in context['candidates'])
    gaps = ''.join(f'<li>{_h(g)}</li>' for g in context['coverage_gaps'])
    return ('<section class="highlights" aria-label="跨期风险与持续跟进"><h2>跨期风险与持续跟进</h2>'
            '<p>本期重评历史风险与持续跟进项；不计作本期新增来源事实。本报告不自动执行内部核验；实际执行以私有反馈为准。</p>'
            f'<p>跨期摘要展开 {len(displayed)} 条；另有 {len(context.get("risk_overflow_ids", []))} 条持续风险未展开，仍需跟进。预算仅限制阅读。</p>'
            '<div class="triage-grid">' + ''.join(cards[key] for key in displayed) + '</div>'
            + (f'<details><summary>展开其余持续风险与已排除/关闭记录</summary><div class="triage-grid">{archive}</div></details>' if archive else '')
            + f'<details><summary>待评审关联 {context["candidate_total"]} 条（当前展开 {len(context["candidates"])}；另有 {context["candidate_overflow"]} 条）</summary><ul>{candidates}</ul></details>'
            f'<ul>{gaps}</ul><p class="index-note">私有反馈 {len(context["feedback"])} 条；'
            f'{sum(f["needs_review"] for f in context["feedback"])} 条对象修订需复查。</p></section>')


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
    triage: Optional[Mapping[str, object]] = None,
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
    triage = triage if triage is not None else build_triage(visible, run_at=utc_now())
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
    lines.extend(_triage_markdown(triage, visible))
    lines.extend(_continuity_markdown(triage.get("continuity", {})))
    runtime = triage.get("runtime", {})
    lines.insert(2, f"运行用途：{runtime.get('run_purpose', '未分类')}；数据状态：{runtime.get('dataset_status', '未验收')}。")
    lines.extend(["## 覆盖缺口与来源异常", ""])
    gaps = list(warnings) + [f"{item['source_id']}: {item['error']}" for item in failures]
    lines.extend([f"- {value}" for value in gaps] or ["未记录来源异常；这不代表外部发现已经完整执行。"])
    lines.extend(["", "<details>", "<summary>展开事件参考与场景建议（按分组展示上限；完整事件见同次 HTML／NDJSON）</summary>", "",
                  "以下为工程推演参考，需要结合实际基线细化；不表示已分派测试、已验证影响或已设置发布门禁。", ""])
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
    lines.extend(["", "</details>", ""])
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
    if rows:
        table = f'<details class="patch-details"><summary>查看版本与补丁关系（{len(rows)} 组）</summary>{table}</details>'
    cautions = []
    for scope, message in (
        ("partial", "部分版本仅获得部分修复，仍需验证剩余症状。"),
        ("unconfirmed", "部分版本的修复关系尚未明确，请勿仅凭关联 KB 判断已修复。"),
    ):
        row = next((row for row in rows if row.get("fix_scope") == scope), None)
        if row:
            cautions.append(
                f'<p class="patch-caution">{_h(message)} '
                f'{_html_link(str(row.get("source_url") or event.source_url), "范围依据", "inline-citation")}</p>'
            )
    conditions = sorted({str(value) for row in rows for value in row.get("conditions", [])})
    condition_text = "、".join(conditions) or "需核对官方适用版本、组件与配置前提"
    return (
        f'<section class="patch-context patch-{_h(phase)}" aria-label="风险发生阶段与补丁关系">'
        f'<div class="patch-heading"><span class="risk-phase">{_h(label)}</span>'
        '<span>当前镜像补丁状态：待核对</span></div>'
        f'<p>{_h(phase_explanation(event))} {_html_link(event.source_url, "判断依据", "inline-citation")}</p>'
        f'<p class="patch-note">需核对的触发条件（原文线索）：{_h(condition_text)}。'
        f'{_html_link(event.source_url, "完整条件与排除范围", "inline-citation")}</p>'
        + "".join(cautions) + table + '</section>'
    )


def _html_scope_summary(event: Event, products: str, components: str, roles: str) -> str:
    """Compact display only; retain the complete products and components below."""
    families = []
    for product in event.products:
        match = re.search(r"Windows Server \d{4}|Windows (?:10|11)\b", product, re.I)
        label = match.group(0) if match else _product_zh(product)
        if label not in families:
            families.append(label)
    brief_products = "、".join(families[:5]) or "产品未明确"
    if len(families) > 5:
        brief_products += f"等 {len(families)} 类产品"
    brief_components = _labels(event.components[:2], COMPONENT_ZH) or "组件未明确"
    if len(event.components) > 2:
        brief_components += f"（另 {len(event.components) - 2} 项）"
    return (
        '<details class="scope-details"><summary>'
        f'<span>影响产品：{_h(brief_products)}</span><span>关联组件：{_h(brief_components)}</span>'
        f'<span class="disclosure-hint">完整版本／组件（{len(event.products)} 组产品）</span></summary>'
        '<div class="details-grid">'
        f'<div><span>影响产品 · 完整版本／架构</span><p>{_h(products)}</p></div>'
        f'<div><span>关联组件 · 完整列表</span><p>{_h(components)}</p></div>'
        f'<div><span>系统角色</span><p>{_h(roles)}</p></div></div></details>'
    )


def _html_phase_tests(event: Event) -> str:
    if needs_external_verification(event):
        return ""
    return (
        '<div class="phase-tests" aria-label="不同补丁阶段应该测什么">'
        '<p class="phase-tests-heading">按补丁状态选择验证</p><ul class="action-list">'
        + "".join(
            f'<li><strong>{_h(stage)}：</strong><span>{_h(action)}</span>'
            f'{_html_link(event.source_url, "触发依据", "inline-citation")}</li>'
            for stage, action in phase_tests(event)
        ) + '</ul></div>'
    )


def _html_evidence_review(event: Event) -> str:
    review = event.evidence_review
    if not review:
        return ""
    items = [
        ("证据状态", _proof_state(event)), ("正文核验时间", review.get("reviewed_at", "未知")),
        ("核验说明", review.get("review_note", "未知")),
        ("独立性核验", review.get("independence_note") or "未核对独立观察"),
        ("复现信息", review.get("reproduction_note", "未独立复现")),
        ("仍缺证据", "；".join(str(value) for value in review.get("missing_evidence", [])) or "以原文范围及内部验证为准"),
    ]
    return '<div class="scope-evidence"><p><strong>正文与证据核验</strong></p><ul>' + "".join(
        '<li><strong>' + _h(label) + '</strong>：' + _h(value) + '</li>' for label, value in items
    ) + '</ul><p><strong>原文摘录：</strong>' + _h(event.evidence) + ' ' + _html_link(event.source_url, "摘录来源", "inline-citation") + '</p></div>'


def _html_event_card(
    event: Event, index: int, delta_ids: Set[str],
    environment: Optional[Mapping[str, object]] = None,
    assessment_only_ids: Optional[Set[str]] = None,
    verification_plan: Optional[Mapping[str, object]] = None,
) -> str:
    event.normalized()
    guidance = build_cloud_desktop_guidance(event, environment)
    scope = event.affected_scope or extract_scope(event)
    review = review_applicability(event, environment or {})
    title = _display_title(event)
    products = "、".join(_product_zh(value) for value in event.products) or "产品未明确"
    roles = _labels(event.roles, ROLE_ZH) or "角色未明确"
    components = _labels(event.components, COMPONENT_ZH) or "组件未明确"
    status = ("官方已发布修复" if event.authoritative_evidence else "来源报告已解决，待核验") if event.status == "resolved" else STATUS_ZH.get(event.status, event.status)
    event_type = TYPE_ZH.get(event.event_type, event.event_type)
    source = SOURCE_ZH.get(event.source_id, event.publisher if event.evidence_review else event.source_id)
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
            f'<li>{_html_link(value["url"], "来源页面 {}：{}".format(number, page_label))}</li>'
        )
    reference_links = "".join(reference_items) or (
        '<li><span class="source-unavailable">暂无可用原文链接</span></li>'
    )
    changes = _labels(event.change_kinds, CHANGE_ZH) or "未明确"
    preconditions = _labels(event.preconditions, PRECONDITION_ZH) or "未明确"
    workflows = _labels(event.affected_workflows, WORKFLOW_ZH) or "未明确"
    asset_details = (
        '<div><span>候选验证基线</span><p>' + _h("、".join(event.asset_matches)) + '</p></div>'
    ) if event.asset_matches else ""
    delta = event.event_id in delta_ids
    delta_label = "评估更新" if event.event_id in (assessment_only_ids or set()) else "本轮变化"
    tone = "red" if event.alert_level == "正式告警" else "amber" if (
        event.alert_level == "调查预警" or event.action_priority >= 75
    ) else "blue"
    search_text = " ".join((title, products, roles, components, identifiers_text, status, event.alert_level, risk_phase(event)[1], workflows, scope_prefix(event), review['status']))
    scope_evidence = "".join(
        f'<li><strong>{_h(value["label"])}</strong>：{_h(value["excerpt"])} '
        f'{_html_link(value["url"], "范围依据", "inline-citation")}</li>'
        for value in scope.get("evidence", [])
    )
    cpu = "、".join(scope.get("cpu_architectures", [])) or "未明确"
    cpu += "（部分产品架构未明确）" if scope.get("cpu_architectures") and not scope.get("cpu_scope_known") else ""
    applications = "、".join(scope.get("applications", [])) or "未提取到特定应用范围"
    update_details = _update_details_summary(event) or "未记录补丁取代或重启关系"
    raw_hash = event.raw_hash[:16] if event.raw_hash else "未提供"
    return f"""
<article class="event-card tone-border-{tone}" id="event-{index}"
  data-search="{_h(search_text.casefold())}" data-alert="{_h(event.alert_level)}"
  data-type="{_h(event_type)}" data-status="{_h(status)}" data-source="{_h(source)}"
  data-phase="{_h(risk_phase(event)[0])}"
  data-cpu="{_h('、'.join(scope.get('cpu_architectures', [])) or '未明确')}" data-applicability="{_h(review['status'])}"
  data-product="{_h(products)}" data-delta="{'1' if delta else '0'}">
  <header class="event-head">
    <div class="event-heading">
      <div class="chips">
        <span class="chip chip-{tone}">{_h(event.alert_level)}</span>
        <span class="chip">{_h(event_type)}</span><span class="chip">{_h(status)}</span>
        {'<span class="chip chip-delta">' + delta_label + '</span>' if delta else ''}
      </div>
      <h2>{_html_link(event.source_url, title, 'title-link')}</h2>
      <p class="event-meta">{_h(date_value)} · {_h(source)} · 来源级别 {_h(event.source_tier)} · {_h(roles)}</p>
      <a class="back-index" href="#report-index">返回分组目录</a>
    </div>
  </header>
  {_html_patch_context(event)}
  <div class="metrics-grid">
    {_html_metric('处置优先级', event.action_priority, tone)}
    {_html_metric('技术风险', event.risk_score, tone)}
    {_html_metric('环境相关度', event.environment_relevance, 'blue')}
    {_html_metric('置信度', event.confidence, 'green')}
    {_html_metric('威胁紧迫度', event.threat_urgency, 'purple')}
  </div>
  {_html_scope_summary(event, products, components, roles)}
  <p class="scope-facts"><strong>CPU 范围：</strong>{_h(cpu)} · <strong>应用范围：</strong>{_h(applications)} {_html_link(event.source_url, '范围原文', 'inline-citation')}</p>
  <section class="decision-analysis" aria-label="云桌面影响与行动分析">
    <div class="fact-summary">
      <div class="analysis-heading"><span class="section-kicker">公开事实摘要</span><span class="evidence-badge">{_h(_proof_state(event))}</span></div>
      <p>{_h(guidance.problem_summary)} {_html_link(event.source_url, '直达原文', 'inline-citation')}</p>
      <p>独立佐证 {_h(event.corroboration_count)} 组 · 不等于内部复现或测试通过。</p>
    </div>
    <div class="applicability-note"><strong>适用性判断</strong><span>{_h(guidance.applicability)}</span></div>
    {_html_verification(verification_plan) if verification_plan else ''}
    {'<details class="extended-guidance"><summary>展开潜在影响与扩展场景参考</summary>' if verification_plan else ''}
    <div class="analysis-grid">
      <section class="analysis-panel impact-panel">
        <div class="analysis-heading"><span class="section-kicker">对云桌面的潜在影响</span><span class="inference-badge">工程推演 · 需验证</span></div>
        <ul class="action-list">{_html_action_list(guidance.potential_impacts, event.source_url, '触发依据')}</ul>
      </section>
      <section class="analysis-panel test-panel">
        <div class="analysis-heading"><span class="section-kicker">建议测试</span><span class="inference-badge">场景参考 · 需细化</span></div>
        <ul class="action-list">{_html_action_list(guidance.recommended_tests, event.source_url, '触发依据')}</ul>
        {_html_phase_tests(event)}
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
    {'</details>' if verification_plan else ''}
  </section>
  <details class="evidence-details">
    <summary>查看关联标识、适用条件与证据链（{len(references)} 个来源）</summary>
    <div class="details-grid">
      <div><span>关联标识 · 完整列表</span><p>{_h(identifiers_text)}</p></div>
      {asset_details}
      <div><span>变化类型</span><p>{_h(changes)}</p></div>
      <div><span>前置条件</span><p>{_h(preconditions)}</p></div>
      <div><span>影响流程</span><p>{_h(workflows)}</p></div>
      <div><span>补丁关系</span><p>{_h(update_details)}</p></div>
    </div>
    <div class="evidence-box">
      <div><span>证据索引</span><code>{_h(event.evidence_id())}</code></div>
      <div><span>原始文档指纹</span><code>{_h(raw_hash)}</code></div>
      <div><span>来源页面</span><strong>{len(references)} 个</strong></div>
    </div>
    <ol class="reference-list">{reference_links}</ol>
    {_html_evidence_review(event)}
    <div class="scope-evidence"><p><strong>适用范围提取证据</strong> · {_h(scope.get('schema', 'scope-v1'))}</p><p>{_h(scope.get('coverage', '范围仍需核验'))}</p><ul>{scope_evidence or '<li>未提取到明确范围；请核对完整原文。</li>'}</ul></div>
  </details>
</article>"""


def _directory_theme(event: Event) -> str:
    for component in ("RDP", "RDS", "Hyper-V", "authentication", "GPU/display", "FSLogix/profile", "networking", "printing", "Windows Update", "application compatibility"):
        if component in event.components:
            return COMPONENT_ZH.get(component, component)
    return "其他 Windows 组件"


def _html_directory(events: Sequence[Event], environment: Optional[Mapping[str, object]] = None) -> str:
    groups: Dict[str, List[tuple]] = {phase: [] for phase in ("regression", "change", "security", "unknown")}
    for index, event in enumerate(events, 1):
        groups[risk_phase(event)[0]].append((index, event))

    def entries(items: Sequence[tuple]) -> str:
        return '<ol class="index-list">' + "".join(
            f'<li class="index-entry" data-target="event-{index}"><a href="#event-{index}">{_h(_display_title(event))}</a>'
            f'<span>处置优先级 {event.action_priority} · {_h(review_applicability(event, environment or {})["status"])}</span></li>'
            for index, event in items
        ) + '</ol>'

    labels = {"regression": "更新后的回归风险", "change": "升级／配置与生命周期变化", "security": "未修复时的安全风险", "unknown": "触发阶段待确认"}
    result = []
    for phase, items in groups.items():
        if not items:
            continue
        if phase == "security":
            themes = sorted({_directory_theme(event) for _, event in items})
            body = "".join(
                f'<details class="index-subgroup"><summary>{_h(theme)} <span class="index-count"></span></summary>'
                + entries([(index, event) for index, event in items if _directory_theme(event) == theme]) + '</details>'
                for theme in themes
            )
        else:
            body = entries(items)
        result.append(
            f'<details class="index-group" data-phase="{phase}"{ " open" if phase != "security" else ""}>'
            f'<summary>{labels[phase]} <span class="index-count">{len(items)} 条</span></summary>{body}</details>'
        )
    return "".join(result) or '<p>本轮没有需要展开的事件。</p>'


def _html_verification(plan: Mapping[str, object], *, compact: bool = False) -> str:
    def listed(key: str, ordered: bool = False) -> str:
        tag = "ol" if ordered else "ul"
        return f'<{tag}>' + ''.join(f'<li>{_h(value)}</li>' for value in plan[key]) + f'</{tag}>'

    decisions = ''.join(
        f'<li><strong>{_h(row["when"])}</strong>：{_h(row["then"])}</li>'
        for row in plan["decisions"]
    )
    missing = '<p class="verification-missing"><strong>缺少输入：</strong>' + _h('；'.join(plan['missing_inputs'])) + '</p>' if plan['missing_inputs'] else ''
    basis = '、'.join(_html_link(row['url'], row['label'], 'inline-citation') for row in plan['basis'])
    method = (
        '<details class="verification-scope"><summary>先核对这些适用条件</summary>' + listed('scope') + '</details>'
        + '<strong>具体操作</strong>' + listed('steps', ordered=True)
        + '<strong>交付什么记录</strong>' + listed('record')
        + '<strong>结果怎么处理</strong><ul>' + decisions + '</ul>'
        + missing + f'<p class="index-note">方案依据：{basis}</p>'
    )
    if compact:
        method = '<details class="verification-method"><summary>展开操作、交付记录和结果处理</summary>' + method + '</details>'
    return (
        f'<section class="verification-plan" data-verification-status="{_h(plan["status"])}" aria-label="下一步怎么做">'
        '<p class="verification-label">下一步怎么做 · 工程建议，待执行</p>'
        f'<p class="verification-first"><strong>先做这一件事：</strong>{_h(plan["first_action"])}</p>'
        f'<p class="index-note">建议承接：{_h(plan.get("suggested_role") or plan["owner"])}</p>'
        + method + '</section>'
    )


def _html_triage(triage: Mapping[str, object], events: Sequence[Event]) -> str:
    by_id = {event.event_id: (index, event) for index, event in enumerate(events, 1)}
    cards = []
    for item in triage["queue"]:
        index, event = by_id[item["event_id"]]
        review = item["review"]
        plan = _item_verification(item, event)
        cards.append(
            '<div class="triage-card">'
            f'<p class="triage-label">{_h(item.get("direction_label") or item["category_label"])} · {_h(item["evidence_state"])}</p>'
            f'<h3>{_html_link(event.source_url, _display_title(event), "title-link")}</h3>'
            f'<p>{_h(_display_summary(event))}</p>'
            f'<p><strong>为什么核验：</strong>{_h("；".join(item["reasons"]))}</p>'
            f'<p class="index-note">{_h(item["priority"])} · {_h(item["external_relevance"]["label"])}；与内部适用性分开。</p>'
            f'{_html_verification(plan, compact=True)}'
            f'<p><strong>未知项：</strong>{_h("；".join(item["unknowns"]) or "暂无额外记录")}</p>'
            f'<p class="index-note">建议复查 {_h(review["suggested_at"])} · {_h("；".join(review["triggers"]))}</p>'
            f'<a class="triage-detail" href="#event-{index}">查看来源范围与场景参考</a></div>'
        )
    overflow = triage.get("high_attention_overflow_ids", [])
    overflow_html = ''
    if overflow:
        links = ''.join(
            f'<li><a href="#event-{by_id[event_id][0]}">{_h(_display_title(by_id[event_id][1]))}</a></li>'
            for event_id in overflow
        )
        overflow_html = (
            '<details class="triage-overflow">'
            f'<summary>摘要未展开的高关注信号：{len(overflow)} 条，需继续评审</summary>'
            f'<ul>{links}</ul></details>'
        )
    return (
        f'<p>{_h(_triage_note(triage))}</p>'
        '<p class="index-note">依据外部证据及通用云桌面流程筛选，不依赖内部画像。'
        '潜在关联不等于产品已受影响；复查日期只是建议，尚未自动调度。摘要不随下方资料筛选器隐藏。</p>'
        '<div class="triage-grid">' + ''.join(cards) + '</div>' + overflow_html
        + ('' if cards else '<p>本轮没有进入摘要的候选；请检查发现覆盖与保留事件，不能据此认定没有风险。</p>')
    )


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
    triage: Optional[Mapping[str, object]] = None,
) -> None:
    """Write a self-contained, offline HTML report with direct source links."""
    ordered = sorted(events, key=lambda event: (-event.action_priority, -event.risk_score, event.event_id))
    new_ids = set(stats.get("new_ids", []))
    fact_changed_ids = set(stats.get("fact_changed_ids", []))
    assessment_changed_ids = set(stats.get("assessment_changed_ids", []))
    delta_ids = new_ids | fact_changed_ids | assessment_changed_ids
    visible = ordered if mode != "incremental" else [event for event in ordered if event.event_id in delta_ids]
    triage = triage if triage is not None else build_triage(visible, run_at=utc_now())
    alerts = Counter(event.alert_level for event in events)
    high_count = sum(event.risk_score >= 75 for event in visible)
    gaps = list(warnings) + [f"{item['source_id']}：{item['error']}" for item in failures]
    gaps_html = "".join(f"<li>{_h(value)}</li>" for value in gaps) or "<li>未记录来源异常；这不代表外部发现已经完整执行。</li>"
    visible_by_id = {event.event_id: event for event in visible}
    verification_by_id = {
        item["event_id"]: _item_verification(item, visible_by_id[item["event_id"]])
        for item in triage["items"] if item["eligible"] and item["event_id"] in visible_by_id
    }
    cards = "".join(
        _html_event_card(event, index, delta_ids, environment, assessment_changed_ids - new_ids - fact_changed_ids,
                         verification_by_id.get(event.event_id))
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
        "{{ASSESSMENT_CHANGED}}": str(stats.get("assessment_changed", 0)),
        "{{HIGH_COUNT}}": str(high_count),
        "{{FORMAL_COUNT}}": str(alerts.get("正式告警", 0)),
        "{{INVESTIGATION_COUNT}}": str(alerts.get("调查预警", 0)),
        "{{WATCH_COUNT}}": str(alerts.get("持续观察", 0)),
        "{{ARCHIVE_COUNT}}": str(alerts.get("留档", 0)),
        "{{PRODUCT_OPTIONS}}": options(_product_zh(value) for event in visible for value in event.products),
        "{{TYPE_OPTIONS}}": options(TYPE_ZH.get(event.event_type, event.event_type) for event in visible),
        "{{STATUS_OPTIONS}}": options(("官方已发布修复" if event.authoritative_evidence else "来源报告已解决，待核验") if event.status == "resolved" else STATUS_ZH.get(event.status, event.status) for event in visible),
        "{{SOURCE_OPTIONS}}": options(SOURCE_ZH.get(event.source_id, event.source_id) for event in visible),
        "{{EVENT_CARDS}}": cards,
        "{{REPORT_INDEX}}": _html_directory(visible, environment),
        "{{TRIAGE}}": _html_triage(triage, visible),
        "{{CONTINUITY}}": _html_continuity(triage.get("continuity", {})),
        "{{RUNTIME_LABEL}}": _h("运行用途：" + triage.get("runtime", {}).get("run_purpose", "未分类") + " · 数据：" + triage.get("runtime", {}).get("dataset_status", "未验收")),
        "{{CPU_OPTIONS}}": options(value for event in visible for value in (event.affected_scope or extract_scope(event)).get("cpu_architectures", []) or ["未明确"]),
        "{{BASELINE_NOTE}}": (
            '<p class="baseline-note">尚未配置具体验证基线；当前仅提供候选范围与潜在影响分析，'
            '不表示实际设备已受影响或未受影响。</p>'
            if not any(event.asset_matches for event in events) and not any(
                isinstance(group, Mapping) and group.get("enabled", True) is not False
                for group in (environment or {}).get("asset_groups", []) or []
            ) else ""
        ),
        "{{GAPS_HTML}}": gaps_html,
    }
    document = template_path.read_text(encoding="utf-8")
    for marker, value in replacements.items():
        document = document.replace(marker, value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document, encoding="utf-8")
