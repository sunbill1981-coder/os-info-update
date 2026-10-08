"""External Windows signals worth examining, independent of local deployment fit.

This is a bounded reading queue, not a new risk score, alert policy or test plan.
All input events remain in ``items``. No event is merged, modified or scheduled.
Only existing structured dimensions establish candidate workflow relationships;
source prose, internal relevance scores and generated advice are not reclassified.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional

from .model import Event
from .verification import build_verification_plan


CATEGORY_LABELS = {
    "failure": "故障与兼容性线索",
    "change": "新特性与行为变化",
    "security": "安全暴露",
    "lifecycle": "生命周期与支持变化",
}
# These describe Windows workflows shared with desktop delivery, not an
# assertion that any vendor product uses a particular component or protocol.
ROUTES = (
    ("远程会话", "direct", {"RDP", "RDS", "peripheral redirection"},
     {"远程会话连接"}, set()),
    ("虚拟化与配置文件", "direct", {"Hyper-V", "FSLogix/profile"},
     set(), set()),
    ("身份认证与域关系", "shared", {"authentication", "Credential Guard", "VBS"},
     {"身份认证与登录", "域加入与信任关系", "domain join", "user logon"}, set()),
    ("镜像交付与启动", "shared", {"image/recovery"},
     {"桌面镜像与交付", "启动与恢复", "desktop provisioning", "image deployment"},
     {"基于镜像或克隆部署", "cloned image"}),
    ("图形、外设与应用", "shared", {"GPU/display", "printing", "audio/media", "application compatibility"},
     {"图形与显示", "打印与外设", "应用启动与兼容"}, set()),
    ("网络与文件访问", "shared", {"networking"}, {"文件与配置文件访问"}, set()),
    ("更新与升级", "shared", {"Windows Update"},
     {"补丁安装与升级", "patch deployment", "in-place upgrade"}, set()),
)
SEVERE_SYMPTOMS = {
    "认证或授权失败", "连接中断", "崩溃或无响应", "蓝屏或无法启动", "数据损坏或丢失",
    "authentication failure", "connection failure",
}
COMMUNITY_SOURCES = {"microsoft-qa", "reddit-sysadmin", "reddit-citrix"}
CONSTRAINT_CHANGES = {
    "安全机制收紧", "默认行为变化", "弃用或移除", "前置条件变化", "版本组合限制",
    "更新回归", "behavior change", "security enforcement", "compatibility change",
    "deprecation", "servicing change",
}
DIRECTION_LABELS = {"constraint": "既有行为与约束变化", "feature": "新特性与预览线索"}
DEFAULT_CONFIG = {
    "display_budget": 8,
    "category_order": ["failure", "change", "security", "lifecycle"],
    "review_days": {"high": 1, "normal": 7, "low": 30},
    "workflow_routes": [
        {"label": label, "kind": kind, "components": sorted(components),
         "workflows": sorted(workflows), "preconditions": sorted(preconditions)}
        for label, kind, components, workflows, preconditions in ROUTES
    ],
    "severe_symptoms": sorted(SEVERE_SYMPTOMS),
    "attention_change_kinds": [
        "安全机制收紧", "默认行为变化", "弃用或移除", "前置条件变化", "版本组合限制",
        "security enforcement", "deprecation", "behavior change",
    ],
}


def _category(event: Event) -> str:
    if event.event_type == "vulnerability":
        return "security"
    if event.event_type == "lifecycle":
        return "lifecycle"
    if event.preview or event.event_type == "feature preview":
        return "change"
    if event.symptoms or event.affected_scope.get("symptoms"):
        return "failure"
    if event.change_kinds:
        return "change"
    if event.event_type == "known issue":
        return "failure"
    if event.event_type == "compatibility" and not event.change_kinds:
        return "failure"
    return "change"


def _relations(event: Event, routes: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    components, workflows, preconditions = map(
        set, (event.components, event.affected_workflows, event.preconditions),
    )
    result = []
    for route in routes:
        matched = sorted(
            (components & set(route.get("components", [])))
            | (workflows & set(route.get("workflows", [])))
            | (preconditions & set(route.get("preconditions", [])))
        )
        if matched:
            result.append({"workflow": route["label"], "kind": route["kind"], "matched_dimensions": matched})
    return result


def _proof(event: Event, body_missing: bool) -> str:
    kind = event.evidence_review.get("source_kind")
    if body_missing:
        return "索引或摘要线索；正文待核验"
    if kind == "community" or event.source_tier == "P3" or event.source_id in COMMUNITY_SOURCES:
        return "用户报告；未证明因果或内部复现"
    if event.authoritative_evidence and event.source_tier in {"P0", "P1"}:
        return "官方说明；不代表内部已受影响"
    if kind == "vendor" or event.source_id == "citrix-support":
        return "厂商说明；需核对适用范围"
    return "外部线索；证据待核验"


def _item(event: Event, now: datetime, settings: Mapping[str, Any], review_days: Mapping[str, int]) -> Dict[str, Any]:
    category = _category(event)
    constraint_kinds = CONSTRAINT_CHANGES | set(settings["attention_change_kinds"])
    direction = ("constraint" if set(event.change_kinds) & constraint_kinds else "feature") if category == "change" else ""
    relations = _relations(event, settings["workflow_routes"])
    direct = any(value["kind"] == "direct" for value in relations)
    body_missing = (event.source_id == "windows-insider-sitemap" or not event.evidence.strip()
                    or event.evidence.strip() == event.title.strip())
    concrete_failure = category == "failure" and bool(event.symptoms or event.affected_scope.get("symptoms"))
    urgent_security = category == "security" and (
        event.kev.get("listed") is True or event.exploitation_status == "已确认被利用"
    )
    # Unknown local baselines never lower these values. A lone concrete user
    # report can merit investigation without becoming a confirmed incident.
    eligible = bool(relations) or urgent_security or category == "lifecycle" or (
        category == "change" and bool(event.preview or event.event_type in {"feature", "feature preview"} or event.change_kinds)
    )
    material_change = (
        category == "change" and bool(relations) and not body_missing
        and bool(set(event.change_kinds) & set(settings["attention_change_kinds"]))
    )
    high = urgent_security or material_change or (
        category == "failure" and bool(relations) and concrete_failure and not body_missing and (
            direct or bool(set(event.symptoms) & set(settings["severe_symptoms"]))
        )
    )
    priority_key = "high" if high else "normal" if eligible else "low"
    priority = {"high": "优先核验", "normal": "计划核验", "low": "留存待查"}[priority_key]
    reasons = []
    if relations:
        reasons.append("结构化维度涉及" + "、".join(value["workflow"] for value in relations) + "，存在外部云桌面候选关联。")
    else:
        reasons.append("现有结构化字段尚未定位云桌面关联流程；保留线索，不假定影响所有桌面。")
    if urgent_security:
        reasons.append("已有利用或 KEV 线索，优先补齐暴露条件与范围。")
    if concrete_failure:
        reasons.append("来源记录了具体异常症状，值得核验触发条件；不表示已确认补丁因果。")
    if category == "change":
        reasons.append("变化评估可以早于故障；先判断新增、收紧或移除的行为是否需要补充版本测试场景。")
    if material_change:
        reasons.append("已有具体行为/约束变化及关联流程，优先核验版本测试缺口；尚未出现故障也可进入核验。")
    if body_missing:
        reasons.append("先补充正文，当前不能把索引或标题当成已确认行为变化。")

    unknowns = []
    if body_missing:
        unknowns.append("完整正文及具体变化/故障事实待核验")
    if not event.products:
        unknowns.append("外部受影响 Windows 产品与版本未明确")
    if not event.builds:
        unknowns.append("外部 Build 与补丁状态边界待核对")
    if not event.preconditions and not event.affected_scope.get("conditions"):
        unknowns.append("触发条件及排除范围未明确")
    if not relations:
        unknowns.append("与桌面业务流程的关系尚待建立")
    unknowns.extend(str(value) for value in event.evidence_review.get("missing_evidence", []) or [])
    unknowns.append("内部产品/现场是否采用相关组件与条件尚需核验；外部分诊不确认内部影响")

    if body_missing:
        questions = ["能否取得完整原文，确认具体变化、适用版本和发布日期，而非仅有公告标题？"]
    elif category == "security":
        questions = ["原文的攻击前提、受影响组件及修复范围是什么，是否涉及桌面侧可到达的路径？"]
    elif category == "lifecycle":
        questions = ["哪个版本/Edition 的何种支持在何时变化，是否要求调整产品兼容矩阵或迁移场景？"]
    elif category == "change":
        questions = ["具体增加、收紧或移除了什么行为，旧版到新版的哪个流程需要新增对照验证？"]
    else:
        questions = ["最小触发条件、原始症状和前后对照是什么，哪些日志可区分因果与同期变更？"]
    if relations:
        questions.append("先核对" + relations[0]["workflow"] + "的真实调用路径；哪些条件相同，哪些只是表面相似？")
    else:
        questions.append("完整证据能否建立与登录、交付、会话、应用或维护等具体流程的关系？")
    questions.append("完成外部核验后，现有版本测试计划是否已有对应场景；只有缺口明确时再补充场景或现场支持卡？")
    if category == "security":
        next_action = "先核验暴露条件与修复范围；关联已有安全/兼容验证，避免每条 CVE 重复生成整套回归。"
    elif body_missing:
        next_action = "补正文后再判断场景价值；目前不生成已确认变化结论或执行测试单。"
    else:
        next_action = "先完成最小外部核验，再决定纳入现有版本测试场景或形成现场支持线索。"

    return {
        "event_id": event.event_id,
        "category": category,
        "category_label": CATEGORY_LABELS[category],
        "direction": direction,
        "direction_label": DIRECTION_LABELS.get(direction, ""),
        "source_title": event.title,
        "source_url": event.source_url,
        "priority": priority,
        "priority_key": priority_key,
        "high_attention": high,
        "eligible": eligible,
        "shown": False,
        "external_relevance": {
            "label": "直接链路候选" if direct else "共性流程候选" if relations else "关联待明确",
            "routes": relations,
            "basis": "仅依据公开事件已有结构化维度；独立于内部画像及适用性，不证明产品已受影响。",
        },
        "evidence_state": _proof(event, body_missing),
        "evidence": {
            "excerpt": event.evidence,
            "source_tier": event.source_tier,
            "source_references": deepcopy(event.source_references),
            "fact_fingerprint": event.fact_hash(),
        },
        "internal_applicability": deepcopy(event.applicability_review) or {"status": "未知"},
        "reasons": reasons,
        "unknowns": list(dict.fromkeys(unknowns)),
        "questions": questions,
        "next_action": next_action,
        "verification_plan": build_verification_plan(event, category=category, body_missing=body_missing),
        "review": {
            "suggested_at": (now + timedelta(days=review_days[priority_key])).isoformat(),
            "scheduled": False,
            "basis": "按本次运行时间建议复查；未创建提醒或定时任务。",
            "triggers": [
                "原文补全，或适用范围、触发条件、修复/支持状态出现实质变化",
                "取得独立用户报告、厂商解释或可复核的前后对照",
                "产品版本测试范围或现场资料补齐，可进一步核验内部适用性",
            ],
        },
        "exclusion_reason": "" if eligible else "现有结构化维度不足以建立关联，保留待查；不是已证明无风险。",
    }


def build_triage(
    events: Iterable[Event], *, run_at: str,
    config: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a serializable complete inventory and category-balanced shortlist.

    ``run_at`` is the actual run timestamp with timezone, never a backfill window
    end. Reading a config file and rendering/localization belong to the caller.
    Changes reserve separate opportunities for constraints and new features.
    With a budget below the active groups, category_order decides which appear;
    per-category/direction counts and high-attention overflow stay explicit.
    """
    now = datetime.fromisoformat(run_at.replace("Z", "+00:00"))
    if now.tzinfo is None:
        raise ValueError("run_at 必须包含时区")
    now = now.astimezone(timezone.utc)
    settings = dict(DEFAULT_CONFIG)
    settings.update(config or {})
    budget = settings["display_budget"]
    if isinstance(budget, bool) or not isinstance(budget, int) or budget < 0:
        raise ValueError("display_budget 必须为非负整数")
    order = list(settings["category_order"])
    if len(order) != len(CATEGORY_LABELS) or set(order) != set(CATEGORY_LABELS):
        raise ValueError("category_order 必须恰好包含四种分诊类别")
    review_days = dict(DEFAULT_CONFIG["review_days"])
    review_days.update(settings.get("review_days") or {})
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in review_days.values()):
        raise ValueError("review_days 必须为正整数")
    for field in ("severe_symptoms", "attention_change_kinds"):
        if not isinstance(settings[field], list) or not all(isinstance(value, str) for value in settings[field]):
            raise ValueError(field + " 必须为字符串列表")
    if not isinstance(settings["workflow_routes"], list):
        raise ValueError("workflow_routes 必须为规则列表")
    for route in settings["workflow_routes"]:
        if (not isinstance(route, Mapping) or not isinstance(route.get("label"), str)
                or not route["label"].strip() or route.get("kind") not in {"direct", "shared"}):
            raise ValueError("每条 workflow_routes 必须有 label 及 direct/shared 类型")
        for field in ("components", "workflows", "preconditions"):
            values = route.get(field, [])
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                raise ValueError("workflow_routes 的匹配维度必须为字符串列表")

    copies = [deepcopy(event).normalized() for event in events]
    if len({event.event_id for event in copies}) != len(copies):
        raise ValueError("分诊输入包含重复事件编号，应先完成事件去重")
    items = [_item(event, now, settings, review_days) for event in copies]
    by_id = {event.event_id: event for event in copies}

    def sort_key(item: Mapping[str, Any]) -> tuple:
        event = by_id[item["event_id"]]
        return (
            -int(item["high_attention"]), -int(item["eligible"]),
            -int(item["external_relevance"]["label"] == "直接链路候选"),
            -event.confidence,
            -(datetime.fromisoformat(event.updated_at or event.published_at).toordinal()
              if event.updated_at or event.published_at else 0),
            event.event_id,
        )

    items.sort(key=sort_key)
    group_order = [group for key in order for group in (
        ["change:constraint", "change:feature"] if key == "change" else [key]
    )]

    def group_key(item: Mapping[str, Any]) -> str:
        return "change:" + item["direction"] if item["category"] == "change" else item["category"]

    buckets = {key: [item for item in items if item["eligible"] and group_key(item) == key] for key in group_order}
    queue = []
    positions = Counter()
    def take_round(high_only: bool = False) -> bool:
        added = False
        for key in group_order:
            if len(queue) >= budget:
                break
            if positions[key] < len(buckets[key]):
                item = buckets[key][positions[key]]
                if high_only and not item["high_attention"]:
                    continue
                positions[key] += 1
                item["shown"] = True
                queue.append(item)
                added = True
        return added

    # Reserve one reading opportunity for each category before filling remaining
    # space with concrete high-attention signals. A long list of sitemap titles
    # must not repeatedly displace substantive failures simply for equal quotas.
    take_round()
    while len(queue) < budget and take_round(high_only=True):
        pass
    while len(queue) < budget and take_round():
        pass

    overflow = [item["event_id"] for item in items if item["high_attention"] and not item["shown"]]
    eligible_count = sum(item["eligible"] for item in items)
    return {
        "schema": "external-triage-v1",
        "run_at": now.isoformat(),
        "policy": "外部候选核验，不代替内部适用性、正式告警或测试执行；全量保留，首轮各类别展示一条（变化类分别保留约束与新特性），余量优先高关注并按类别轮转。",
        "summary": {
            "total": len(items), "eligible": eligible_count, "shown": len(queue),
            "not_shown": len(items) - len(queue),
            "eligible_not_shown": eligible_count - len(queue),
            "low_signal_retained": len(items) - eligible_count,
            "high_attention_total": sum(item["high_attention"] for item in items),
            "high_attention_overflow": len(overflow), "display_budget": budget,
        },
        "categories": {
            key: {
                "label": CATEGORY_LABELS[key],
                "total": sum(item["category"] == key for item in items),
                "eligible": sum(item["category"] == key and item["eligible"] for item in items),
                "shown": sum(item["category"] == key and item["shown"] for item in items),
                "not_shown": sum(item["category"] == key and not item["shown"] for item in items),
                "high_attention_overflow": sum(item["category"] == key and item["high_attention"] and not item["shown"] for item in items),
            } for key in order
        },
        "directions": {
            key: {
                "label": label,
                "total": sum(item["direction"] == key for item in items),
                "shown": sum(item["direction"] == key and item["shown"] for item in items),
                "not_shown": sum(item["direction"] == key and not item["shown"] for item in items),
            } for key, label in DIRECTION_LABELS.items()
        },
        "items": items,
        "queue": queue,
        "high_attention_overflow_ids": overflow,
        "excluded_reason_counts": dict(Counter(item["exclusion_reason"] for item in items if not item["eligible"])),
        "warnings": [f"还有 {len(overflow)} 条优先核验线索未在阅读预算内展示；请检查完整分诊结果，不能视为已处理或低风险。"] if overflow else [],
    }
