"""Small, source-bounded verification plans; never executed tests or impact findings.

An excerpt or automatically extracted scope is not a completed scope review.
The source reviewer may supply a validated semantic plan, or explicitly record
``scope_verified`` with ``scope_basis`` after checking the original scope.
The public function is deterministic and never modifies an Event or a plan.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
from typing import Any, Dict, Mapping

from .model import Event, parse_date


SCHEMA = "verification-plan-v1"
ANALYST = "情报分析"
ENGINEERING = "产品研发或测试"
CONFIG = json.loads((Path(__file__).resolve().parents[2] / "config/verification.json").read_text(encoding="utf-8"))
_LIST_FIELDS = ("scope", "steps", "record", "missing_inputs")
_UNKNOWN = {"unknown", "not specified", "未明确", "未知", ""}
_STATUS_ZH = {"confirmed": "来源已确认", "reported": "来源已报告", "investigating": "调查中",
              "mitigated": "来源已缓解", "unknown": "未明确"}
_FIX_SCOPE_ZH = {"complete": "完整修复", "partial": "部分修复", "security": "安全修复",
                 "unconfirmed": "未确认", "unknown": "未明确"}


def _values(values: Any) -> list[str]:
    return [str(value).strip() for value in (values or [])
            if str(value).strip().casefold() not in _UNKNOWN]


def _labels(values: Any) -> list[str]:
    return [str(value.get("label") or value.get("id") or "").strip()
            if isinstance(value, Mapping) else str(value).strip() for value in (values or [])]


def _show(values: list[str], limit: int = 4) -> str:
    clean = list(dict.fromkeys(value for value in values if value))
    return "、".join(clean[:limit]) + (f" 等 {len(clean)} 项（完整范围见事件详情）" if len(clean) > limit else "")


def _products(values: Any) -> list[str]:
    return [re.sub(r"\bversion\b", "版本", value, flags=re.I) for value in _values(values)]


def _source_urls(event: Event) -> set[str]:
    return {str(value) for value in [event.source_url] + [
        row.get("url") for row in event.source_references if isinstance(row, Mapping)
    ] if value}


def validate_verification_plan(plan: Mapping[str, Any], event: Event) -> Dict[str, Any]:
    """Validate reviewed semantics at ingestion and return a detached copy.

    Validation checks structure/provenance, not truth of arbitrary source prose.
    ``scope_verified`` means externally reviewed scope, never internal impact.
    All product actions must remain conditional on a later local scope check.
    """
    if not isinstance(plan, Mapping) or plan.get("schema") != SCHEMA:
        raise ValueError("核验计划 schema 必须为 verification-plan-v1")
    result = deepcopy(dict(plan))
    if result.get("executed") is not False:
        raise ValueError("核验计划必须标记 executed=false，不能作为已执行结果")
    for key in ("status", "owner", "first_action"):
        if not isinstance(result.get(key), str) or not result[key].strip():
            raise ValueError(f"核验计划 {key} 必须为非空字符串")
    if result["status"] not in {"待补外部证据", "待核对内部范围"}:
        raise ValueError("核验计划状态只能是待补外部证据或待核对内部范围")
    if result["owner"] not in {ANALYST, ENGINEERING}:
        raise ValueError("核验计划 owner 必须为情报分析或产品研发或测试")
    for key in _LIST_FIELDS:
        if not isinstance(result.get(key), list) or any(not isinstance(value, str) or not value.strip() for value in result[key]):
            raise ValueError(f"核验计划 {key} 必须为字符串列表")
    if not result["steps"] or not result["record"] or not result["scope"]:
        raise ValueError("核验计划 scope、steps、record 不得为空")
    for key, fields in (("decisions", ("when", "then")), ("basis", ("label", "url"))):
        if not isinstance(result.get(key), list) or not result[key]:
            raise ValueError(f"核验计划 {key} 必须为非空对象列表")
        for row in result[key]:
            if not isinstance(row, Mapping) or any(not isinstance(row.get(field), str) or not row[field].strip() for field in fields):
                raise ValueError(f"核验计划 {key} 字段不完整")
    if any(row["url"] not in _source_urls(event) for row in result["basis"]):
        raise ValueError("核验计划 basis 只能引用事件已有来源或 source_references")
    if "scope_verified" in result and not isinstance(result["scope_verified"], bool):
        raise ValueError("scope_verified 必须为布尔值")
    if "scope_basis" in result and not isinstance(result["scope_basis"], str):
        raise ValueError("scope_basis 必须为字符串")
    if "suggested_role" in result and (not isinstance(result["suggested_role"], str) or not result["suggested_role"].strip()):
        raise ValueError("suggested_role 如有提供必须为非空字符串")
    if result.get("scope_verified") is True:
        if not result.get("scope_basis", "").strip():
            raise ValueError("已核验外部范围必须说明 scope_basis")
    if result["owner"] == ENGINEERING:
        if (result["status"] != "待核对内部范围" or result.get("scope_verified") is not True
                or not (parse_date(event.published_at) or parse_date(event.updated_at))):
            raise ValueError("产品核验需有来源日期和已核验的外部范围；否则先由情报分析补证")
    elif result["status"] != "待补外部证据":
        raise ValueError("情报分析阶段应标记待补外部证据")
    # A source-authored plan cannot certify a product deployment or test result.
    result["internal_applicability"] = "未知"
    result["executed"] = False
    return result


def _scope(event: Event) -> list[str]:
    scope = event.affected_scope
    rows = [
        "来源产品/版本：" + (_show(_products(event.products)) or "未明确"),
        "来源 Build：" + (_show(_values(event.builds)) or "未明确"),
        "前置条件：" + (_show(_values(event.preconditions)) or "未明确"),
        "原文触发条件：" + (_show(_labels(scope.get("conditions"))) or "未明确；不能视为无条件触发"),
    ]
    for label, key in (("CPU 架构", "cpu_architectures"), ("应用", "applications")):
        if scope.get(key):
            rows.append(label + "：" + _show(_values(scope[key])))
    exclusions = scope.get("exclusions") or []
    exclusion_labels = []
    for value in exclusions:
        label = _labels([value])[0]
        if isinstance(value, Mapping) and value.get("certainty") == "not_known_affected":
            label += "（仅未发现已知影响，不作绝对排除）"
        exclusion_labels.append(label)
    rows.append("原文排除范围：" + (_show(exclusion_labels) or "未明确；不能推断其它环境安全"))
    if event.affected_workflows:
        rows.append("来源关联流程：" + _show(_values(event.affected_workflows)))
    if event.symptoms or scope.get("symptoms"):
        rows.append("来源症状：" + _show(_values(event.symptoms) + _values(scope.get("symptoms"))))
    status = _STATUS_ZH.get(event.status, event.status or "未明确")
    if event.status == "resolved":
        status = "官方已发布修复" if event.authoritative_evidence else "来源报告已解决，待核验"
    rows.append("来源问题状态：" + status + "；不等于内部已修复")
    patch_rows = []
    for detail in event.update_details:
        if not isinstance(detail, Mapping):
            continue
        fixes = _values(detail.get("fixed_kb"))
        if not fixes and str(detail.get("type") or "") == "2":
            fixes = _values(detail.get("kb"))
        build = str(detail.get("fixed_build") or "")
        if fixes or build:
            product = _show(_products(detail.get("products"))) or "产品边界待核对"
            fix_scope = str(detail.get("fix_scope") or "未明确")
            patch_rows.append(product + " → " + _show(fixes + (["Build " + build] if build else []))
                              + "（来源修复范围：" + _FIX_SCOPE_ZH.get(fix_scope, fix_scope) + "）")
    rows.append("修复关系：" + (_show(patch_rows) or "未取得按产品核验的修复关系；事件标识列表不能当作修复清单"))
    return rows


def _basis(event: Event) -> list[dict[str, str]]:
    result = [{"label": "本事件原始来源", "url": event.source_url}] if event.source_url else []
    for row in event.source_references:
        if isinstance(row, Mapping) and row.get("url") and row["url"] not in {value["url"] for value in result}:
            result.append({"label": "事件补充来源", "url": str(row["url"])})
    return result


def _decisions(category: str) -> list[dict[str, str]]:
    result = [
        {"when": "内部产品、版本或必要条件明确不相交", "then": "记录不适用的具体差异、基线版本和依据；来源或基线变化后重审。"},
        {"when": "外部范围或内部版本/配置仍未知", "then": "标记待补输入，写明缺什么、由谁补；不能用未复现或低相关度替代范围判断。"},
        {"when": "产品版本和必要条件命中", "then": "只执行本计划的针对性核验；尚未执行时维持内部影响未知。"},
    ]
    if category == "security":
        result.append({"when": "命中暴露条件且修复未覆盖或不明", "then": "记录安全整改/补丁核验工作项及责任人；验证受支持修复覆盖，不以漏洞利用证明受影响。"})
    elif category == "lifecycle":
        result.append({"when": "在用版本命中已核实的支持截止条件", "then": "把支持缺口、迁移选项和负责人纳入版本计划；不把停止支持描述为已发生故障。"})
    else:
        result.append({"when": "隔离对照复现来源症状或出现可重复的兼容差异", "then": "建立缺陷，附版本/配置、步骤、预期与实际、对照日志；关联本事件及受影响测试计划。"})
    result.append({"when": "本次核验未发现问题", "then": "只记录本次覆盖的版本、条件和结果；保留未覆盖边界，不能宣称所有产品不受影响。"})
    return result


def _focus(event: Event) -> str:
    workflows = _values(event.affected_workflows)
    symptoms = _values(event.symptoms) + _values(event.affected_scope.get("symptoms"))
    return (_show(workflows) or _show(_values(event.components)) or "来源具体流程待明确") + (
        "；只观察「" + _show(symptoms) + "」" if symptoms else "；只观察原文明确的新旧行为差异"
    )


def _workflow_steps(event: Event) -> list[str]:
    # Match declared workflows only; components never expand to unrelated flows.
    actions = CONFIG.get("workflow_actions", {})
    values = [actions[key] for key in event.affected_workflows if key in actions]
    if not values:
        values = ["按原文已核验的操作步骤执行一次目标流程，记录开始、结束、结果与相应日志；若原文没有可执行步骤，退回情报分析补证。"]
    return list(dict.fromkeys(values))


def build_verification_plan(event: Event, *, category: str, body_missing: bool) -> Dict[str, Any]:
    """Build a source-specific next action without requiring internal profiles."""
    supplied = event.evidence_review.get("verification_plan")
    reviewed = validate_verification_plan(supplied, event) if supplied is not None else None
    body_missing = bool(body_missing or not event.evidence.strip() or event.evidence.strip() == event.title.strip())
    dated = bool(parse_date(event.published_at) or parse_date(event.updated_at))
    reviewed_scope = reviewed if reviewed is not None else event.evidence_review
    verified = reviewed_scope.get("scope_verified") is True and bool(str(reviewed_scope.get("scope_basis") or "").strip())
    needs_workflow = category not in {"security", "lifecycle"}
    concrete = bool(_values(event.products) and (
        not needs_workflow or event.affected_workflows or event.components
    ))
    ready = verified and concrete and dated and not body_missing and bool(event.source_url)
    if reviewed is not None and (reviewed["owner"] == ANALYST or ready):
        return reviewed

    missing = list(dict.fromkeys(_values(event.evidence_review.get("missing_evidence"))))
    if body_missing:
        missing.insert(0, "完整正文与具体事实；当前仅标题、索引或摘要不足以提出产品实验")
    if not dated:
        missing.append("可核实的原始发布时间或实质修订日期（不能使用抓取时间替代）")
    if not event.source_url:
        missing.append("可回查的原始来源 URL")
    if not verified:
        missing.append("外部适用范围的人工/智能体核验结论：版本、必要条件、排除边界及出处；自动提取字段不是完整范围核验")
    if not _values(event.products):
        missing.append("来源所指的具体产品和版本")
    if needs_workflow and not event.affected_workflows and not event.components:
        missing.append("来源变化影响的具体组件或操作流程")
    scope = _scope(event)
    plan = {
        "schema": SCHEMA, "status": "待核对内部范围" if ready else "待补外部证据",
        "owner": ENGINEERING if ready else ANALYST, "first_action": "", "scope": scope,
        "steps": [], "record": [], "decisions": _decisions(category), "missing_inputs": missing,
        "basis": _basis(event), "executed": False, "internal_applicability": "未知",
        "scope_verified": bool(ready), "scope_basis": str(reviewed_scope.get("scope_basis") or "") if ready else "",
    }
    current = "；".join(scope[:4])
    if not ready:
        plan["first_action"] = f"情报分析先打开本事件原始来源，补齐正文、日期及适用范围，并逐项核对当前记录：{current}。"
        plan["steps"] = [
            "读取完整原文及本事件已有补充来源，区分正文事实、作者自述与回复推测；记录发布日期/实质修订日期和原始 URL。",
            "核对「" + _focus(event) + "」对应的产品版本、必要条件和排除边界；来源没有说明的字段明确记为未知，不能自行补成政策命令或实验配置。",
            "查清来源当前修复/缓解状态及按产品的修复边界；只有外部范围可支持明确匹配问题时，保存范围核验结论与原文依据，再交产品研发或测试核对现有基线。",
        ]
        plan["record"] = ["补齐的原文快照/链接、真实发布日期或修订日期", "具体范围与对应原文依据、仍缺失的字段及补证责任人", "下一步是继续补外部证据，还是可核对内部范围；本阶段没有执行产品测试"]
        return plan

    plan["missing_inputs"].append("待核对的内部产品版本、Windows 基线、组件/配置清单及其记录日期（未提供不等于不适用）")
    plan["first_action"] = f"产品研发或测试从当前版本测试计划/配置清单中找出与以下外部范围可能相交的基线，逐项记录匹配、不匹配或未知：{current}。"
    plan["steps"] = ["先只核对版本、组件和原文必要条件，不修改配置。明确不匹配则记录依据；任一必要输入未知则补输入，不直接执行实验。"]
    if category == "security":
        plan["steps"] += [
            "仅对匹配基线核对原文攻击/暴露前提是否实际成立、受影响组件是否启用和可达，以及对应产品修复是否已覆盖；不运行漏洞利用。",
            "修复状态未知时由情报分析补按产品的官方修复关系，产品研发或测试提供已安装版本记录；需要验证修复时，在隔离环境只确认修复生效及该组件正常使用结果。",
        ]
    elif category == "lifecycle":
        plan["steps"].append("仅对匹配版本核对来源支持截止条件、内部版本计划和仍需支持的场景；记录支持缺口及迁移负责人，尚无具体行为变化时不生成回归实验。")
    else:
        plan["steps"].append("仅在范围匹配后选择现有隔离测试环境，固化来源涉及的版本/配置；只对照来源明确的变更变量，执行「" + _focus(event) + "」。若缺少可对照的版本/配置，先补输入。")
        plan["steps"] += _workflow_steps(event)
        plan["steps"].append("记录同一流程在对照组和变更组的结果；保持其它已知条件一致，不把论坛临时绕过措施自动当作修复。")
    plan["record"] = [
        "内部产品/Windows 版本、Build、组件与必要配置的实际值、清单来源和核对日期",
        "逐项范围匹配表：命中、不相交或未知，以及对应依据",
        "执行时记录来源目标流程、单一变更变量、预期与实际、对照日志；未执行项明确记未执行",
        "结论限定的版本与条件、缺陷或版本测试计划链接、责任人和下一次重审触发条件",
    ]
    if category == "security":
        plan["record"][2] = "组件启用/可达性、攻击前提、按产品的修复覆盖及其依据；未核实的项明确未知，不填漏洞利用结果"
    elif category == "lifecycle":
        plan["record"][2] = "来源支持截止条件、内部版本计划中的对应节点、支持缺口与迁移负责人；没有执行回归实验"
    return plan
