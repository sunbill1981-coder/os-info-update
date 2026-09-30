"""Evidence-backed patch roles and human-facing patch-stage interpretation."""
from __future__ import annotations

import re
from typing import Dict, List, Sequence

from .model import Event
from .parsers import Block
from .scoring import extract_identifiers
from .scope import extract_scope, scope_prefix


def release_patch_details(
    blocks: Sequence[Block], title: str, product: str, url: str, status: str,
) -> Dict[str, object]:
    cells = [block.text for block in blocks if block.tag == "td"]
    paragraphs = [block.text for block in blocks if block.tag in {"p", "li"}]
    body = " ".join(paragraphs)
    origin = cells[1] if len(cells) >= 3 else ""
    fixed = cells[0] if len(cells) >= 3 and status == "resolved" else ""
    # Never interpret every KB mentioned in prose as an originating or fixing KB.
    if not origin:
        match = re.search(r"after (?:installing|installation of)\b[^.]{0,500}", title + " " + body, re.I)
        origin = match.group(0) if match else ""
    resolution = [text for text in paragraphs if re.match(r"Resolution\s*:", text, re.I)]
    resolution_text = " ".join(resolution)
    if resolution and re.search(r"\b(?:resolved|fixed)\b", resolution_text, re.I):
        fixed += " " + resolution_text
    mitigation = []
    in_workaround = False
    for text in paragraphs:
        if re.match(r"(?:Resolution|Next Steps|Affected platforms)\s*:", text, re.I):
            in_workaround = False
        if re.match(r"Workaround\s*:", text, re.I):
            in_workaround = True
        if in_workaround:
            mitigation.append(text)
    introduced = extract_identifiers(origin)["kb"]
    fixed_kb = extract_identifiers(fixed)["kb"]
    partial = bool(re.search(r"\bpartially (?:resolved|fixed)\b", resolution_text, re.I))
    changed_after_update = bool(introduced or re.search(
        r"after (?:installing|installation of)\b", title + " " + body, re.I,
    ))
    # These are source-supported configuration clues, not sufficient conditions.
    clues = (
        ("remote desktop services", "Windows 远程桌面服务（RDS）"),
        ("fslogix", "FSLogix 用户配置文件"),
        ("existing user profiles", "存量用户配置文件"),
        ("credential guard", "Credential Guard 凭据保护"),
        ("machine identity isolation", "机器身份隔离策略与域功能级别组合"),
        ("usb audio class 1.0", "USB Audio Class 1.0 设备"),
        ("arm-based", "ARM 架构设备"),
        ("hyper-v", "Hyper-V 虚拟化环境"),
        ("plan9", "Plan9 宿主机文件夹共享"),
        ("non-english", "非英语 Windows 安装环境"),
    )
    lowered = (title + " " + body).casefold()
    conditions = [label for term, label in clues if term in lowered]
    exclusions = [
        text for text in paragraphs
        if re.search(r"(?:does not|do not) affect\b|not (?:known to be )?affected", text, re.I)
    ]
    return {
        "relationship": "update_regression" if changed_after_update else "unknown",
        "products": [product],
        "introduced_kb": introduced,
        "introduced_build": extract_identifiers(origin)["build"],
        "fixed_kb": fixed_kb,
        "mitigation_kb": sorted(set(extract_identifiers(" ".join(mitigation))["kb"]) - set(introduced) - set(fixed_kb)),
        "fix_scope": "partial" if partial else "complete" if status == "resolved" and fixed_kb else "unconfirmed",
        "conditions": conditions,
        "exclusions_evidence": exclusions,
        "source_url": url,
        "status": status,
        "evidence": " | ".join(cells[:3] + resolution)[:1600],
    }


def risk_phase(event: Event) -> tuple[str, str]:
    if event.event_type == "vulnerability":
        return "security", "未修复时的安全风险"
    if any(row.get("relationship") == "update_regression" for row in event.update_details):
        return "regression", "更新后的回归风险"
    if event.event_type == "feature preview" or any(
        value in event.change_kinds for value in ("行为变化", "安全机制收紧", "弃用或移除", "behavior change", "security enforcement", "deprecation")
    ):
        return "change", "升级／配置变更风险"
    return "unknown", "问题触发阶段待确认"


def patch_rows(event: Event) -> List[Dict[str, object]]:
    """Keep product-specific patch pairs intact; prefer the latest observation."""
    rows: Dict[tuple, Dict[str, object]] = {}
    for detail in event.update_details:
        if detail.get("relationship"):
            row = dict(detail)
        elif str(detail.get("type") or "") == "2" or detail.get("fixed_build"):
            row = {
                "products": detail.get("products") or ["适用版本未明确"],
                "introduced_kb": [], "fixed_kb": detail.get("kb") or [],
                "mitigation_kb": [], "fixed_build": detail.get("fixed_build") or "",
                "source_url": detail.get("url") or event.source_url,
                "fix_scope": "security", "conditions": [],
            }
        else:
            continue
        key = (tuple(row.get("products") or []), row.get("fixed_build") or "")
        prior = rows.get(key)
        if prior is None or (str(row.get("observed_at") or ""), str(row.get("source_url") or "")) > (
            str(prior.get("observed_at") or ""), str(prior.get("source_url") or ""),
        ):
            rows[key] = row
    return sorted(rows.values(), key=lambda row: " ".join(row.get("products") or []))


def phase_explanation(event: Event) -> str:
    phase, _ = risk_phase(event)
    if phase == "security":
        return "风险成立于受影响版本尚未获得漏洞修复时。先核对对应修复 KB、Build 或包含修复的累计更新，再验证更新后的业务兼容性；缺少某个旧 KB 编号不等于尚未修复。"
    if phase == "regression":
        return "风险发生在安装引入更新或包含该变更的后续更新后，并需满足官方触发条件。下表按版本区分引入、修复与缓解措施；官方已解决不代表当前镜像已验证通过。"
    if phase == "change":
        return "关注升级或启用新配置后的行为与兼容性变化。预览信号仍需核验正文和正式发布路径。"
    return "当前证据尚不足以区分补丁前后触发方向，请核对原文适用条件；关联 KB 仅作为检索线索。"


def phase_tests(event: Event) -> List[tuple[str, str]]:
    phase, _ = risk_phase(event)
    scope = event.affected_scope or extract_scope(event)
    prefix = scope_prefix(event)

    def scoped(values: List[tuple[str, str]]) -> List[tuple[str, str]]:
        return [(label, f"先核对 {prefix}。{action}") for label, action in values] if prefix else values

    if phase == "regression" and scope.get("applications") and scope.get("symptoms"):
        partial = any(row.get("fix_scope") == "partial" for row in patch_rows(event))
        return scoped([
            ("尚未包含引入变更", "记录指定应用的启动、登录和退出基线，与更新后对比；本条不证明补丁前存在该回归。"),
            ("已包含引入变更、未获完整修复", "在原文 CPU／应用／配置范围内复现指定应用故障；对比新部署与存量镜像以及应用更新状态，不直接扩展为会话、克隆或加域故障。"),
            ("已安装修复或缓解措施", "验证指定应用原症状与剩余症状，并检查缓解措施撤销和回滚。" if partial else "验证指定应用启动和退出恢复正常；若仅使用缓解措施，继续核对残余风险与撤销路径。"),
        ])
    if phase == "security":
        return scoped([
            ("未获得修复", "核对系统、组件和攻击前提是否相交，确认修复覆盖范围并安排补丁验证。"),
            ("已安装修复", "核验对应 Build 和修复有效性，执行交付、登录、会话及业务兼容性回归。"),
            ("已安装后续累计更新", "核对官方取代／修复包含关系，再执行同一专项回归；不要只检查旧 KB 是否存在。"),
        ])
    if phase == "regression":
        partial = any(row.get("fix_scope") == "partial" for row in patch_rows(event))
        return scoped([
            ("尚未包含引入变更", "记录问题流程的正常基线，与更新后结果对比；本条不证明此时存在该回归。"),
            ("已包含引入变更、未获完整修复", "按官方配置和症状复现问题，覆盖存量／新建桌面及登录、持续会话、重连等相关流程。"),
            ("已安装修复或缓解措施", "分别验证已修复症状和剩余症状，检查缓解措施的撤销与回滚。" if partial else "验证原故障是否消失、核心流程是否正常；只有缓解措施时继续验证残余风险和撤销路径。"),
        ])
    return scoped([("升级或配置变更前后", "核验适用版本和前提，保留基线对照，在隔离环境验证行为变化与回滚。")])
