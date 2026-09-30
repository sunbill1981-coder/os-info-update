"""Evidence-supported scope extraction, independent of numeric risk scoring.

CPU architecture is not a delivery architecture (VDI/IDV/etc.). Missing scope
is unknown, and a negative observation must not become an affected product.
These are versioned derived fields: existing fact/alert hashes stay unchanged.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Dict, List, Mapping, Optional

from .model import Event


RULES = json.loads((Path(__file__).resolve().parents[2] / "config/scope-rules.json").read_text(encoding="utf-8"))
NEGATIVE = re.compile(r"not (?:known to be |currently known to be )?affected|unaffected|does not affect|do not affect|not impacted|no known impact", re.I)
HEDGED_NEGATIVE = re.compile(r"not (?:currently )?known|no known", re.I)
FAILURE = re.compile(r"fail|unable|crash|unexpected|not (?:launch|start|open)", re.I)


def _sentences(text: str) -> List[str]:
    return [value.strip() for value in re.split(r"(?<=[.!?。])\s+|\n+", text) if value.strip()]


def _matches(text: str, rules: Mapping[str, str]) -> List[str]:
    return [label for label, pattern in rules.items() if re.search(pattern, text, re.I)]


def _apps(text: str) -> List[str]:
    values = _matches(text, RULES["applications"])
    if "新版 Outlook" in values or "经典版 Outlook" in values:
        values = [value for value in values if value != "Outlook"]
    return values


def _title_apps(title: str) -> List[str]:
    known = _apps(title)
    if known:
        return known
    # Generic title grammar catches named applications beyond the alias catalog.
    # Unnamed cohorts and OS/device subjects remain unknown.
    match = re.match(r"^(.{2,90}?)\s+(?:(?:might|may|can|could)\s+)?(?:fail(?:s)? to|(?:does|do) not)\s+(?:launch|open|start)\b", title, re.I)
    if not match:
        return []
    subject = match.group(1).strip()
    if re.search(r"\b(?:Windows|devices?|systems?|some|certain|other|apps?|applications?)\b", subject, re.I):
        return []
    return [value.strip() for value in re.split(r",\s*|\s+and\s+", subject) if value.strip()]


def extract_scope(event: Event, body: Optional[str] = None) -> Dict[str, Any]:
    text = body if body is not None else f"{event.summary} {event.evidence}"
    sentences = _sentences(text)
    positive = [sentence for sentence in sentences if not NEGATIVE.search(sentence)]
    evidence: List[Dict[str, str]] = []

    def cite(dimension: str, label: str, excerpt: str) -> None:
        evidence.append({"dimension": dimension, "label": label, "excerpt": excerpt, "url": event.source_url})

    architectures = []
    title_architectures = _matches(event.title, RULES["architectures"])
    if not NEGATIVE.search(event.title):
        for architecture in title_architectures:
            architectures.append(architecture)
            cite("cpu_architectures", architecture, event.title)
    for sentence in positive:
        # An incidental architecture in workaround instructions is not scope.
        if FAILURE.search(sentence) or re.search(r"(?:only|limited to|affects|affected devices|affected systems)", sentence, re.I):
            for architecture in _matches(sentence, RULES["architectures"]):
                architectures.append(architecture)
                cite("cpu_architectures", architecture, sentence)
    # MSRC product identities carry explicit affected architectures.
    if event.event_type == "vulnerability":
        for product in event.products:
            for architecture in _matches(product, RULES["architectures"]):
                architectures.append(architecture)
                cite("cpu_architectures", architecture, product)
        # Partial architecture labels in a mixed product set cannot exclude
        # unspecified products, e.g. Windows Server without an arch suffix.
        architecture_complete = bool(event.products) and all(_matches(product, RULES["architectures"]) for product in event.products)
    else:
        architecture_complete = bool(architectures)

    applications = _title_apps(event.title) if FAILURE.search(event.title) else []
    if applications:
        cite("applications", "、".join(applications), event.title)
    for sentence in positive:
        if FAILURE.search(sentence):
            names = _apps(sentence)
            applications.extend(names)
            if names:
                cite("applications", "、".join(names), sentence)
    # Prefer the precise app variant from the issue prose over a generic title.
    if "新版 Outlook" in applications or "经典版 Outlook" in applications:
        applications = [value for value in applications if value != "Outlook"]

    conditions = []
    for key, rule in RULES["conditions"].items():
        for sentence in positive:
            if re.search(rule["pattern"], sentence, re.I):
                conditions.append({"id": key, "label": rule["label"]})
                cite("conditions", rule["label"], sentence)
                break
    exclusions = []
    for sentence in sentences:
        if not NEGATIVE.search(sentence):
            continue
        names = _apps(sentence) + _matches(sentence, RULES["architectures"])
        if names:
            qualifier = "未发现已知影响（不是绝对排除）" if HEDGED_NEGATIVE.search(sentence) else "原文明确不受该问题影响"
            label = "、".join(names) + "：" + qualifier
            exclusions.append({"label": label, "certainty": "not_known_affected" if HEDGED_NEGATIVE.search(sentence) else "explicit", "targets": names})
            cite("exclusions", label, sentence)
    symptoms = _matches(" ".join([event.title] + positive), RULES["symptoms"])
    for symptom in symptoms:
        excerpt = next((value for value in [event.title] + positive if re.search(RULES["symptoms"][symptom], value, re.I)), event.title)
        cite("symptoms", symptom, excerpt)
    unique_evidence = {json.dumps(value, sort_keys=True, ensure_ascii=False): value for value in evidence}
    return {
        "schema": RULES["version"], "cpu_architectures": sorted(set(architectures)),
        "cpu_scope_known": architecture_complete, "applications": sorted(set(applications)),
        "conditions": conditions, "exclusions": exclusions, "symptoms": symptoms,
        "evidence": list(unique_evidence.values()),
        "product_cpu_scopes": [
            {"product": product, "architectures": _matches(product, RULES["architectures"])}
            for product in event.products
        ] if event.event_type == "vulnerability" else [],
        "coverage": "仅提取可识别的原文范围线索；仍需核对完整条件，来源权威性不代表范围解析完整。",
    }


def merge_scopes(scopes: List[Dict[str, Any]]) -> Dict[str, Any]:
    valid = [value for value in scopes if value]
    if not valid:
        return {}
    merged = dict(valid[0])
    for field in ("cpu_architectures", "applications", "conditions", "exclusions", "symptoms", "evidence", "product_cpu_scopes"):
        values = [item for scope in valid for item in scope.get(field, [])]
        unique = {json.dumps(item, sort_keys=True, ensure_ascii=False): item for item in values}
        merged[field] = [unique[key] for key in sorted(unique)]
    merged["cpu_scope_known"] = all(value.get("cpu_scope_known", False) for value in valid)
    return merged


def _canonical_architecture(value: str) -> str:
    lowered = value.casefold()
    if lowered in {"arm", "arm64", "aarch64"}:
        return "arm"
    if lowered in {"x64", "amd64", "x86-64"}:
        return "x64"
    return "x86" if lowered in {"x86", "32-bit"} else ""


def _product_match(left: str, right: str) -> bool:
    # CPU suffixes belong to their own dimension; remove them for OS matching.
    def normalized(value: str) -> str:
        return re.sub(r"\s+for\s+(?:ARM64|x64|32-bit)(?:-based)?\s+Systems", "", value, flags=re.I).casefold()
    first, second = normalized(left), normalized(right)
    return first in second or second in first


def review_applicability(event: Event, environment: Mapping[str, object]) -> Dict[str, Any]:
    groups = [group for group in environment.get("asset_groups", []) or [] if isinstance(group, Mapping) and group.get("enabled", True) is not False]
    scope = event.affected_scope or extract_scope(event)
    if not groups:
        return {"schema": "applicability-v1", "status": "未知", "reason": "CPU、应用和触发条件尚未完成具体核验；不能用产品组合相关度代替实际适用性。", "groups": []}
    reviews = []
    for group in groups:
        misses, unknowns = [], []
        products = list(group.get("products", []) or [])
        if products and event.products:
            if not any(_product_match(str(left), str(right)) for left in products for right in event.products):
                misses.append("Windows 产品版本不相交")
        else:
            unknowns.append("Windows 产品版本待核对")
        roles = set(group.get("roles", []) or [])
        if roles and set(event.roles) - {"unknown"}:
            if not roles.intersection(event.roles):
                misses.append("系统角色不相交")
        else:
            unknowns.append("系统角色待核对")
        affected_arch = {_canonical_architecture(value) for value in scope.get("cpu_architectures", [])}
        architecture_known = scope.get("cpu_scope_known")
        product_scopes = scope.get("product_cpu_scopes", [])
        if product_scopes and products:
            selected = [value for value in product_scopes if any(_product_match(str(product), value["product"]) for product in products)]
            architecture_known = bool(selected) and all(value["architectures"] for value in selected)
            affected_arch = {_canonical_architecture(value) for item in selected for value in item["architectures"]}
        local_arch = {_canonical_architecture(str(value)) for value in group.get("cpu_architectures", []) or []} - {""}
        if affected_arch and architecture_known and local_arch:
            if not affected_arch.intersection(local_arch):
                misses.append("CPU 架构不相交")
        else:
            unknowns.append("CPU 适用范围或基线架构待核对")
        apps = scope.get("applications", [])
        local_apps = group.get("applications")
        if apps:
            if local_apps is None:
                unknowns.append("受影响应用是否使用待核对")
            elif not any(_app_match(str(left), str(right)) for left in apps for right in local_apps):
                misses.append("已声明的应用清单未包含受影响应用")
        condition_values = group.get("scope_conditions", {}) or {}
        for condition in scope.get("conditions", []):
            # A clue may describe a higher-likelihood cohort or workaround,
            # not a necessary condition. False must not auto-exclude.
            if condition_values.get(condition["id"]) is not True:
                unknowns.append(condition["label"] + "待核对")
        status = "不匹配" if misses else "未知" if unknowns else "匹配"
        reviews.append({"name": str(group.get("name") or group.get("id") or "未命名基线"), "status": status, "reasons": misses + unknowns or ["已提取维度与声明基线相交；不等于已复现或已受影响"]})
    states = {value["status"] for value in reviews}
    status = "匹配" if "匹配" in states else "未知" if "未知" in states else "不匹配"
    return {"schema": "applicability-v1", "status": status, "reason": "仅核验已提取的公开范围与已声明基线，不代表实际影响；未知不等于匹配。", "groups": reviews}


def _app_match(left: str, right: str) -> bool:
    left_names = _apps(left) or [left]
    right_names = _apps(right) or [right]
    return any(first.casefold() == second.casefold() or (first == "Outlook" and second in {"新版 Outlook", "经典版 Outlook"}) for first in left_names for second in right_names)


def scope_prefix(event: Event) -> str:
    scope = event.affected_scope or extract_scope(event)
    parts = []
    if scope.get("cpu_architectures"):
        parts.append("CPU 范围：" + "、".join(scope["cpu_architectures"]) + ("（存在架构未明确的产品，不能据此排除其他架构）" if not scope.get("cpu_scope_known") else ""))
    if scope.get("applications"):
        parts.append("受影响应用：" + "、".join(scope["applications"]))
    return "；".join(parts)
