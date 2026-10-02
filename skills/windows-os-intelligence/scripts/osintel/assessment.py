from __future__ import annotations

from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

from .model import Event
from .scope import extract_scope, review_applicability


def _matches(text: str, terms: Iterable[str]) -> bool:
    lowered = text.casefold()
    return any(term.casefold() in lowered for term in terms)


def classify_text(text: str, taxonomy: Mapping[str, object]) -> Dict[str, List[str]]:
    result: Dict[str, List[str]] = {}
    for dimension in ("change_kinds", "preconditions", "affected_workflows", "symptoms"):
        rules = taxonomy.get(dimension, {})
        result[dimension] = sorted(
            label for label, terms in rules.items()
            if _matches(text, terms)
        )
    return result


def _product_matches(left: str, right: str) -> bool:
    first, second = left.casefold(), right.casefold()
    return first in second or second in first


def match_asset_groups(event: Event, environment: Mapping[str, object]) -> Tuple[List[str], int, int]:
    names: List[str] = []
    count = 0
    best_score = 0
    for group in environment.get("asset_groups", []) or []:
        if not isinstance(group, Mapping) or group.get("enabled", True) is False:
            continue
        products = [str(value) for value in group.get("products", []) or []]
        if products and not any(
            _product_matches(target, product) for target in products for product in event.products
        ):
            continue
        roles = set(str(value) for value in group.get("roles", []) or [])
        if roles and not roles.intersection(event.roles):
            continue
        builds = set(str(value) for value in group.get("builds", []) or [])
        if builds and event.builds and not builds.intersection(event.builds):
            continue
        components = set(str(value) for value in group.get("components", []) or [])
        component_match = len(components.intersection(event.components))
        score = 30 if products else 0
        score += 15 if roles else 0
        score += min(15, component_match * 5)
        score += 10 if builds and event.builds else 0
        score += round(min(100, int(group.get("criticality", 0) or 0)) * 0.2)
        best_score = max(best_score, score)
        names.append(str(group.get("name") or group.get("id") or "未命名资产队列"))
        count += max(0, int(group.get("asset_count", 0) or 0))
    return sorted(set(names)), count, min(100, best_score)


def environment_relevance(event: Event, environment: Mapping[str, object]) -> int:
    score = 0
    target_products = [str(value).casefold() for value in environment.get("products", [])]
    if any(any(target in product.casefold() for target in target_products) for product in event.products):
        score += 25

    target_roles = set(environment.get("roles", []))
    if target_roles.intersection(event.roles):
        score += 15

    target_components = set(environment.get("components", []))
    component_matches = target_components.intersection(event.components)
    if component_matches:
        score += min(25, 10 + 5 * len(component_matches))

    workflow_criticality = environment.get("workflow_criticality", {})
    workflow_values = [int(workflow_criticality[name]) for name in event.affected_workflows if name in workflow_criticality]
    if workflow_values:
        score += round(max(workflow_values) * 0.25)

    deployment_patterns = environment.get("deployment_patterns", {})
    known_matches = [name for name in event.preconditions if deployment_patterns.get(name) is True]
    if known_matches:
        score += min(10, 5 * len(known_matches))

    _, _, group_score = match_asset_groups(event, environment)
    return min(100, max(score, group_score))


def action_priority(risk: int, relevance: int, confidence: int, threat_urgency: int = 0) -> int:
    original = risk * 0.55 + relevance * 0.35 + confidence * 0.10
    enriched = risk * 0.40 + relevance * 0.30 + confidence * 0.10 + threat_urgency * 0.20
    return max(0, min(100, round(max(original, enriched))))


def inferred_risk(event: Event) -> int:
    score = 25
    score += min(20, 8 * len(event.change_kinds))
    score += min(15, 5 * len(event.preconditions))
    score += min(15, 5 * len(event.affected_workflows))
    symptom_weight = {
        "蓝屏或无法启动": 25,
        "数据损坏或丢失": 25,
        "崩溃或无响应": 22,
        "认证或授权失败": 20,
        "连接中断": 18,
        "安装或升级失败": 18,
        "性能下降": 12,
    }
    score += max((symptom_weight.get(value, 8) for value in event.symptoms), default=0)
    return min(95, score)


def alert_level(event: Event) -> str:
    if event.risk_score >= 75 and event.environment_relevance >= 70:
        if (
            event.confidence >= 85
            and event.authoritative_evidence
            and event.source_tier in {"P0", "P1"}
        ):
            return "正式告警"
        if event.confidence >= 45 and event.corroboration_count >= 2:
            return "调查预警"
    if event.action_priority >= 65:
        return "重点关注"
    if event.action_priority >= 45:
        return "持续观察"
    return "留档"


def assess_event(event: Event, taxonomy: Mapping[str, object], environment: Mapping[str, object]) -> Event:
    if not event.affected_scope:
        event.affected_scope = extract_scope(event)
    event.applicability_review = review_applicability(event, environment)
    # Assess source evidence only. Generated recommendations would feed the model's own
    # wording back into classification and create systematic false positives.
    text = " ".join((event.title, event.summary, event.evidence))
    # Reviewed discovery is already a scoped semantic extraction. Re-classifying
    # incidental words (e.g. "reboot" as a boot failure) would broaden that scope.
    dimensions = {} if event.evidence_review else classify_text(text, taxonomy)
    for name, values in dimensions.items():
        current = getattr(event, name)
        setattr(event, name, sorted(set(current + values)))
    event.risk_score = max(event.risk_score, inferred_risk(event))
    event.environment_relevance = environment_relevance(event, environment)
    event.asset_matches, event.affected_asset_count, _ = match_asset_groups(event, environment)
    event.action_priority = action_priority(
        event.risk_score, event.environment_relevance, event.confidence, event.threat_urgency,
    )
    event.alert_level = alert_level(event)
    return event
