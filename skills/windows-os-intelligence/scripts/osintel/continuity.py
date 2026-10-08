"""Review-backed cross-period constraints and risks, separate from Event facts."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from .model import Event, parse_date, stable_hash

FIELDS = {
    "constraint": {"schema", "id", "claim_key", "title", "mechanism", "before", "after",
                   "status", "effective_at", "products", "components", "workflows",
                   "conditions", "exclusions", "event_refs", "basis", "review_note"},
    "risk": {"schema", "id", "claim_key", "title", "mechanism", "status", "coexistence",
             "coexistence_basis", "constraint_refs", "event_refs", "basis", "missing_inputs",
             "first_action", "steps", "record", "decisions", "review_note", "suggested_role"},
    "feedback": {"schema", "id", "subject_kind", "subject_id", "subject_revision",
                 "applicability", "action_clear", "executed", "result", "baseline",
                 "owner", "next_action", "note", "recorded_at"},
}


def _text(row, keys):
    for key in keys:
        if not isinstance(row.get(key), str) or not row[key].strip():
            raise ValueError(f"{key} 必须为非空字符串")


def _lists(row, keys):
    for key in keys:
        if not isinstance(row.get(key), list) or any(not isinstance(v, str) or not v.strip() for v in row[key]):
            raise ValueError(f"{key} 必须为字符串列表")


def validate_review(kind: str, value: dict, events: dict, constraints: dict) -> dict:
    if kind not in FIELDS or not isinstance(value, dict):
        raise ValueError("未知评审记录")
    row = copy.deepcopy(value)
    for key in ("revision_hash", "updated_at"):
        row.pop(key, None)
    if set(row) - FIELDS[kind]:
        raise ValueError("记录含未声明字段：" + ",".join(sorted(set(row) - FIELDS[kind])))
    if row.get("schema") != kind + "-v1":
        raise ValueError("评审格式版本不兼容")
    if kind == "feedback":
        _text(row, ["id", "subject_kind", "subject_id", "subject_revision", "baseline", "owner", "next_action", "recorded_at"])
        if row["subject_kind"] not in {"event", "risk"} or row.get("applicability") not in {"适用", "不适用", "未知"}:
            raise ValueError("反馈对象或适用性不合法")
        if not isinstance(row.get("executed"), bool) or not isinstance(row.get("action_clear"), bool):
            raise ValueError("反馈执行/清晰度必须为布尔值")
        if not parse_date(row["recorded_at"]):
            raise ValueError("反馈记录日期无效")
        subject = events.get(row["subject_id"]) if row["subject_kind"] == "event" else constraints.get(row["subject_id"])
        if not subject:
            raise ValueError("反馈对象不存在")
        revision = subject.record_hash() if isinstance(subject, Event) else subject["revision_hash"]
        if row["subject_revision"] != revision:
            raise ValueError("新反馈需引用当前对象修订；旧反馈原样保留")
        if row["executed"]:
            _text(row, ["result"])
        return row

    _text(row, ["claim_key", "title", "mechanism", "review_note"])
    refs = row.get("event_refs")
    if not isinstance(refs, list) or not refs:
        raise ValueError("必须引用事件及事实修订")
    linked = {}
    for ref in refs:
        event = events.get(ref.get("event_id"))
        if not event or ref.get("fact_hash") != event.fact_hash():
            raise ValueError("事件引用不存在或已过期")
        linked[event.event_id] = event
    bases = row.get("basis")
    if not isinstance(bases, list) or not bases:
        raise ValueError("必须有原文依据")
    covered = set()
    for basis in bases:
        _text(basis, ["event_id", "url", "quote"])
        event = linked.get(basis["event_id"])
        if not event:
            raise ValueError("依据不属于引用事件")
        excerpts = ([event.evidence] if basis["url"] == event.source_url else []) + [str(r.get("evidence") or r.get("excerpt") or "") for r in event.source_references if r.get("url") == basis["url"]]
        if len(basis["quote"].strip()) < 20 or not any(basis["quote"] in e for e in excerpts):
            raise ValueError("依据必须是事件已保存原文中的可回查引文（至少20字符）")
        covered.add(event.event_id)
    if covered != set(linked):
        raise ValueError("每个引用事件均须有原文依据")
    if kind == "constraint":
        _text(row, ["before", "after", "status"])
        _lists(row, ["products", "components", "workflows", "conditions", "exclusions"])
        if row["status"] not in {"active", "unknown", "retired"}:
            raise ValueError("约束状态无效")
        if row.get("effective_at") and not parse_date(row["effective_at"]):
            raise ValueError("生效日期无效，未知时留空")
    else:
        _text(row, ["status", "coexistence", "coexistence_basis", "first_action"])
        _lists(row, ["missing_inputs", "steps", "record"])
        if len(linked) < 2 or row["coexistence"] not in {"compatible", "unknown", "disjoint"}:
            raise ValueError("组合风险必须引用至少两个事件并说明共同生效条件")
        if row["status"] not in {"hypothesis", "supported", "dismissed", "closed"}:
            raise ValueError("风险状态无效，不允许声明内部已受影响")
        if row["coexistence"] == "disjoint" and row["status"] != "dismissed":
            raise ValueError("明确不相交的组合必须标记为排除")
        if row["coexistence"] == "unknown" and row["status"] == "supported":
            raise ValueError("共同生效条件未知不能标记支持")
        if not row["steps"] or not row["record"] or not isinstance(row.get("decisions"), list) or not row["decisions"]:
            raise ValueError("风险需具体操作、记录和结果处理")
        for decision in row["decisions"]:
            _text(decision, ["when", "then"])
        for ref in row.get("constraint_refs", []):
            constraint = constraints.get(ref.get("id"))
            if not constraint or ref.get("revision_hash") != constraint["revision_hash"]:
                raise ValueError("约束引用不存在或已过期")
            if not {r["event_id"] for r in constraint["event_refs"]}.issubset(linked):
                raise ValueError("风险依据缺少所引用约束的原始事件")
            if constraint["status"] == "retired" and row["status"] not in {"dismissed", "closed"}:
                raise ValueError("约束已撤销，应重新评审组合")
    identity = kind + ":" + stable_hash([sorted(linked), row["claim_key"]])[:24]
    if row.get("id") and row["id"] != identity:
        raise ValueError("标识应由事件身份和稳定 claim_key 生成，不随措辞修订")
    row["id"] = identity
    return row


def build_context(store, current, *, budget=None, risk_budget=None) -> dict:
    policy = json.loads((Path(__file__).resolve().parents[2] / "config/continuity.json").read_text())
    budget = policy["candidate_budget"] if budget is None else budget
    risk_budget = policy["risk_digest_budget"] if risk_budget is None else risk_budget
    if isinstance(risk_budget, bool) or not isinstance(risk_budget, int) or risk_budget < 0:
        raise ValueError("跨期摘要预算必须是非负整数")
    if isinstance(budget, bool) or not isinstance(budget, int) or budget < 1:
        raise ValueError("关联检索预算必须大于0")
    events = {e["event_id"]: Event(**e) for e in store.list_events()}
    constraints = {r["id"]: r for r in store.records("constraint")}
    risks = store.records("risk")
    candidates = dict(store.metadata("continuity-candidates", {}))
    known_pairs = {(ref["id"], tuple(sorted(r["event_id"] for r in risk["event_refs"]))) for risk in risks for ref in risk.get("constraint_refs", [])}
    for event in current:
        for c in constraints.values():
            source_ids = {r["event_id"] for r in c["event_refs"]}
            if c["status"] == "retired" or event.event_id in source_ids:
                continue
            components = set(event.components) & set(c["components"])
            workflows = set(event.affected_workflows) & set(c["workflows"])
            if not components and not workflows:
                continue
            pair = tuple(sorted(source_ids | {event.event_id}))
            if (c["id"], pair) in known_pairs:
                continue
            key = stable_hash([event.event_id, c["id"]])
            candidates[key] = {"event_id": event.event_id, "constraint_id": c["id"],
                               "title": event.title, "historical_title": c["title"],
                               "shared_components": sorted(components), "shared_workflows": sorted(workflows),
                               "state": "待评审；共享维度不是组合风险证明"}
    pending = store.metadata("pending-semantic-review", {})
    for row in list(constraints.values()) + risks:
        gaps = [pending[kind][row["id"]] for kind in ("constraint", "risk") if row["id"] in pending.get(kind, {})]
        for ref in row["event_refs"]:
            event = events.get(ref["event_id"])
            if not event or event.fact_hash() != ref["fact_hash"]:
                gaps.append("来源事实修订已变化：" + ref["event_id"])
        for ref in row.get("constraint_refs", []):
            c = constraints.get(ref["id"])
            if not c or c["revision_hash"] != ref["revision_hash"] or c["status"] == "retired":
                gaps.append("依赖约束已变化：" + ref["id"])
        row["needs_review"], row["review_gaps"] = bool(gaps), gaps
    candidates = {key: row for key, row in candidates.items()
                  if row["constraint_id"] in constraints and row["event_id"] in events
                  and constraints[row["constraint_id"]]["status"] != "retired"
                  and (row["constraint_id"], tuple(sorted({row["event_id"]} | {r["event_id"] for r in constraints[row["constraint_id"]]["event_refs"]}))) not in known_pairs}
    store.set_metadata("continuity-candidates", candidates)
    rows = sorted(candidates.values(), key=lambda r: (r["constraint_id"], r["event_id"]))
    previous = store.metadata("continuity-report-state", {})
    changes = []
    state = {}
    for risk in risks:
        history = store.record_history("risk", risk["id"])
        risk["history"] = history
        prior = history[-2] if len(history) > 1 else {}
        fields = sorted(k for k in FIELDS["risk"] - {"id", "schema", "claim_key"} if prior.get(k) != risk.get(k))
        risk["changes"] = [{"field": k, "before": prior.get(k), "after": risk.get(k),
                            "category": "editorial" if k in {"title", "review_note", "suggested_role"} else "needs-semantic-review"} for k in fields]
        risk["previous_conclusion"] = {k: prior.get(k) for k in ("status", "mechanism", "coexistence_basis", "first_action")} if prior else None
        semantic = stable_hash({k: risk.get(k) for k in ("revision_hash", "needs_review", "review_gaps")})
        state[risk["id"]] = semantic
        if previous.get(risk["id"]) != semantic:
            changes.append(risk["id"])
    feedback = store.records("feedback")
    for item in feedback:
        subject = events.get(item["subject_id"]) if item["subject_kind"] == "event" else next((r for r in risks if r["id"] == item["subject_id"]), None)
        current_revision = subject.record_hash() if isinstance(subject, Event) else (subject or {}).get("revision_hash")
        item["needs_review"] = current_revision != item["subject_revision"] or bool(isinstance(subject, dict) and subject.get("needs_review"))
    gaps = ([] if constraints else ["尚无经审阅的外部约束，跨期关联覆盖不足"])
    if rows:
        gaps.append(f"有 {len(rows)} 条跨期关联候选尚未完成评审")
    stale = sum(bool(r.get("needs_review")) for r in list(constraints.values()) + risks)
    if stale:
        gaps.append(f"有 {stale} 条约束/风险因依据或评估变化需要重审")
    if len(rows) > budget:
        gaps.append(f"关联候选 {len(rows)} 条，当前预算 {budget}，剩余 {len(rows)-budget} 条待评审")
    ordered = sorted((r for r in risks if r["status"] not in {"closed", "dismissed"}),
                     key=lambda r: (not r["needs_review"], r["id"] not in changes, r["status"] != "supported", r["id"]))
    display = [r["id"] for r in ordered[:risk_budget]]
    overflow = [r["id"] for r in ordered[risk_budget:]]
    return {"schema": "continuity-v1", "display_risk_ids": display, "risk_overflow_ids": overflow, "risk_digest_budget": risk_budget, "constraints": list(constraints.values()), "risks": risks,
            "changed_risk_ids": changes, "candidate_total": len(rows), "candidates": rows[:budget],
            "candidate_overflow": max(0, len(rows)-budget), "coverage_gaps": gaps,
            "feedback": feedback, "state": state,
            "internal_applicability": "未知", "product_tests_executed": False}
