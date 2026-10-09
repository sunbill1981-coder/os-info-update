"""Reviewed editorial themes, never automatic same-KB risk aggregation."""
from __future__ import annotations

import copy
import json
from datetime import datetime, date
from pathlib import Path
from urllib.parse import urlsplit

from .model import stable_hash

FIELDS = {"schema", "id", "claim_key", "title", "risk", "mechanism", "relation",
          "grouping_note", "event_refs", "basis", "scope", "queue", "critical",
          "why_now", "first_action", "owner", "steps", "record", "decisions",
          "evidence_state", "source_verified", "review_note", "reviewed_at",
          "timeline", "subitems", "closed"}
QUEUES = {"action": "需要行动", "verify": "需要验证", "watch": "持续关注", "evidence": "待补外部证据"}
POLICY = Path(__file__).resolve().parents[2] / "config/engineer-report.json"


def policy():
    value = json.loads(POLICY.read_text())
    if isinstance(value["display_budget"], bool) or not isinstance(value["display_budget"], int) or value["display_budget"] < 1:
        raise ValueError("主题阅读预算必须为正整数")
    if set(value["queue_order"]) != set(QUEUES) or len(value["queue_order"]) != len(QUEUES):
        raise ValueError("主题队列配置无效")
    return value


def basis_check(rows, events, allowed):
    if not isinstance(rows, list) or not rows:
        raise ValueError("主题或时间节点必须提供原文依据")
    covered = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"event_id", "url", "quote"}:
            raise ValueError("依据需 event_id/url/quote")
        event = events.get(row["event_id"])
        if not event or event.event_id not in allowed:
            raise ValueError("依据事件不属于主题")
        url = urlsplit(row["url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise ValueError("主题依据须为公开HTTPS地址")
        excerpts = ([event.evidence] if row["url"] == event.source_url else []) + [
            str(r.get("evidence") or r.get("excerpt") or "") for r in event.source_references if r.get("url") == row["url"]]
        excerpts += [str(r.get("evidence") or "") for r in event.update_details if r.get("source_url") == row["url"]]
        excerpts += [str(q) for r in event.update_details if r.get("source_url") == row["url"] for q in r.get("exclusions_evidence", [])]
        quote = row["quote"]
        if not isinstance(quote, str) or len(quote.strip()) < 20 or not any(quote in text for text in excerpts):
            raise ValueError("主题依据须为所引用网页已保存原文的连续摘录")
        covered.add(event.event_id)
    return covered


def valid_day(value):
    try:
        return isinstance(value, str) and date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def validate_theme(value, events):
    row = copy.deepcopy(value)
    for key in ("revision_hash", "updated_at", "needs_review", "review_gaps", "history"):
        row.pop(key, None)
    if set(row) - FIELDS or row.get("schema") != "theme-v1":
        raise ValueError("主题格式或字段无效")
    for key in ("claim_key", "title", "risk", "mechanism", "grouping_note", "why_now",
                "first_action", "owner", "evidence_state", "review_note", "reviewed_at"):
        if not isinstance(row.get(key), str) or not row[key].strip():
            raise ValueError("主题缺少 " + key)
    for key in ("critical", "source_verified", "closed"):
        if not isinstance(row.get(key), bool):
            raise ValueError(key + " 须为布尔值")
    try:
        if datetime.fromisoformat(row["reviewed_at"].replace("Z", "+00:00")).tzinfo is None:
            raise ValueError()
    except (TypeError, ValueError):
        raise ValueError("评审时间须为带时区的真实时间")
    if row.get("relation") not in {"same-risk", "verification-batch"} or row.get("queue") not in QUEUES:
        raise ValueError("主题关系或队列无效")
    for key in ("scope", "steps", "record"):
        if not isinstance(row.get(key), list) or not row[key] or any(not isinstance(s, str) or not s.strip() for s in row[key]):
            raise ValueError(key + " 须为非空文字列表")
    if row["queue"] in {"action", "verify"} and not row["source_verified"]:
        raise ValueError("外部范围未核验的主题不能交付工程师行动或验证队列")
    refs = row.get("event_refs")
    if not isinstance(refs, list) or not refs:
        raise ValueError("主题须引用事件及事实修订")
    linked = set()
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {"event_id", "fact_hash"}:
            raise ValueError("事件引用字段无效")
        event = events.get(ref["event_id"])
        if not event or ref["fact_hash"] != event.fact_hash() or event.event_id in linked:
            raise ValueError("事件引用重复、缺失或修订过期")
        linked.add(event.event_id)
    if basis_check(row.get("basis"), events, linked) != linked:
        raise ValueError("主题每个事件须有原文依据")
    decisions = row.get("decisions")
    if not isinstance(decisions, list) or not decisions or any(
            not isinstance(d, dict) or set(d) != {"when", "then"} or not all(isinstance(v, str) and v.strip() for v in d.values()) for d in decisions):
        raise ValueError("需明确结果处理 when/then")
    row.setdefault("subitems", [])
    row.setdefault("timeline", [])
    subitems = row["subitems"]
    if not isinstance(subitems, list):
        raise ValueError("子项须为列表")
    subrefs = set()
    for sub in subitems:
        if not isinstance(sub, dict) or set(sub) != {"event_ids", "scope", "action", "expected"}:
            raise ValueError("子项需 event_ids/scope/action/expected")
        if not isinstance(sub["event_ids"], list) or not sub["event_ids"] or not set(sub["event_ids"]).issubset(linked):
            raise ValueError("子项引用无效")
        if not all(isinstance(sub[k], str) and sub[k].strip() for k in ("scope", "action", "expected")):
            raise ValueError("子项必须保留适用条件、动作和独立结果")
        subrefs.update(sub["event_ids"])
    if row["relation"] == "verification-batch" and (subrefs != linked or any(len(s["event_ids"]) != 1 for s in subitems)):
        raise ValueError("验证批次必须为每个独立风险保留子项")
    nodes = row.get("timeline", [])
    if not isinstance(nodes, list):
        raise ValueError("时间线须为列表")
    for node in nodes:
        if not isinstance(node, dict) or set(node) - {"kind", "date", "end", "note", "basis", "scale_basis"}:
            raise ValueError("时间节点字段无效")
        if node.get("kind") not in policy()["timeline_labels"] or not isinstance(node.get("note"), str) or not node["note"].strip():
            raise ValueError("时间类型或说明无效")
        day = node.get("date")
        if day is not None:
            if not valid_day(day):
                raise ValueError("已知日期需YYYY-MM-DD；精度不足使用有依据的起止区间")
            if node.get("end") and (not valid_day(node["end"]) or node["end"] < day):
                raise ValueError("时间区间无效")
            basis_check(node.get("basis"), events, linked)
            if node["kind"] == "outbreak" and (node.get("scale_basis") != "explicit-source" or not any(events[b["event_id"]].authoritative_evidence for b in node["basis"])):
                raise ValueError("大规模爆发须有权威来源明确规模说明；多帖或首次确认不能替代")
        elif node.get("basis") or node.get("end"):
            raise ValueError("未知节点不能带暗示已确定日期的依据或区间")
    identity = "theme:" + stable_hash(row["claim_key"])[:24]
    if row.get("id") and row["id"] != identity:
        raise ValueError("主题标识应基于稳定claim_key，不随成员或措辞改变")
    row["id"] = identity
    return row


def build_themes(records, events, *, histories=None, pending=None):
    result = []
    for value in records:
        row = copy.deepcopy(value)
        gaps = ["历史重评后需复核主题"] if row["id"] in (pending or {}) else []
        for ref in row["event_refs"]:
            if ref["event_id"] not in events or events[ref["event_id"]].fact_hash() != ref["fact_hash"]:
                gaps.append("依据缺失或已修订：" + ref["event_id"])
        row["needs_review"], row["review_gaps"] = bool(gaps), gaps
        if gaps:
            row["queue"] = "evidence"
        row["history"] = (histories or {}).get(row["id"], [])
        result.append(row)
    order = policy()["queue_order"]
    return sorted(result, key=lambda r: (not r["critical"], order.index(r["queue"]), r["id"]))


def store_themes(store, events):
    records = store.records("theme")
    return build_themes(records, {e.event_id: e for e in events},
                        histories={r["id"]: store.record_history("theme", r["id"]) for r in records},
                        pending=store.metadata("pending-semantic-review", {}).get("theme", {}))
