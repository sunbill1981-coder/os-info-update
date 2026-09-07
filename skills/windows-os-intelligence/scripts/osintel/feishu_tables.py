from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Mapping, Sequence

from .feishu import FeishuClient, FeishuConfigurationError
from .model import Event
from .report import ROLE_ZH, display_action, display_product, display_values


RUN_MODE_ZH = {"backfill": "历史回填", "rolling": "滚动窗口", "incremental": "增量采集"}
RUN_STATUS_ZH = {"running": "运行中", "success": "成功", "partial": "部分成功", "failed": "失败"}
CHANGE_TYPE_ZH = {"initial": "初始建立", "fact_change": "来源事实变化", "assessment_change": "仅评估变化"}
CHANGED_FIELD_ZH = {
    "status": "当前状态", "products": "产品范围", "editions": "版本类型",
    "builds": "构建号", "identifiers": "关联标识", "evidence": "证据摘要",
    "published_at": "发布时间", "updated_at": "更新时间", "source_url": "原文链接",
}


def _hash_fields(fields: Mapping[str, Any]) -> str:
    encoded = json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _same_fields(current: Mapping[str, Any], wanted: Mapping[str, Any]) -> bool:
    return all(current.get(name) == value for name, value in wanted.items())


def sync_records(
    client: FeishuClient,
    table_id: str,
    key_field: str,
    records: Sequence[Mapping[str, Any]],
    dry_run: bool = False,
) -> Dict[str, int]:
    if not table_id:
        return {"待新增": 0, "待更新": 0, "未变化": 0}
    if any(not str(record.get(key_field, "")).strip() for record in records):
        raise FeishuConfigurationError(f"飞书辅助表数据缺少主键字段：{key_field}")
    if dry_run:
        return {"待新增": len(records), "待更新": 0, "未变化": 0}

    missing = client.missing_fields(list(records[0]) if records else [key_field], table_id)
    if missing:
        raise FeishuConfigurationError(f"飞书辅助表缺少字段：{'、'.join(missing)}")
    existing = client.list_table_records(table_id)
    by_key: Dict[str, Mapping[str, Any]] = {}
    for record in existing:
        fields = record.get("fields", {}) or {}
        key = str(fields.get(key_field, "")).strip()
        if not key:
            continue
        if key in by_key:
            raise FeishuConfigurationError(f"飞书辅助表存在重复主键：{key}")
        by_key[key] = record

    creates: List[Dict[str, Any]] = []
    updates = []
    unchanged = 0
    for wanted in records:
        fields = dict(wanted)
        key = str(fields[key_field])
        current = by_key.get(key)
        if current is None:
            creates.append(fields)
        elif _same_fields(current.get("fields", {}) or {}, fields):
            unchanged += 1
        else:
            updates.append((str(current.get("record_id", "")), fields))
    for index in range(0, len(creates), client.settings.batch_size):
        client.batch_create(creates[index:index + client.settings.batch_size], table_id)
    for index in range(0, len(updates), client.settings.batch_size):
        client.batch_update(updates[index:index + client.settings.batch_size], table_id)
    return {"待新增": len(creates), "待更新": len(updates), "未变化": unchanged}


def seed_records(
    client: FeishuClient,
    table_id: str,
    key_field: str,
    records: Sequence[Mapping[str, Any]],
    dry_run: bool = False,
) -> Dict[str, int]:
    """只初始化不存在的记录，永不覆盖人工编辑。"""
    if not table_id:
        return {"待新增": 0, "待更新": 0, "未变化": 0}
    if any(not str(record.get(key_field, "")).strip() for record in records):
        raise FeishuConfigurationError(f"飞书人工闭环表数据缺少主键字段：{key_field}")
    if dry_run:
        return {"待新增": len(records), "待更新": 0, "未变化": 0}
    missing = client.missing_fields(list(records[0]) if records else [key_field], table_id)
    if missing:
        raise FeishuConfigurationError(f"飞书人工闭环表缺少字段：{'、'.join(missing)}")
    existing = client.list_table_records(table_id)
    existing_keys = set()
    for record in existing:
        key = str((record.get("fields", {}) or {}).get(key_field, "")).strip()
        if not key:
            continue
        if key in existing_keys:
            raise FeishuConfigurationError(f"飞书人工闭环表存在重复主键：{key}")
        existing_keys.add(key)
    creates = [dict(record) for record in records if str(record[key_field]) not in existing_keys]
    for index in range(0, len(creates), client.settings.batch_size):
        client.batch_create(creates[index:index + client.settings.batch_size], table_id)
    return {"待新增": len(creates), "待更新": 0, "未变化": len(records) - len(creates)}


def load_evidence(db_path: Path) -> List[Dict[str, Any]]:
    with sqlite3.connect(str(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT e.*,v.payload_json FROM evidence e
            LEFT JOIN events v ON v.event_id=e.event_id ORDER BY e.collected_at DESC
            """
        ).fetchall()
    result = []
    for row in rows:
        payload = json.loads(row["payload_json"] or "{}")
        fields = {
            "证据编号": row["evidence_id"], "事件编号": row["event_id"],
            "来源级别": row["source_tier"], "发布者": row["publisher"],
            "原文链接": row["source_url"], "证据原文": row["excerpt"],
            "发布时间": payload.get("published_at") or "",
            "更新时间": payload.get("updated_at") or "",
            "采集时间": row["collected_at"],
        }
        fields["内容指纹"] = _hash_fields(fields)
        result.append(fields)
    return result


def load_runs(db_path: Path, limit: int = 100) -> List[Dict[str, Any]]:
    with sqlite3.connect(str(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM runs ORDER BY run_id DESC LIMIT ?", (limit,)
        ).fetchall()
    result = []
    for row in rows:
        stats = json.loads(row["stats_json"] or "{}")
        result.append({
            "运行编号": str(row["run_id"]), "采集模式": RUN_MODE_ZH.get(row["mode"], row["mode"]),
            "开始日期": row["window_start"], "结束日期": row["window_end"],
            "开始时间": row["started_at"], "结束时间": row["finished_at"] or "",
            "运行状态": RUN_STATUS_ZH.get(row["status"], row["status"]), "新增数": int(stats.get("new", 0)),
            "变化数": int(stats.get("changed", 0)),
            "失败来源数": int(stats.get("sources_failed", 0)),
            "异常摘要": row["error"] or "",
        })
    return result


def load_changes(db_path: Path, limit: int = 1000) -> List[Dict[str, Any]]:
    with sqlite3.connect(str(db_path)) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM event_changes ORDER BY change_id DESC LIMIT ?", (limit,)
        ).fetchall()
    result = []
    for row in rows:
        changed_fields = "、".join(
            CHANGED_FIELD_ZH.get(value, value)
            for value in json.loads(row["changed_fields_json"] or "[]")
        )
        result.append({
            "变更编号": str(row["change_id"]), "事件编号": row["event_id"],
            "变更时间": row["changed_at"],
            "变更类型": CHANGE_TYPE_ZH.get(row["change_type"], row["change_type"]),
            "变更前指纹": row["prior_hash"] or "", "变更后指纹": row["new_hash"],
            "变更摘要": changed_fields or "初始建立",
        })
    return result


def _profile_identity(payload: Mapping[str, Any]) -> tuple[str, str]:
    name = str(payload.get("profile_name") or "未配置环境")
    return "profile:" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:20], name


def load_profile(environment_path: Path) -> List[Dict[str, Any]]:
    payload = json.loads(environment_path.read_text(encoding="utf-8"))
    profile_id, name = _profile_identity(payload)
    products = list(payload.get("products", []) or [])
    roles = list(payload.get("roles", []) or [])
    criticality = max((int(value) for value in (payload.get("workflow_criticality", {}) or {}).values()), default=0)
    return [{
        "环境编号": profile_id, "环境名称": name, "产品家族": "Windows",
        "版本": "、".join(display_product(str(value)) for value in products), "版本类型": "未单独指定",
        "构建号": "", "安装方式": "未单独指定", "体系结构": "未单独指定",
        "云桌面角色": display_values([str(value) for value in roles], ROLE_ZH), "重要性": criticality,
        "是否启用": bool(products or roles),
    }]


def _load_event_payloads(db_path: Path) -> List[Dict[str, Any]]:
    with sqlite3.connect(str(db_path)) as connection:
        rows = connection.execute("SELECT payload_json FROM events ORDER BY event_id").fetchall()
    return [json.loads(row[0]) for row in rows]


def load_applicability(db_path: Path, environment_path: Path) -> List[Dict[str, Any]]:
    environment = json.loads(environment_path.read_text(encoding="utf-8"))
    profile_id, _ = _profile_identity(environment)
    configured = bool(environment.get("products") or environment.get("roles"))
    result = []
    for payload in _load_event_payloads(db_path):
        event = Event(**payload).normalized()
        decision = "建议优先核验" if configured and event.environment_relevance >= 70 else "待人工判断"
        reason = (
            f"系统初筛的环境相关度为 {event.environment_relevance}；"
            "需结合真实版本、组件、镜像与业务流程人工确认。"
        )
        digest = hashlib.sha256(f"{event.event_id}|{profile_id}".encode("utf-8")).hexdigest()[:24]
        result.append({
            "判断编号": f"applicability:{digest}", "事件编号": event.event_id,
            "环境编号": profile_id, "适用性": decision, "判断理由": reason,
            "判断方式": "系统初筛，待人工确认", "负责人": "",
            "最后更新": event.updated_at or event.published_at or "",
        })
    return result


def load_actions(db_path: Path) -> List[Dict[str, Any]]:
    result = []
    for payload in _load_event_payloads(db_path):
        event = Event(**payload).normalized()
        if event.alert_level not in {"正式告警", "调查预警"}:
            continue
        digest = hashlib.sha256(event.event_id.encode("utf-8")).hexdigest()[:24]
        result.append({
            "处置编号": f"action:{digest}", "事件编号": event.event_id,
            "处置类型": "专项验证", "负责人": "", "截止时间": "",
            "处置状态": "待分派", "测试环境": "", "测试结论": "",
            "上线决策": "待决定", "备注": display_action(event),
        })
    return result


def publish_supporting_tables(
    client: FeishuClient, db_path: Path, environment_path: Path, dry_run: bool = False,
) -> Dict[str, Dict[str, int]]:
    machine_tables = (
        ("证据来源", client.settings.evidence_table_id, "证据编号", load_evidence(db_path)),
        ("Windows 环境画像", client.settings.profiles_table_id, "环境编号", load_profile(environment_path)),
        ("变更历史", client.settings.changes_table_id, "变更编号", load_changes(db_path)),
        ("采集任务", client.settings.runs_table_id, "运行编号", load_runs(db_path)),
    )
    summary = {
        name: sync_records(client, table_id, key, records, dry_run=dry_run)
        for name, table_id, key, records in machine_tables if table_id
    }
    human_tables = (
        ("适用性判断", client.settings.applicability_table_id, "判断编号", load_applicability(db_path, environment_path)),
        ("验证与处置", client.settings.actions_table_id, "处置编号", load_actions(db_path)),
    )
    summary.update({
        name: seed_records(client, table_id, key, records, dry_run=dry_run)
        for name, table_id, key, records in human_tables if table_id
    })
    return summary
