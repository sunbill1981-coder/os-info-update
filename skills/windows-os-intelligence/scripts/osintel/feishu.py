from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .report import display_action, display_summary, display_title


class FeishuConfigurationError(ValueError):
    """飞书配置不完整或不安全。"""


class FeishuApiError(RuntimeError):
    """飞书开放接口返回错误。"""


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _env_value(config: Mapping[str, Any], key: str, environ: Mapping[str, str]) -> str:
    env_name = str(config.get(key, "")).strip()
    return environ.get(env_name, "").strip() if env_name else ""


def load_env_file(path: Path, environ: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    values = dict(environ if environ is not None else os.environ)
    if not path.exists():
        return values
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            raise FeishuConfigurationError(f"环境文件第 {line_number} 行缺少等号。")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if key and key not in values:
            values[key] = value
    return values


def write_env_file(path: Path, updates: Mapping[str, str]) -> None:
    for key, value in updates.items():
        if not key or "\n" in key or "\r" in key or "\n" in value or "\r" in value:
            raise FeishuConfigurationError("环境变量名和值不能包含换行符。")
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = dict(updates)
    output: List[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        candidate = line[7:].strip() if line.startswith("export ") else line
        if candidate and not candidate.startswith("#") and "=" in candidate:
            key = candidate.split("=", 1)[0].strip()
            if key in remaining:
                output.append(f"{key}={remaining.pop(key)}")
                continue
        output.append(raw_line)
    if output and output[-1].strip():
        output.append("")
    output.extend(f"{key}={value}" for key, value in remaining.items())
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(str(temporary), str(path))
    os.chmod(path, 0o600)


def load_events(path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not path.exists():
        raise FeishuConfigurationError(f"找不到规范化情报文件：{path}")
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise FeishuConfigurationError(f"第 {line_number} 行不是有效 JSON：{exc.msg}") from exc
            if not isinstance(payload, dict):
                raise FeishuConfigurationError(f"第 {line_number} 行必须是 JSON 对象。")
            events.append(payload)
    return events


@dataclass
class FeishuSettings:
    enabled: bool
    api_base: str
    app_id: str
    app_secret: str
    base_token: str
    events_table_id: str
    alert_chat_id: str
    send_alerts: bool
    alert_levels: Tuple[str, ...]
    max_alerts_per_run: int
    batch_size: int
    timeout_seconds: int

    @classmethod
    def load(
        cls,
        path: Path,
        environ: Optional[Mapping[str, str]] = None,
        require_remote: bool = True,
    ) -> "FeishuSettings":
        environment = environ if environ is not None else os.environ
        payload = json.loads(path.read_text(encoding="utf-8"))
        credentials = payload.get("credentials", {})
        resources = payload.get("resources", {})
        publish = payload.get("publish", {})
        settings = cls(
            enabled=bool(payload.get("enabled", False)),
            api_base=str(payload.get("api_base", "https://open.feishu.cn/open-apis")).rstrip("/"),
            app_id=_env_value(credentials, "app_id_env", environment),
            app_secret=_env_value(credentials, "app_secret_env", environment),
            base_token=_env_value(resources, "base_token_env", environment),
            events_table_id=_env_value(resources, "events_table_id_env", environment),
            alert_chat_id=_env_value(resources, "alert_chat_id_env", environment),
            send_alerts=bool(publish.get("send_alerts", False)),
            alert_levels=tuple(str(value) for value in publish.get("alert_levels", ["正式告警", "调查预警"])),
            max_alerts_per_run=max(1, int(publish.get("max_alerts_per_run", 20))),
            batch_size=max(1, min(200, int(publish.get("batch_size", 200)))),
            timeout_seconds=max(5, int(payload.get("timeout_seconds", 30))),
        )
        if require_remote:
            if not settings.enabled:
                raise FeishuConfigurationError("飞书发布尚未启用；请在本地配置中设置 enabled=true。")
            missing = []
            for label, value in (
                ("应用编号", settings.app_id), ("应用密钥", settings.app_secret),
                ("多维表格标识", settings.base_token), ("情报事件表标识", settings.events_table_id),
            ):
                if not value:
                    missing.append(label)
            if settings.send_alerts and not settings.alert_chat_id:
                missing.append("告警群标识")
            if missing:
                raise FeishuConfigurationError("缺少运行时配置：" + "、".join(missing))
        return settings


class FeishuClient:
    def __init__(self, settings: FeishuSettings):
        self.settings = settings
        self._token = ""
        self._token_expires_at = 0.0

    def _safe_text(self, value: Any) -> str:
        text = str(value)
        sensitive = (
            self.settings.app_id, self.settings.app_secret, self.settings.base_token,
            self.settings.events_table_id, self.settings.alert_chat_id, self._token,
        )
        for item in sensitive:
            if item:
                text = text.replace(item, "***")
        return text

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Mapping[str, Any]] = None,
        query: Optional[Mapping[str, Any]] = None,
        authenticated: bool = True,
    ) -> Dict[str, Any]:
        url = f"{self.settings.api_base}/{path.lstrip('/')}"
        if query:
            url += "?" + urlencode({key: value for key, value in query.items() if value is not None})
        headers = {"Content-Type": "application/json; charset=utf-8"}
        if authenticated:
            headers["Authorization"] = f"Bearer {self.access_token()}"
        data = json.dumps(body, ensure_ascii=False).encode("utf-8") if body is not None else None
        request = Request(url, data=data, headers=headers, method=method)
        try:
            with urlopen(request, timeout=self.settings.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = self._safe_text(exc.read().decode("utf-8", errors="replace")[:1000])
            raise FeishuApiError(f"飞书接口 HTTP {exc.code}：{detail}") from exc
        except URLError as exc:
            raise FeishuApiError(f"无法连接飞书开放接口：{self._safe_text(exc.reason)}") from exc
        if int(payload.get("code", 0)) != 0:
            code = payload.get("code", "未知")
            message = self._safe_text(str(payload.get("msg", "未提供错误信息"))[:500])
            raise FeishuApiError(f"飞书接口错误 {code}：{message}")
        return payload

    def access_token(self) -> str:
        if self._token and time.monotonic() < self._token_expires_at:
            return self._token
        payload = self._request(
            "POST",
            "auth/v3/tenant_access_token/internal",
            {"app_id": self.settings.app_id, "app_secret": self.settings.app_secret},
            authenticated=False,
        )
        token = str(payload.get("tenant_access_token", ""))
        if not token:
            raise FeishuApiError("飞书鉴权成功响应中没有 tenant_access_token。")
        expires = max(60, int(payload.get("expire", 7200)))
        self._token = token
        self._token_expires_at = time.monotonic() + expires - 60
        return token

    def list_event_records(self) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        offset = 0
        while True:
            payload = self._request(
                "GET",
                f"base/v3/bases/{self.settings.base_token}/tables/{self.settings.events_table_id}/records",
                query={"limit": 200, "offset": offset},
            )
            data = payload.get("data", {})
            page = data.get("records", data.get("items", [])) or []
            for item in page:
                if "fields" in item:
                    records.append(dict(item))
                else:
                    fields = {
                        key: value for key, value in item.items()
                        if key not in {"record_id", "created_at", "updated_at", "created_by", "updated_by"}
                    }
                    records.append({"record_id": item.get("record_id", ""), "fields": fields})
            if not data.get("has_more"):
                break
            if not page:
                raise FeishuApiError("飞书记录分页显示仍有数据但本页为空，已停止以避免无限循环。")
            offset = int(data.get("next_offset", offset + len(page)))
        return records

    def list_fields(self) -> List[Dict[str, Any]]:
        fields: List[Dict[str, Any]] = []
        offset = 0
        while True:
            payload = self._request(
                "GET",
                f"base/v3/bases/{self.settings.base_token}/tables/{self.settings.events_table_id}/fields",
                query={"limit": 100, "offset": offset},
            )
            data = payload.get("data", {})
            page = data.get("fields", data.get("items", [])) or []
            fields.extend(page)
            if not data.get("has_more"):
                break
            if not page:
                raise FeishuApiError("飞书字段分页显示仍有数据但本页为空，已停止以避免无限循环。")
            offset = int(data.get("next_offset", offset + len(page)))
        return fields

    def missing_fields(self, required_fields: Sequence[str]) -> List[str]:
        fields = self.list_fields()
        actual = {str(field.get("field_name", field.get("name", ""))) for field in fields}
        return [name for name in required_fields if name not in actual]

    def validate_event_table(self, required_fields: Sequence[str]) -> None:
        missing = self.missing_fields(required_fields)
        if missing:
            raise FeishuConfigurationError("飞书情报事件表缺少字段：" + "、".join(missing))

    def create_fields(self, definitions: Sequence[Mapping[str, Any]]) -> List[str]:
        created: List[str] = []
        for definition in definitions:
            name = str(definition.get("name", "")).strip()
            if not name or not definition.get("type"):
                raise FeishuConfigurationError("字段定义必须包含 name 和 type。")
            self._request(
                "POST",
                f"base/v3/bases/{self.settings.base_token}/tables/{self.settings.events_table_id}/fields",
                dict(definition),
            )
            created.append(name)
        return created

    def batch_create(self, fields: Sequence[Dict[str, Any]]) -> List[str]:
        payload = self._request(
            "POST",
            f"base/v3/bases/{self.settings.base_token}/tables/{self.settings.events_table_id}/records/batch_create",
            {"create_records": list(fields)},
        )
        data = payload.get("data", {})
        record_ids = [str(value) for value in (data.get("record_id_list", []) or [])]
        if not record_ids:
            records = data.get("records", []) or []
            record_ids = [str(item.get("record_id", "")) for item in records]
        if len(record_ids) != len(fields) or any(not value for value in record_ids):
            raise FeishuApiError("飞书批量新增的记录数与返回编号数不一致。")
        return record_ids

    def batch_update(self, records: Sequence[Tuple[str, Dict[str, Any]]]) -> None:
        self._request(
            "POST",
            f"base/v3/bases/{self.settings.base_token}/tables/{self.settings.events_table_id}/records/batch_update",
            {"update_records": {record_id: fields for record_id, fields in records}},
        )

    def send_text(self, chat_id: str, text: str, idempotency_key: str) -> str:
        payload = self._request(
            "POST",
            "im/v1/messages",
            {
                "receive_id": chat_id,
                "msg_type": "text",
                "content": json.dumps({"text": text}, ensure_ascii=False),
                "uuid": idempotency_key[:50],
            },
            query={"receive_id_type": "chat_id"},
        )
        return str(payload.get("data", {}).get("message_id", ""))


def _joined(values: Any) -> str:
    if not values:
        return ""
    if isinstance(values, (list, tuple, set)):
        return "、".join(str(value) for value in values)
    return str(values)


def _identifier_text(identifiers: Any) -> str:
    if not isinstance(identifiers, Mapping):
        return ""
    parts = []
    for key in sorted(identifiers):
        value = identifiers[key]
        parts.append(f"{key}={_joined(value)}")
    return "；".join(parts)


def event_fingerprint(event: Mapping[str, Any]) -> str:
    value = dict(event)
    value.pop("raw_hash", None)
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def alert_fingerprint(event: Mapping[str, Any]) -> str:
    value = f"{event.get('event_id', '')}|{event_fingerprint(event)}|{event.get('alert_level', '')}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def event_to_fields(event: Mapping[str, Any], synced_at: Optional[str] = None) -> Dict[str, Any]:
    # Import lazily to keep this mapper usable with plain dictionaries in tests.
    from .model import Event

    model = Event(**dict(event))
    return {
        "事件编号": model.event_id,
        "中文标题": display_title(model),
        "中文摘要": display_summary(model),
        "事件类型": model.event_type,
        "当前状态": model.status,
        "告警级别": model.alert_level,
        "技术风险": model.risk_score,
        "环境相关度": model.environment_relevance,
        "置信度": model.confidence,
        "处置优先级": model.action_priority,
        "产品范围": _joined(model.products),
        "版本类型": _joined(model.editions),
        "构建号": _joined(model.builds),
        "云桌面角色": _joined(model.roles),
        "关联组件": _joined(model.components),
        "变化类型": _joined(model.change_kinds),
        "前置条件": _joined(model.preconditions),
        "影响流程": _joined(model.affected_workflows),
        "可观察症状": _joined(model.symptoms),
        "来源标识": model.source_id,
        "来源级别": model.source_tier,
        "发布者": model.publisher,
        "发布时间": model.published_at or "",
        "更新时间": model.updated_at or "",
        "原文链接": model.source_url,
        "证据摘要": model.evidence,
        "建议动作": display_action(model),
        "关联标识": _identifier_text(model.identifiers),
        "关联键": _joined(model.correlation_keys),
        "内容指纹": event_fingerprint(event),
        "最近同步时间": synced_at or _utc_now(),
    }


def _chunks(values: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for index in range(0, len(values), size):
        yield values[index:index + size]


def _alert_text(event: Mapping[str, Any]) -> str:
    from .model import Event

    model = Event(**dict(event))
    products = _joined(model.products) or "未明确"
    roles = _joined(model.roles) or "未明确"
    return (
        f"【Windows {model.alert_level}】{display_title(model)}\n"
        f"产品：{products}\n"
        f"云桌面角色：{roles}\n"
        f"技术风险 {model.risk_score} · 环境相关度 {model.environment_relevance} · "
        f"置信度 {model.confidence} · 处置优先级 {model.action_priority}\n"
        f"{display_summary(model)}\n"
        f"建议：{display_action(model)}\n"
        f"证据：{model.source_url}"
    )


def build_publish_plan(
    events: Sequence[Mapping[str, Any]],
    existing_records: Sequence[Mapping[str, Any]],
    alert_levels: Sequence[str],
) -> Dict[str, Any]:
    existing_by_event: Dict[str, Dict[str, Any]] = {}
    for record in existing_records:
        fields = record.get("fields", {}) or {}
        event_id = str(fields.get("事件编号", "")).strip()
        if not event_id:
            continue
        if event_id in existing_by_event:
            raise FeishuConfigurationError(f"飞书情报事件表存在重复事件编号：{event_id}")
        existing_by_event[event_id] = dict(record)

    creates: List[Dict[str, Any]] = []
    updates: List[Dict[str, Any]] = []
    alerts: List[Dict[str, Any]] = []
    unchanged = 0
    seen = set()
    for raw_event in events:
        event = dict(raw_event)
        event_id = str(event.get("event_id", "")).strip()
        if not event_id:
            raise FeishuConfigurationError("待发布事件缺少 event_id。")
        if event_id in seen:
            raise FeishuConfigurationError(f"待发布数据存在重复事件编号：{event_id}")
        seen.add(event_id)
        fields = event_to_fields(event)
        fingerprint = str(fields["内容指纹"])
        current = existing_by_event.get(event_id)
        if current is None:
            creates.append({"event_id": event_id, "fields": fields, "event": event})
        else:
            current_fields = current.get("fields", {}) or {}
            if str(current_fields.get("内容指纹", "")) == fingerprint:
                unchanged += 1
            else:
                updates.append({
                    "event_id": event_id,
                    "record_id": str(current.get("record_id", "")),
                    "fields": fields,
                    "event": event,
                })
        if str(event.get("alert_level", "")) in alert_levels:
            wanted = alert_fingerprint(event)
            previous = "" if current is None else str((current.get("fields", {}) or {}).get("最近告警指纹", ""))
            if previous != wanted:
                alerts.append({"event_id": event_id, "fingerprint": wanted, "event": event})
    return {"creates": creates, "updates": updates, "alerts": alerts, "unchanged": unchanged}


def publish_events(
    client: FeishuClient,
    events: Sequence[Mapping[str, Any]],
    dry_run: bool = False,
    send_alerts: Optional[bool] = None,
    allow_bulk_alerts: bool = False,
) -> Dict[str, Any]:
    should_alert = client.settings.send_alerts if send_alerts is None else send_alerts
    if should_alert and not dry_run and not client.settings.alert_chat_id:
        raise FeishuConfigurationError("已要求发送告警，但未配置告警群标识。")
    if dry_run:
        existing = []
    else:
        example_fields = event_to_fields(events[0]) if events else {"事件编号": "", "内容指纹": ""}
        client.validate_event_table(list(example_fields) + ["最近告警指纹", "告警状态"])
        existing = client.list_event_records()
    plan = build_publish_plan(events, existing, client.settings.alert_levels)
    if (
        should_alert and not dry_run and not allow_bulk_alerts
        and len(plan["alerts"]) > client.settings.max_alerts_per_run
    ):
        raise FeishuConfigurationError(
            f"本轮待发送告警 {len(plan['alerts'])} 条，超过安全上限 "
            f"{client.settings.max_alerts_per_run} 条。请先不发告警完成历史基线，"
            "或在确认受众和数量后显式允许批量告警。"
        )
    summary = {
        "待新增": len(plan["creates"]),
        "待更新": len(plan["updates"]),
        "未变化": int(plan["unchanged"]),
        "待告警": len(plan["alerts"]) if should_alert else 0,
        "演练模式": dry_run,
    }
    if dry_run:
        return summary

    record_ids: Dict[str, str] = {
        item["event_id"]: item["record_id"] for item in plan["updates"]
    }
    for chunk in _chunks(plan["creates"], client.settings.batch_size):
        created_ids = client.batch_create([item["fields"] for item in chunk])
        for item, record_id in zip(chunk, created_ids):
            record_ids[item["event_id"]] = record_id
    for chunk in _chunks(plan["updates"], client.settings.batch_size):
        client.batch_update([(item["record_id"], item["fields"]) for item in chunk])

    sent = 0
    if should_alert:
        alert_updates: List[Tuple[str, Dict[str, Any]]] = []
        for item in plan["alerts"]:
            record_id = record_ids.get(item["event_id"])
            if not record_id:
                current = next(
                    (record for record in existing if str((record.get("fields", {}) or {}).get("事件编号", "")) == item["event_id"]),
                    None,
                )
                record_id = str(current.get("record_id", "")) if current else ""
            client.send_text(
                client.settings.alert_chat_id,
                _alert_text(item["event"]),
                item["fingerprint"],
            )
            sent += 1
            if record_id:
                alert_updates.append((record_id, {
                    "最近告警指纹": item["fingerprint"], "告警状态": "已发送",
                }))
        for chunk in _chunks(alert_updates, client.settings.batch_size):
            client.batch_update(list(chunk))
    else:
        suppressed_updates: List[Tuple[str, Dict[str, Any]]] = []
        for item in plan["alerts"]:
            record_id = record_ids.get(item["event_id"])
            if not record_id:
                current = next(
                    (record for record in existing if str((record.get("fields", {}) or {}).get("事件编号", "")) == item["event_id"]),
                    None,
                )
                record_id = str(current.get("record_id", "")) if current else ""
            if record_id:
                suppressed_updates.append((record_id, {
                    "最近告警指纹": item["fingerprint"], "告警状态": "已抑制",
                }))
        for chunk in _chunks(suppressed_updates, client.settings.batch_size):
            client.batch_update(list(chunk))
    summary["已发送告警"] = sent
    summary["已抑制告警"] = 0 if should_alert else len(plan["alerts"])
    return summary
