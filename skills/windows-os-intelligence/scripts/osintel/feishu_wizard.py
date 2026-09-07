from __future__ import annotations

from datetime import date
import getpass
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Callable, Dict, List, Mapping, Sequence, TextIO, Tuple
from urllib.parse import parse_qs, urlparse

from .feishu import (
    FeishuApiError,
    FeishuClient,
    FeishuConfigurationError,
    FeishuSettings,
    event_to_fields,
    load_env_file,
    load_events,
    publish_events,
    write_env_file,
)


InputFunction = Callable[[str], str]
SecretFunction = Callable[[str], str]


SUPPORTING_TABLES = (
    ("证据来源", "evidence_table_id", "evidence"),
    ("Windows 环境画像", "profiles_table_id", "profiles"),
    ("变更历史", "changes_table_id", "changes"),
    ("采集任务", "runs_table_id", "runs"),
    ("适用性判断", "applicability_table_id", "applicability"),
    ("验证与处置", "actions_table_id", "actions"),
)


def mask_value(value: str) -> str:
    value = value.strip()
    if not value:
        return "未配置"
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "…" + value[-4:]


def parse_base_location(value: str) -> Tuple[str, str]:
    text = value.strip()
    if not text:
        return "", ""
    if "://" not in text:
        return text, ""
    parsed = urlparse(text)
    segments = [segment for segment in parsed.path.split("/") if segment]
    token = ""
    for marker in ("base", "bitable"):
        if marker in segments:
            index = segments.index(marker)
            if index + 1 < len(segments):
                token = segments[index + 1]
                break
    query = parse_qs(parsed.query)
    table_id = (query.get("table") or query.get("table_id") or [""])[0]
    if not token:
        raise FeishuConfigurationError(
            "无法从链接解析 Base 标识；请使用包含 /base/ 或 /bitable/ 的"
            "多维表格链接，或直接输入 Base 标识。"
        )
    return token, table_id


def load_event_field_definitions(schema_path: Path) -> List[Dict[str, Any]]:
    return load_table_definitions(schema_path)["events"]


def load_table_definitions(schema_path: Path) -> Dict[str, List[Dict[str, Any]]]:
    payload = json.loads(schema_path.read_text(encoding="utf-8"))
    result: Dict[str, List[Dict[str, Any]]] = {}
    for table in payload.get("tables", []):
        logical_name = str(table.get("logical_name") or "")
        definitions = table.get("fields", [])
        if logical_name and definitions:
            result[logical_name] = [dict(item) for item in definitions]
    if "events" not in result:
        raise FeishuConfigurationError("飞书 schema 中找不到情报事件表字段定义。")
    return result


def ensure_local_config(example_path: Path, local_path: Path) -> None:
    source = local_path if local_path.exists() else example_path
    payload = json.loads(source.read_text(encoding="utf-8"))
    payload["enabled"] = True
    payload.setdefault("publish", {})["send_alerts"] = False
    local_path.parent.mkdir(parents=True, exist_ok=True)
    local_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _ask_yes_no(prompt: str, input_fn: InputFunction, default: bool = False) -> bool:
    suffix = " [Y/n]：" if default else " [y/N]："
    answer = input_fn(prompt + suffix).strip().casefold()
    if not answer:
        return default
    return answer in {"y", "yes", "是", "好", "确认"}


def _ask_value(
    label: str,
    current: str,
    input_fn: InputFunction,
    secret_fn: SecretFunction,
    secret: bool = False,
    optional: bool = False,
) -> str:
    current_hint = f"（已有 {mask_value(current)}，回车保留）" if current else ""
    optional_hint = "（可留空）" if optional and not current else ""
    prompt = f"{label}{current_hint}{optional_hint}："
    value = secret_fn(prompt) if secret else input_fn(prompt)
    value = value.strip()
    result = value or current
    if not result and not optional:
        raise FeishuConfigurationError(f"{label}不能为空。")
    return result


def preview_events(events: Sequence[Mapping[str, Any]], output: TextIO, limit: int = 3) -> None:
    print(f"已读取 {len(events)} 条规范化情报。", file=output)
    if not events:
        print("当前没有可预览数据，请先运行采集器。", file=output)
        return
    print("飞书字段预览：", file=output)
    for event in events[:limit]:
        fields = event_to_fields(event)
        print(
            f"- {fields['中文标题']}｜{fields['告警级别']}｜"
            f"技术风险 {fields['技术风险']}｜环境相关度 {fields['环境相关度']}",
            file=output,
        )


def check_connection(
    settings: FeishuSettings,
    definitions: Sequence[Mapping[str, Any]],
    output: TextIO,
) -> Tuple[FeishuClient, List[str]]:
    client = FeishuClient(settings)
    client.access_token()
    print("✓ 应用鉴权成功。", file=output)
    missing = client.missing_fields([str(item["name"]) for item in definitions])
    if missing:
        print(f"⚠ 情报事件表缺少 {len(missing)} 个字段。", file=output)
    else:
        print("✓ 情报事件表结构完整。", file=output)
    return client, missing


def check_supporting_tables(
    client: FeishuClient,
    definitions: Mapping[str, Sequence[Mapping[str, Any]]],
    output: TextIO,
) -> List[Tuple[str, str, str, List[str]]]:
    results = []
    for label, setting_name, logical_name in SUPPORTING_TABLES:
        table_id = str(getattr(client.settings, setting_name))
        if not table_id:
            print(f"○ {label}表未配置，已跳过。", file=output)
            continue
        missing = client.missing_fields(
            [str(item["name"]) for item in definitions[logical_name]], table_id,
        )
        results.append((label, table_id, logical_name, missing))
        if missing:
            print(f"⚠ {label}表缺少 {len(missing)} 个字段：{'、'.join(missing)}", file=output)
        else:
            print(f"✓ {label}表结构完整。", file=output)
    return results


def _configure_values(
    env_path: Path,
    input_fn: InputFunction,
    secret_fn: SecretFunction,
) -> Dict[str, str]:
    current = load_env_file(env_path, environ={})
    app_id = _ask_value("飞书应用编号", current.get("FEISHU_APP_ID", ""), input_fn, secret_fn)
    app_secret = _ask_value(
        "飞书应用密钥（输入时不显示）",
        current.get("FEISHU_APP_SECRET", ""), input_fn, secret_fn, secret=True,
    )
    current_base = current.get("FEISHU_BASE_TOKEN", "")
    location = _ask_value(
        "Base 链接或 Base 标识", current_base, input_fn, secret_fn,
    )
    base_token, parsed_table = parse_base_location(location)
    table_id = _ask_value(
        "情报事件表标识",
        parsed_table or current.get("FEISHU_EVENTS_TABLE_ID", ""),
        input_fn,
        secret_fn,
    )
    chat_id = _ask_value(
        "告警群标识",
        current.get("FEISHU_ALERT_CHAT_ID", ""),
        input_fn,
        secret_fn,
        optional=True,
    )
    optional_tables = {}
    for label, env_name in (
        ("证据来源表标识", "FEISHU_EVIDENCE_TABLE_ID"),
        ("Windows 环境画像表标识", "FEISHU_PROFILES_TABLE_ID"),
        ("变更历史表标识", "FEISHU_CHANGES_TABLE_ID"),
        ("采集任务表标识", "FEISHU_RUNS_TABLE_ID"),
        ("适用性判断表标识", "FEISHU_APPLICABILITY_TABLE_ID"),
        ("验证与处置表标识", "FEISHU_ACTIONS_TABLE_ID"),
    ):
        optional_tables[env_name] = _ask_value(
            label, current.get(env_name, ""), input_fn, secret_fn, optional=True,
        )
    return {
        "FEISHU_APP_ID": app_id,
        "FEISHU_APP_SECRET": app_secret,
        "FEISHU_BASE_TOKEN": base_token,
        "FEISHU_BASE_URL": location if "://" in location else current.get("FEISHU_BASE_URL", ""),
        "FEISHU_EVENTS_TABLE_ID": table_id,
        "FEISHU_ALERT_CHAT_ID": chat_id,
        **optional_tables,
    }


def run_interactive(
    workspace: Path,
    input_fn: InputFunction = input,
    secret_fn: SecretFunction = getpass.getpass,
    output: TextIO = sys.stdout,
) -> int:
    skill_root = workspace / "skills/windows-os-intelligence"
    events_path = workspace / "data/normalized/events.ndjson"
    schema_path = skill_root / "config/feishu-schema.json"
    example_path = skill_root / "config/feishu.example.json"
    local_path = skill_root / "config/feishu.local.json"
    env_path = workspace / ".env"

    print("Windows 操作系统情报—飞书接入向导", file=output)
    print("真实密钥和飞书资源标识只保存在本地忽略文件中。\n", file=output)
    events = load_events(events_path)
    preview_events(events, output)
    if not _ask_yes_no("\n是否继续连接真实飞书", input_fn):
        print("已停在本地预览，未连接或修改飞书。", file=output)
        return 0

    print("\n第 1 步：准备飞书资源", file=output)
    print("- 在 https://open.feishu.cn/app 创建企业自建应用并启用机器人。", file=output)
    print("- 授予 Base 记录读写和机器人发送消息的必要权限。", file=output)
    print("- 新建一个 Base 和“情报事件”表，并让应用可访问该 Base。", file=output)
    print("- 可选新建六张辅助表；适用性与处置表只初始化，不覆盖人工内容。", file=output)
    if not _ask_yes_no("上述准备是否已完成", input_fn):
        print("请完成飞书资源准备后重新运行向导。", file=output)
        return 0

    print("\n第 2 步：填写本地配置", file=output)
    values = _configure_values(env_path, input_fn, secret_fn)
    print(
        f"将保存：应用 {mask_value(values['FEISHU_APP_ID'])}，"
        f"Base {mask_value(values['FEISHU_BASE_TOKEN'])}，"
        f"数据表 {mask_value(values['FEISHU_EVENTS_TABLE_ID'])}，"
        f"证据表 {mask_value(values['FEISHU_EVIDENCE_TABLE_ID'])}，"
        f"任务表 {mask_value(values['FEISHU_RUNS_TABLE_ID'])}，"
        f"告警群 {mask_value(values['FEISHU_ALERT_CHAT_ID'])}。",
        file=output,
    )
    if not _ask_yes_no("确认保存到本地忽略文件", input_fn):
        print("已取消，未写入配置。", file=output)
        return 0
    ensure_local_config(example_path, local_path)
    write_env_file(env_path, values)
    print(f"✓ 本地配置已保存：{local_path}", file=output)
    print(f"✓ 密钥与资源位置已保存：{env_path}（权限 600）", file=output)

    print("\n第 3 步：验证连接与表结构", file=output)
    all_definitions = load_table_definitions(schema_path)
    definitions = all_definitions["events"]
    settings = FeishuSettings.load(local_path, environ=values, require_remote=True)
    try:
        client, missing = check_connection(settings, definitions, output)
    except (FeishuApiError, FeishuConfigurationError) as exc:
        print(f"✗ 连接验证失败：{exc}", file=output)
        print("配置已保留，修正应用权限或资源位置后可重新运行 --check。", file=output)
        return 2

    if missing:
        print("缺失字段：" + "、".join(missing), file=output)
        if not _ask_yes_no("是否由向导逐个创建缺失字段", input_fn):
            print("未修改 Base。请补齐字段后重新运行 --check。", file=output)
            return 0
        by_name = {str(item["name"]): item for item in definitions}
        try:
            created = client.create_fields([by_name[name] for name in missing])
            client.validate_event_table([str(item["name"]) for item in definitions])
        except (FeishuApiError, FeishuConfigurationError) as exc:
            print(f"✗ 创建字段中止：{exc}", file=output)
            print("已成功创建的字段会保留；修正失败项后重新运行即可继续。", file=output)
            return 2
        print(f"✓ 已创建 {len(created)} 个缺失字段。", file=output)

    try:
        supporting_results = check_supporting_tables(client, all_definitions, output)
        for label, table_id, logical_name, support_missing in supporting_results:
            if not support_missing:
                continue
            if not _ask_yes_no(f"是否由向导创建{label}表的缺失字段", input_fn):
                continue
            by_name = {str(item["name"]): item for item in all_definitions[logical_name]}
            created = client.create_fields(
                [by_name[name] for name in support_missing], table_id,
            )
            remaining = client.missing_fields(
                [str(item["name"]) for item in all_definitions[logical_name]], table_id,
            )
            if remaining:
                raise FeishuConfigurationError(
                    f"{label}表补字段后仍缺少：{'、'.join(remaining)}"
                )
            print(f"✓ {label}表已创建 {len(created)} 个缺失字段。", file=output)
    except (FeishuApiError, FeishuConfigurationError) as exc:
        print(f"✗ 辅助表检查或补字段中止：{exc}", file=output)
        print("已成功创建的字段会保留；修正失败项后重新运行即可继续。", file=output)
        return 2

    print("\n第 4 步：单条记录验证", file=output)
    if events:
        sample_fields = event_to_fields(events[0])
        print(f"待试写：{sample_fields['中文标题']}", file=output)
        if _ask_yes_no("是否写入这一条真实情报（不发群消息）", input_fn):
            result = publish_events(client, [events[0]], send_alerts=False)
            print("✓ 单条试写完成：" + json.dumps(result, ensure_ascii=False), file=output)

    print("\n第 5 步：建立历史基线", file=output)
    if _ask_yes_no(f"是否将当前 {len(events)} 条情报幂等同步到 Base（不发群消息）", input_fn):
        result = publish_events(client, events, send_alerts=False)
        print("✓ 历史基线完成：" + json.dumps(result, ensure_ascii=False), file=output)

    print("\n第 6 步：机器人消息验证", file=output)
    if settings.alert_chat_id:
        if _ask_yes_no("是否向已配置群发送一条连接测试消息", input_fn):
            key_source = f"setup|{settings.alert_chat_id}|{date.today().isoformat()}"
            idempotency_key = hashlib.sha256(key_source.encode("utf-8")).hexdigest()
            client.send_text(
                settings.alert_chat_id,
                "Windows 操作系统情报系统连接测试成功。这是向导发送的测试消息。",
                idempotency_key,
            )
            print("✓ 测试消息已发送。", file=output)
    else:
        print("未配置告警群，已跳过消息测试。", file=output)

    print("\n向导完成。现在可以在 Base 中查看情报记录。", file=output)
    print("日常运行先执行采集命令，再执行 publish_feishu.py --send-alerts。", file=output)
    return 0


def run_check(workspace: Path, output: TextIO = sys.stdout) -> int:
    skill_root = workspace / "skills/windows-os-intelligence"
    local_path = skill_root / "config/feishu.local.json"
    env_path = workspace / ".env"
    all_definitions = load_table_definitions(skill_root / "config/feishu-schema.json")
    definitions = all_definitions["events"]
    settings = FeishuSettings.load(
        local_path, environ=load_env_file(env_path), require_remote=True,
    )
    client, missing = check_connection(settings, definitions, output)
    if missing:
        print("表结构未完成，请重新运行交互向导进行修复。", file=output)
        return 2
    supporting = check_supporting_tables(client, all_definitions, output)
    if any(missing_support for _, _, _, missing_support in supporting):
        return 2
    print("飞书连接检查通过。", file=output)
    return 0
