"""Immutable, reviewable public baselines; no publication/checkpoint side effects."""
from __future__ import annotations

import copy
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit

from . import __version__
from .assessment import assess_event
from .continuity import FIELDS, validate_review
from .themes import validate_theme, FIELDS as THEME_FIELDS
from .correlate import correlate_events
from .model import Event, stable_hash, utc_now, parse_date
from .runtime import VERSIONS, PURPOSES

PUBLIC_EXTRA = {"components", "change_kinds", "preconditions", "affected_workflows", "symptoms",
                "confidence", "risk_score", "authoritative_evidence", "preview", "raw_hash"}


def implementation_fingerprint() -> str:
    root = Path(__file__).resolve().parents[2]
    files = sorted(p for folder in ("scripts", "config") for p in (root / folder).rglob("*")
                   if p.is_file() and p.suffix in {".py", ".json"} and ".local." not in p.name)
    # Agent instructions also affect semantic extraction; track them alongside code/rules.
    files = sorted(set(files + [root / "SKILL.md"] + list((root / "references").glob("*.md"))))
    return stable_hash([[str(p.relative_to(root)), hashlib.sha256(p.read_bytes()).hexdigest()] for p in files])


def _public_url(value):
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if parsed.scheme != "https" or not host or parsed.username or parsed.password or parsed.query:
        raise ValueError("公共数据来源必须是无认证信息/查询参数的 HTTPS 链接")
    if host == "localhost" or host.endswith((".local", ".internal")):
        raise ValueError("公共数据不能包含内部地址")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return
    if not address.is_global:
        raise ValueError("公共数据不能包含私有 IP")


def public_event(event: Event) -> dict:
    source = event.payload()
    value = event.fact_payload()
    value.update({key: source[key] for key in PUBLIC_EXTRA})
    # Retain source excerpts/fingerprints; never copy arbitrary nested metadata.
    value["source_references"] = [{key: row[key] for key in ("page_id", "url", "evidence", "excerpt", "raw_hash") if key in row}
                                  for row in source["source_references"]]
    _public_url(value["source_url"])
    for row in value["source_references"]:
        _public_url(row["url"])
    if Event(**value).fact_hash() != event.fact_hash():
        raise ValueError("公共导出改变了来源事实，需先人工检查")
    return value


def validate_coverage(coverage):
    if not isinstance(coverage, dict):
        raise ValueError("覆盖清单必须为对象")
    start, end = parse_date(coverage.get("start")), parse_date(coverage.get("end"))
    if not start or not end or start > end:
        raise ValueError("覆盖清单必须声明有效的 start/end；不能只用条数断言覆盖")
    for key in ("sources", "input_runs", "limitations"):
        values = coverage.get(key)
        if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v.strip() for v in values):
            raise ValueError(f"覆盖清单 {key} 必须为非空字符串列表")


def make_package(store, space, dataset_id, version, coverage: dict) -> dict:
    if space.purpose == "debug":
        raise ValueError("debug 合成数据禁止导出为公共基线")
    if not dataset_id or not version:
        raise ValueError("须提供数据集名称、版本和覆盖限制（完整覆盖不能仅按条数断言）")
    validate_coverage(coverage)
    pending = store.metadata("pending-semantic-review", {})
    for kind in ("constraint", "risk", "theme"):
        if any(value["id"] in pending.get(kind, {}) for value in store.records(kind)):
            raise ValueError("历史重评后仍有约束/风险待重审，请先提交评审再导出候选新版")
    events = [public_event(Event(**value)) for value in store.list_events()]
    event_map = {e["event_id"]: Event(**e) for e in events}
    constraints, risks = [], []
    for kind, dest in (("constraint", constraints), ("risk", risks)):
        for value in store.records(kind):
            row = {key: value[key] for key in FIELDS[kind] if key in value}
            dest.append(validate_review(kind, row, event_map, {c["id"]: dict(c, revision_hash=stable_hash(c)) for c in constraints}))
    themes = [validate_theme({k: v for k, v in row.items() if k in THEME_FIELDS}, event_map) for row in store.records("theme")]
    data = {"events": events, "constraints": constraints, "risks": risks}
    if themes:
        data["themes"] = themes
    package = {"manifest": {"schema": "dataset-v1", "dataset_id": dataset_id, "version": version,
                         "status": "candidate", "created_at": utc_now(), "run_purpose": space.purpose,
                         "skill_version": __version__, "implementation": implementation_fingerprint(),
                         "versions": VERSIONS, "coverage": coverage, "counts": {k: len(v) for k, v in data.items()},
                         "data_sha256": stable_hash(data), "basis": "current-source-reconstruction",
                         "public_review_required": True}, "data": data}
    if themes:
        package["manifest"]["theme_schema"] = "theme-v1"
    validate_package(package)
    return package


def write_package(path: Path, package: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (json.dumps(package, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    if path.suffix == ".gz":
        body = gzip.compress(body, mtime=0)
    with path.open("xb") as handle:
        handle.write(body)


def read_package(path: Path, *, approved=False) -> dict:
    body = path.read_bytes()
    if path.suffix == ".gz":
        body = gzip.decompress(body)
    package = json.loads(body)
    validate_package(package, approved=approved)
    return package


def validate_package(package: dict, *, approved=False) -> None:
    if set(package) != {"manifest", "data"}:
        raise ValueError("数据包结构无效")
    manifest, data = package["manifest"], package["data"]
    if not isinstance(manifest, dict) or not isinstance(data, dict):
        raise ValueError("数据包清单与内容必须为对象")
    for key in ("dataset_id", "version", "skill_version", "implementation", "created_at"):
        if not isinstance(manifest.get(key), str) or not manifest[key].strip():
            raise ValueError("数据包缺少有效的 " + key)
    if manifest.get("schema") != "dataset-v1" or manifest.get("versions", {}).get("schema") != VERSIONS["schema"]:
        raise ValueError("数据格式版本不兼容，需显式迁移")
    if manifest.get("run_purpose") not in PURPOSES or manifest.get("run_purpose") == "debug":
        raise ValueError("debug 数据不能导入正式基线")
    if manifest.get("status") not in {"candidate", "approved"} or (approved and manifest.get("status") != "approved"):
        raise ValueError("数据尚未验收")
    if manifest.get("status") == "approved" and not all(manifest.get("approval", {}).get(k) for k in ("reviewer", "note", "reviewed_at")):
        raise ValueError("已验收数据必须有验收记录")
    if set(data) not in ({"events", "constraints", "risks"}, {"events", "constraints", "risks", "themes"}) or stable_hash(data) != manifest.get("data_sha256"):
        raise ValueError("数据校验失败")
    if any(not isinstance(v, list) for v in data.values()):
        raise ValueError("数据包记录必须为列表")
    if manifest.get("counts") != {k: len(v) for k, v in data.items()}:
        raise ValueError("数据数量与清单不一致")
    validate_coverage(manifest.get("coverage"))
    events = {}
    for row in data["events"]:
        event = Event(**row)
        allowed = set(event.fact_payload()) | PUBLIC_EXTRA
        if set(row) - allowed or public_event(event) != row:
            raise ValueError("公共事件字段非法或含非公共信息")
        if event.event_id in events:
            raise ValueError("事件身份重复")
        events[event.event_id] = event
    if {e.source_id for e in events.values()} - set(manifest["coverage"]["sources"]):
        raise ValueError("覆盖清单未声明包内事件来源")
    constraints = {}
    for kind, values in (("constraint", data["constraints"]), ("risk", data["risks"])):
        seen = set()
        for row in values:
            checked = validate_review(kind, row, events, constraints)
            if checked != row or row["id"] in seen:
                raise ValueError("派生身份重复或结构不规范")
            for basis in row["basis"]:
                _public_url(basis["url"])
            seen.add(row["id"])
            if kind == "constraint":
                constraints[row["id"]] = dict(row, revision_hash=stable_hash(row))


    if "themes" in data and manifest.get("theme_schema") != "theme-v1":
        raise ValueError("主题数据需要显式声明 theme-v1 能力；旧版Skill不能导入")
    if manifest.get("theme_schema") not in (None, "theme-v1"):
        raise ValueError("主题格式版本不兼容")
    seen_themes = set()
    for row in data.get("themes", []):
        if validate_theme(row, events) != row or row["id"] in seen_themes:
            raise ValueError("主题身份或结构不规范")
        seen_themes.add(row["id"])
        for basis in row["basis"] + [b for n in row["timeline"] for b in n.get("basis", [])]:
            _public_url(basis["url"])


def approve_package(package: dict, reviewer: str, note: str) -> dict:
    validate_package(package)
    if package["manifest"]["status"] != "candidate" or not reviewer.strip() or not note.strip():
        raise ValueError("只可验收候选包，需提供验收者与范围/公开内容核验说明")
    result = copy.deepcopy(package)
    result["manifest"].update(status="approved", public_review_required=False,
                              approval={"reviewer": reviewer, "note": note, "reviewed_at": utc_now()})
    validate_package(result, approved=True)
    return result


def import_package(store, package: dict, *, dry_run=False) -> dict:
    validate_package(package, approved=True)
    manifest, data = package["manifest"], package["data"]
    key = manifest["dataset_id"] + ":" + manifest["version"]
    prior = store.metadata("dataset:" + key)
    if prior and prior != package:
        raise ValueError("同一已发布版本不能改写，请发布新版本")
    current = {e["event_id"]: Event(**e) for e in store.list_events()}
    summary = {"dataset": key, "new": 0, "changed": 0, "unchanged": 0,
               "live_preserved": 0, "notifications_sent": False, "checkpoints_changed": False}
    live = set(store.metadata("live-event-ids", []))
    for row in data["events"]:
        event = Event(**row)
        if event.event_id in live:
            summary["live_preserved"] += 1
        elif event.event_id not in current:
            summary["new"] += 1
        elif current[event.event_id].fact_hash() != event.fact_hash():
            summary["changed"] += 1
        else:
            summary["unchanged"] += 1
    if dry_run:
        return summary
    live_records = store.metadata("live-record-ids", {})
    managed = store.metadata("baseline-managed", {"events": [], "constraint": [], "risk": []})
    active = {"events": [e["event_id"] for e in data["events"]],
              "constraint": [r["id"] for r in data["constraints"]], "risk": [r["id"] for r in data["risks"]],
              "theme": [r["id"] for r in data.get("themes", [])]}
    with store.connect() as connection:
        store.upsert_events([Event(**row) for row in data["events"] if row["event_id"] not in live], connection)
        for kind, rows in (("constraint", data["constraints"]), ("risk", data["risks"]), ("theme", data.get("themes", []))):
            for row in rows:
                if row["id"] not in live_records.get(kind, []):
                    store.upsert_record(kind, row, connection)
        store.set_metadata("dataset:" + key, package, connection)
        store.set_metadata("active-dataset", key, connection)
        store.set_metadata("baseline-active", active, connection)
        store.set_metadata("baseline-managed", {k: sorted(set(managed.get(k, [])) | set(v)) for k, v in active.items()}, connection)
        store.set_metadata("latest-report", None, connection)
    return summary


def reprocess(store, taxonomy: dict, environment: dict, *, event_ids=None) -> dict:
    """Reassess stored facts. Re-parsing requires source snapshots, never old AI prose."""
    events = [Event(**e) for e in store.list_events()]
    if event_ids is not None:
        unknown = set(event_ids) - {e.event_id for e in events}
        if unknown:
            raise ValueError("指定事件不存在：" + ",".join(sorted(unknown)))
    selected = [e for e in events if event_ids is None or e.event_id in event_ids]
    before_payload = {e.event_id: e.assessment_payload() for e in events}
    before = {e.event_id: (e.fact_hash(), e.assessment_hash()) for e in events}
    for event in selected:
        assess_event(event, taxonomy, environment)
    correlate_events(events)
    assert all(e.fact_hash() == before[e.event_id][0] for e in events)
    stats = store.upsert_events(events)
    impacted = {e.event_id for e in selected} | {e.event_id for e in events if e.assessment_hash() != before[e.event_id][1]}
    pending = store.metadata("pending-semantic-review", {})
    for kind in ("constraint", "risk", "theme"):
        pending.setdefault(kind, {})
        for row in store.records(kind):
            if any(ref["event_id"] in impacted for ref in row["event_refs"]):
                pending[kind][row["id"]] = "历史评估规则重跑后，需要核对原评审是否仍成立"
    store.set_metadata("pending-semantic-review", pending)
    changes = [{"event_id": e.event_id, "fact_changed": False,
                "assessment_fields": [{"field": k, "before": before_payload[e.event_id].get(k), "after": e.assessment_payload().get(k)}
                                      for k in sorted(set(before_payload[e.event_id]) | set(e.assessment_payload()))
                                      if before_payload[e.event_id].get(k) != e.assessment_payload().get(k)]}
               for e in events if e.assessment_hash() != before[e.event_id][1]]
    return {"stage": "assessment", "stats": stats, "versions": VERSIONS,
            "input_dataset": store.metadata("active-dataset"), "implementation": implementation_fingerprint(),
            "scope": sorted(e.event_id for e in selected), "changes": changes,
            "changed_ids": [e.event_id for e in events if e.assessment_hash() != before[e.event_id][1]],
            "limitations": ["本入口重评已有结构化事实，不自动重新解析旧网页；提取规则变化需要核对并重新导入对应来源快照。",
                            "历史约束与风险评审未被自动改写；来源/约束修订变化会标记重审。"],
            "notifications_sent": False}
