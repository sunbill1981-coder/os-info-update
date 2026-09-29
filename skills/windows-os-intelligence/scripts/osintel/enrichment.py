from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any, Dict, Iterable, List, Mapping, Sequence
from urllib.parse import urlencode

from .model import Event
from .sources import CollectorContext


@dataclass
class EnrichmentResult:
    warnings: List[str] = field(default_factory=list)
    metrics: Dict[str, int] = field(default_factory=dict)
    failures: List[Dict[str, str]] = field(default_factory=list)
    successful_sources: Dict[str, int] = field(default_factory=dict)


def _cves(event: Event) -> List[str]:
    values = event.identifiers.get("cve", []) if isinstance(event.identifiers, dict) else []
    if isinstance(values, str):
        values = [values]
    return sorted({str(value).upper() for value in values if str(value).upper().startswith("CVE-")})


def _chunks_by_query_length(values: Sequence[str], maximum: int = 1800) -> Iterable[List[str]]:
    chunk: List[str] = []
    length = 0
    for value in values:
        added = len(value) + (1 if chunk else 0)
        if chunk and length + added > maximum:
            yield chunk
            chunk, length = [], 0
        chunk.append(value)
        length += added
    if chunk:
        yield chunk


def threat_urgency(event: Event) -> int:
    if event.kev.get("listed"):
        return 100
    if event.exploitation_status == "已确认被利用":
        return 95
    score = float(event.epss.get("score") or 0)
    percentile = float(event.epss.get("percentile") or 0)
    if score >= 0.5 or percentile >= 0.99:
        return 85
    if score >= 0.1 or percentile >= 0.95:
        return 75
    if score >= 0.01 or percentile >= 0.8:
        return 60
    return min(55, max(0, event.risk_score // 2))


def _apply_kev(
    events: Sequence[Event], context: CollectorContext, config: Mapping[str, Any], result: EnrichmentResult,
) -> None:
    settings = config.get("cisa_kev", {}) if isinstance(config, Mapping) else {}
    if not settings or not bool(settings.get("enabled", True)):
        return
    url = str(settings.get("url") or "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    try:
        document = context.fetch("cisa-kev", url, "application/json")
        payload = json.loads(document.body.decode("utf-8-sig"))
        rows = payload.get("vulnerabilities")
        if not isinstance(rows, list):
            raise ValueError("响应缺少 vulnerabilities 列表")
    except Exception as exc:
        message = f"CISA KEV enrichment 获取失败：{type(exc).__name__}: {exc}"
        result.warnings.append(message)
        result.failures.append({"source_id": "cisa-kev", "error": message})
        for event in events:
            if _cves(event):
                event.field_status["cisa_kev"] = "获取失败"
        return
    by_cve = {
        str(row.get("cveID") or "").upper(): row
        for row in rows if isinstance(row, dict) and row.get("cveID")
    }
    matched = 0
    for event in events:
        cves = _cves(event)
        if not cves:
            event.field_status["cisa_kev"] = "不适用"
            continue
        entries = [by_cve[cve] for cve in cves if cve in by_cve]
        event.field_status["cisa_kev"] = "已发布" if entries else "明确无记录"
        if entries:
            matched += 1
            dates = sorted(str(row.get("dateAdded") or "") for row in entries if row.get("dateAdded"))
            due_dates = sorted(str(row.get("dueDate") or "") for row in entries if row.get("dueDate"))
            event.kev = {
                "listed": True,
                "cves": sorted(str(row.get("cveID")) for row in entries),
                "date_added": dates[0] if dates else "",
                "due_date": due_dates[0] if due_dates else "",
                "ransomware_use": any(
                    str(row.get("knownRansomwareCampaignUse") or "").casefold() == "known"
                    for row in entries
                ),
                "required_action": "；".join(sorted({
                    str(row.get("requiredAction") or "").strip() for row in entries
                    if str(row.get("requiredAction") or "").strip()
                })),
            }
        else:
            event.kev = {"listed": False}
    result.metrics["kev_matched_events"] = matched
    result.successful_sources["cisa-kev"] = len(rows)


def _apply_epss(
    events: Sequence[Event], context: CollectorContext, config: Mapping[str, Any], result: EnrichmentResult,
) -> None:
    settings = config.get("first_epss", {}) if isinstance(config, Mapping) else {}
    if not settings or not bool(settings.get("enabled", True)):
        return
    base_url = str(settings.get("url") or "https://api.first.org/data/v1/epss")
    wanted = sorted({cve for event in events for cve in _cves(event)})
    if not wanted:
        return
    by_cve: Dict[str, Dict[str, Any]] = {}
    failed = False
    for chunk in _chunks_by_query_length(wanted):
        url = base_url + "?" + urlencode({"cve": ",".join(chunk)})
        try:
            document = context.fetch("first-epss", url, "application/json")
            payload = json.loads(document.body.decode("utf-8-sig"))
            rows = payload.get("data")
            if not isinstance(rows, list):
                raise ValueError("响应缺少 data 列表")
            for row in rows:
                if isinstance(row, dict) and row.get("cve"):
                    by_cve[str(row["cve"]).upper()] = row
        except Exception as exc:
            failed = True
            message = f"FIRST EPSS enrichment 获取失败：{type(exc).__name__}: {exc}"
            result.warnings.append(message)
            result.failures.append({"source_id": "first-epss", "error": message})
            break
    matched = 0
    for event in events:
        cves = _cves(event)
        if not cves:
            event.field_status["first_epss"] = "不适用"
            continue
        if failed:
            event.field_status["first_epss"] = "获取失败"
            continue
        candidates = [by_cve[cve] for cve in cves if cve in by_cve]
        event.field_status["first_epss"] = "已发布" if candidates else "明确无记录"
        if candidates:
            best = max(candidates, key=lambda row: float(row.get("epss") or 0))
            matched += 1
            event.epss = {
                "cve": str(best.get("cve") or ""),
                "score": float(best.get("epss") or 0),
                "percentile": float(best.get("percentile") or 0),
                "date": str(best.get("date") or ""),
            }
        else:
            event.epss = {}
    result.metrics["epss_matched_events"] = matched
    if not failed:
        result.successful_sources["first-epss"] = len(by_cve)


def enrich_events(
    events: Sequence[Event], context: CollectorContext, config: Mapping[str, Any],
) -> EnrichmentResult:
    result = EnrichmentResult()
    if not any(_cves(event) for event in events):
        for event in events:
            event.field_status.setdefault("cisa_kev", "不适用")
            event.field_status.setdefault("first_epss", "不适用")
            event.threat_urgency = threat_urgency(event)
        return result
    _apply_kev(events, context, config, result)
    _apply_epss(events, context, config, result)
    for event in events:
        event.threat_urgency = threat_urgency(event)
    return result
