from __future__ import annotations

from calendar import month_abbr
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

from .http import FetchError, HttpClient
from .model import Event, RawDocument, SourceResult, parse_date, stable_hash
from .parsers import Block, clean_text, parse_article_blocks, parse_table_rows
from .scoring import extract_identifiers, infer_components, infer_roles, risk_score
from .store import Store


MONTH_NAME = {name: index for index, name in enumerate(
    ("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"), 1
)}
DATE_TOKEN_RE = re.compile(r"\b(20\d{2}-\d{2}-\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+20\d{2})\b", re.I)
PRODUCT_RE = re.compile(
    r"Windows 11(?:,? version \d{2}H\d)?|Windows 10(?:,? version \d{2}H\d)?|Windows Server(?:,? version)? (?:2019|2022|2025)", re.I
)


@dataclass
class CollectorContext:
    http: HttpClient
    store: Store

    def fetch(self, source_id: str, url: str, accept: str) -> RawDocument:
        meta = self.store.document_meta(url)
        document = self.http.fetch(
            source_id, url, accept=accept,
            etag=meta["etag"] if meta else None,
            last_modified=meta["last_modified"] if meta else None,
        )
        if document.status == 304:
            cached = self.store.cached_document(url)
            if cached is None:
                document = self.http.fetch(source_id, url, accept=accept)
            else:
                return cached
        return self.store.persist_document(document)


def _in_window(value: Optional[str], start: date, end: date) -> bool:
    parsed = parse_date(value)
    return bool(parsed and start <= parsed <= end)


def _month_iter(start: date, end: date) -> Iterable[Tuple[int, int]]:
    year, month = start.year, start.month
    while (year, month) <= (end.year, end.month):
        yield year, month
        if month == 12:
            year, month = year + 1, 1
        else:
            month += 1


def _walk_products(value, mapping: Dict[str, str]) -> None:
    if isinstance(value, dict):
        product_id = value.get("ProductID")
        label = value.get("Value")
        if product_id and label:
            mapping[str(product_id)] = str(label)
        for child in value.values():
            _walk_products(child, mapping)
    elif isinstance(value, list):
        for child in value:
            _walk_products(child, mapping)


def _value(node) -> str:
    if isinstance(node, dict):
        return str(node.get("Value") or "")
    return str(node or "")


def _revision_dates(vulnerability: Dict[str, object]) -> List[str]:
    values = []
    for revision in vulnerability.get("RevisionHistory", []) or []:
        if isinstance(revision, dict) and revision.get("Date"):
            values.append(str(revision["Date"]))
    return values


def parse_msrc_document(document: Dict[str, object], start: date, end: date, target_products: Sequence[str], raw_hash: str) -> List[Event]:
    product_map: Dict[str, str] = {}
    _walk_products(document.get("ProductTree", {}), product_map)
    targets = tuple(value.casefold() for value in target_products)
    events: List[Event] = []
    for vulnerability in document.get("Vulnerability", []) or []:
        if not isinstance(vulnerability, dict):
            continue
        affected_ids = {
            str(product_id)
            for status in vulnerability.get("ProductStatuses", []) or []
            if isinstance(status, dict)
            for product_id in status.get("ProductID", []) or []
        }
        products = sorted({
            product_map[product_id] for product_id in affected_ids
            if product_id in product_map and any(target in product_map[product_id].casefold() for target in targets)
        })
        if not products:
            continue
        release_date = str(vulnerability.get("ReleaseDate") or "")
        parsed_release_date = parse_date(release_date)
        revision_dates = _revision_dates(vulnerability)
        matching_revision_dates = [value for value in revision_dates if _in_window(value, start, end)]
        if not (
            _in_window(release_date, start, end)
            or (parsed_release_date and parsed_release_date <= end and matching_revision_dates)
        ):
            continue
        cve = str(vulnerability.get("CVE") or "").upper()
        title = _value(vulnerability.get("Title")) or cve or "Microsoft security update"
        notes = [_value(note.get("Value") if isinstance(note, dict) else note) for note in vulnerability.get("Notes", []) or []]
        notes = [value for value in notes if value]
        threat_values = [_value(item.get("Description")) for item in vulnerability.get("Threats", []) or [] if isinstance(item, dict)]
        combined = " ".join([title] + notes + threat_values)
        exploited = "Exploited:Yes".casefold() in combined.casefold()
        cvss = max((float(item.get("BaseScore") or 0) for item in vulnerability.get("CVSSScoreSets", []) or [] if isinstance(item, dict)), default=0.0)
        severity = next((value for value in threat_values if value in {"Critical", "Important", "Moderate", "Low"}), "")
        components = infer_components(combined)
        identifiers = extract_identifiers(combined)
        if cve:
            identifiers["cve"] = [cve]
        identifiers["msrc_document"] = _value(document.get("DocumentTracking", {}).get("Identification", {}).get("ID", {})) if isinstance(document.get("DocumentTracking"), dict) else ""
        summary_parts = [value for value in (severity, f"CVSS {cvss:g}" if cvss else "", threat_values[0] if threat_values else "") if value]
        event = Event(
            event_id=f"msrc:{cve or stable_hash([title, products])[:20]}",
            title=f"{cve}: {title}" if cve and cve not in title else title,
            event_type="vulnerability",
            status="confirmed",
            source_id="msrc",
            source_tier="P0",
            source_url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}" if cve else "https://msrc.microsoft.com/update-guide/",
            published_at=release_date or None,
            updated_at=max(matching_revision_dates) if matching_revision_dates else release_date or None,
            products=products,
            roles=infer_roles(products, components),
            components=components,
            identifiers=identifiers,
            summary="; ".join(summary_parts) or title,
            evidence=clean_text(" ".join(notes))[:800],
            recommended_action="核对补丁适用范围，并在有代表性的云桌面来宾镜像和宿主机上完成安装、回滚及业务兼容性验证。",
            risk_score=risk_score(combined, products, components, cvss=cvss, exploited=exploited),
            confidence=98,
            raw_hash=raw_hash,
        )
        events.append(event)
    return events


class MsrcCollector:
    source_id = "msrc"

    def collect(self, context: CollectorContext, start: date, end: date, config: Dict[str, object]) -> SourceResult:
        result = SourceResult(self.source_id)
        for year, month in _month_iter(start, end):
            document_id = f"{year}-{month_abbr[month]}"
            url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{document_id}"
            try:
                raw = context.fetch(self.source_id, url, "application/json")
            except FetchError as exc:
                if exc.status == 404:
                    result.warnings.append(f"No MSRC document for {document_id}")
                    continue
                raise
            result.documents.append(raw)
            document = json.loads(raw.body.decode("utf-8-sig"))
            result.events.extend(parse_msrc_document(document, start, end, config["target_products"], raw.sha256))
        return result


def _section_date_match(month_heading: str, body: str, start: date, end: date) -> bool:
    dates = [
        parse_date(match.group(1))
        for match in re.finditer(
            r"(?:Opened|Resolved|Last updated):\s*(20\d{2}-\d{2}-\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},\s+20\d{2})",
            body,
            flags=re.I,
        )
    ]
    dates = [value for value in dates if value]
    if dates:
        return any(start <= value <= end for value in dates)
    match = re.fullmatch(r"([A-Za-z]+)\s+(20\d{2})", month_heading.strip())
    if not match or match.group(1) not in MONTH_NAME:
        return False
    month_start = date(int(match.group(2)), MONTH_NAME[match.group(1)], 1)
    next_month = date(month_start.year + (month_start.month == 12), 1 if month_start.month == 12 else month_start.month + 1, 1)
    return month_start <= end and next_month > start


def _extract_products(text: str, fallback: str) -> List[str]:
    products = sorted({clean_text(match.group(0)) for match in PRODUCT_RE.finditer(text)}, key=str.casefold)
    return products or [fallback]


def parse_release_health(html: str, source_id: str, url: str, fallback_product: str, start: date, end: date, raw_hash: str) -> List[Event]:
    blocks = parse_article_blocks(html)
    events: List[Event] = []
    current_month = ""
    in_details = False
    index = 0
    while index < len(blocks):
        block = blocks[index]
        if block.tag == "h2":
            in_details = block.text.casefold() in {"issue details", "resolved issues", "known issues"}
        elif in_details and block.tag == "h3":
            current_month = block.text
        elif in_details and block.tag == "h4":
            following: List[str] = []
            cursor = index + 1
            while cursor < len(blocks) and blocks[cursor].tag not in {"h2", "h3", "h4"}:
                following.append(blocks[cursor].text)
                cursor += 1
            body = clean_text(" ".join(following))
            if body and _section_date_match(current_month, body, start, end):
                status = "reported"
                for candidate in ("resolved", "mitigated", "confirmed", "investigating", "reported"):
                    if re.search(rf"\b{candidate}\b", body, flags=re.I):
                        status = candidate
                        break
                products = _extract_products(body, fallback_product)
                combined = f"{block.text} {body}"
                components = infer_components(combined)
                identifiers = extract_identifiers(combined)
                opened = re.search(r"Opened:\s*(20\d{2}-\d{2}-\d{2})", body, re.I)
                resolved = re.search(r"Resolved:\s*(20\d{2}-\d{2}-\d{2})", body, re.I)
                section_id = block.attrs.get("id") or stable_hash(block.text)[:20]
                events.append(Event(
                    event_id=f"release-health:{section_id}",
                    title=block.text,
                    event_type="known issue",
                    status=status,
                    source_id="release-health",
                    source_tier="P0",
                    source_url=f"{url}#{block.attrs.get('id')}" if block.attrs.get("id") else url,
                    published_at=opened.group(1) if opened else None,
                    updated_at=resolved.group(1) if resolved else None,
                    products=products,
                    builds=identifiers.get("build", []),
                    roles=infer_roles(products, components),
                    components=components,
                    identifiers=identifiers,
                    summary=body[:600],
                    evidence=body[:1000],
                    recommended_action="核对关联 KB、影响平台、临时缓解措施和修复版本，在镜像推广前完成复现与验证。",
                    risk_score=risk_score(combined, products, components),
                    confidence=97,
                    raw_hash=raw_hash,
                ))
            index = cursor - 1
        index += 1
    return events


class ReleaseHealthCollector:
    source_id = "release-health"

    def collect(self, context: CollectorContext, start: date, end: date, config: Dict[str, object]) -> SourceResult:
        result = SourceResult(self.source_id)
        for page in config.get("release_health", []):
            page_id = str(page["id"])
            try:
                raw = context.fetch(self.source_id, str(page["url"]), "text/html")
            except FetchError as exc:
                result.warnings.append(f"{page_id}: {exc}")
                continue
            result.documents.append(raw)
            result.events.extend(parse_release_health(
                raw.body.decode("utf-8", errors="replace"), page_id, str(page["url"]),
                str(page["product"]), start, end, raw.sha256,
            ))
        if not result.documents:
            raise RuntimeError("all Windows Release Health pages failed")
        return result


def parse_lifecycle(html: str, source_id: str, url: str, product: str, start: date, end: date, raw_hash: str) -> List[Event]:
    events: List[Event] = []
    for row in parse_table_rows(html):
        text = clean_text(" | ".join(row))
        dates = [parse_date(match.group(1)) for match in DATE_TOKEN_RE.finditer(text)]
        dates = [value for value in dates if value]
        if not dates or not any(start <= value <= end for value in dates):
            continue
        lowered = text.casefold()
        if not any(term in lowered for term in ("version", "support", "retirement", "listing", "windows")):
            continue
        matched_products = _extract_products(text, product)
        components = infer_components(text)
        event_date = min(value for value in dates if start <= value <= end)
        events.append(Event(
            event_id=f"lifecycle:{source_id}:{stable_hash(text)[:24]}",
            title=f"Lifecycle milestone: {row[0] if row else product}",
            event_type="lifecycle",
            status="confirmed",
            source_id=source_id,
            source_tier="P0",
            source_url=url,
            published_at=event_date.isoformat(),
            updated_at=event_date.isoformat(),
            products=matched_products,
            roles=infer_roles(matched_products, components),
            components=components,
            summary=text[:700],
            evidence=text[:1000],
            recommended_action="与内部镜像清单对照，并为受影响版本安排升级或退役计划。",
            risk_score=45 if any(term in lowered for term in ("end", "retirement")) else 30,
            confidence=96,
            raw_hash=raw_hash,
        ))
    return events


class LifecycleCollector:
    source_id = "lifecycle"

    def collect(self, context: CollectorContext, start: date, end: date, config: Dict[str, object]) -> SourceResult:
        result = SourceResult(self.source_id)
        for page in config.get("lifecycle", []):
            page_id = str(page["id"])
            try:
                raw = context.fetch(self.source_id, str(page["url"]), "text/html")
            except FetchError as exc:
                result.warnings.append(f"{page_id}: {exc}")
                continue
            result.documents.append(raw)
            result.events.extend(parse_lifecycle(
                raw.body.decode("utf-8", errors="replace"), page_id, str(page["url"]),
                str(page["product"]), start, end, raw.sha256,
            ))
        if not result.documents:
            raise RuntimeError("all Microsoft Lifecycle pages failed")
        return result


def _xml_locs(xml_body: bytes) -> List[Tuple[str, Optional[str]]]:
    root = ET.fromstring(xml_body)
    namespace = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    values = []
    for node in root:
        location = node.findtext(f"{namespace}loc")
        modified = node.findtext(f"{namespace}lastmod")
        if location:
            values.append((location.strip(), modified.strip() if modified else None))
    return values


def parse_insider_sitemap(xml_body: bytes, start: date, end: date, raw_hash: str) -> List[Event]:
    events: List[Event] = []
    for url, modified in _xml_locs(xml_body):
        match = re.search(r"/windows-insider/(20\d{2})/(\d{2})/(\d{2})/([^/]+)/?", url)
        if not match:
            continue
        published = date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
        modified_date = parse_date(modified)
        if not (start <= published <= end or (modified_date and start <= modified_date <= end)):
            continue
        title = clean_text(match.group(4).replace("-", " ")).title()
        products = _extract_products(title, "Windows 11 preview")
        components = infer_components(title)
        events.append(Event(
            event_id=f"insider:{hashlib.sha256(url.encode('utf-8')).hexdigest()[:24]}",
            title=title,
            event_type="feature preview",
            status="reported",
            source_id="windows-insider-sitemap",
            source_tier="P1",
            source_url=url,
            published_at=published.isoformat(),
            updated_at=modified,
            products=products,
            roles=infer_roles(products, components),
            components=components,
            summary="从 Windows 预览体验计划官方站点地图发现。文章正文需要后续浏览器补充抓取和核验。",
            evidence=f"官方站点地图条目；最后修改时间：{modified or '未提供'}。",
            recommended_action="先作为预警线索跟踪；若涉及内部云桌面组件，再补充正文核验和专项测试。",
            risk_score=risk_score(title, products, components, preview=True),
            confidence=72,
            preview=True,
            raw_hash=raw_hash,
        ))
    return events


class InsiderCollector:
    source_id = "windows-insider"

    def collect(self, context: CollectorContext, start: date, end: date, config: Dict[str, object]) -> SourceResult:
        result = SourceResult(self.source_id)
        index_url = str(config["insider_sitemap"])
        index = context.fetch(self.source_id, index_url, "application/xml,text/xml")
        result.documents.append(index)
        child_urls = [url for url, _ in _xml_locs(index.body) if "post-sitemap" in url]
        for url in child_urls:
            raw = context.fetch(self.source_id, url, "application/xml,text/xml")
            result.documents.append(raw)
            result.events.extend(parse_insider_sitemap(raw.body, start, end, raw.sha256))
        if not child_urls:
            result.warnings.append("No post sitemap was found in the Windows Insider sitemap index")
        return result


COLLECTORS = {
    "msrc": MsrcCollector(),
    "release-health": ReleaseHealthCollector(),
    "lifecycle": LifecycleCollector(),
    "windows-insider": InsiderCollector(),
}
