"""Bounded discovery queue. Search is delegated to the invoking agent, not scraped."""
from __future__ import annotations

import argparse
import hashlib
from datetime import date
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from html import escape
import json
from pathlib import Path
import re
import time
from typing import Dict, List, Mapping, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser
import xml.etree.ElementTree as ET

from .http import HttpClient, HttpSettings
from .model import Event, RawDocument, SourceResult, parse_date, stable_hash, utc_now
from .parsers import clean_text
from .report import write_ndjson
from .scoring import extract_identifiers
from .signals import signal_event
from .store import Store


def canonical_url(value: str) -> str:
    parsed = urlsplit(value.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in {None, 443}:
        raise ValueError("发现来源必须使用无凭据的 HTTPS 公共地址")
    return urlunsplit(("https", parsed.hostname.lower(), parsed.path or "/", parsed.query, ""))


def source_for(url: str, config: Mapping[str, object]) -> Dict[str, object]:
    canonical = canonical_url(url)
    for source in config.get("sources", []):
        for prefix in source.get("prefixes", []):
            # Case-insensitive publisher paths accommodate legacy Citrix/Reddit links.
            if canonical.casefold().startswith(str(prefix).casefold()):
                return source
    raise ValueError("地址不在专项公告／社区来源白名单内")


class PageText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: List[str] = []
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript", "svg"}:
            self.ignored += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript", "svg"} and self.ignored:
            self.ignored -= 1

    def handle_data(self, data):
        if not self.ignored:
            self.parts.append(data)


def page_text(body: bytes) -> str:
    parser = PageText()
    parser.feed(body.decode("utf-8", errors="replace"))
    return clean_text(" ".join(parser.parts))


def read_records(path: Path) -> List[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def import_snapshot(record: dict, context, config: dict) -> dict:
    """Explicit exports from an allowed read tool/manual session, not a crawler bypass."""
    url = canonical_url(str(record.get("source_url") or ""))
    source = source_for(url, config)
    method = record.get("acquisition_method")
    if method not in {"manual-export", "authorized-tool-fulltext"} or not record.get("acquisition_note"):
        raise ValueError("导入须声明合规人工导出／授权工具正文获取及说明；搜索摘要不可导入")
    text = clean_text(str(record.get("text") or ""))
    if not 160 <= len(text) <= 1000000:
        raise ValueError("导入正文不足或超过大小预算")
    body = ("<html><main><pre>" + escape(text) + "</pre></main></html>").encode("utf-8")
    document = context.store.persist_document(RawDocument(source["id"], url, body, "text/html", utc_now()))
    return {"candidate_id": "candidate:" + stable_hash(url)[:24], "source_url": url,
            "source_id": source["id"], "source_kind": source["kind"],
            "title": record.get("title") or "标题待核验", "published_at": record.get("published_at"),
            "updated_at": record.get("updated_at"), "collected_at": document.fetched_at,
            "raw_hash": document.sha256, "raw_path": document.raw_path,
            "identifiers": extract_identifiers(text), "text": text, "review_state": "待核验",
            "date_state": "导入日期待正文核对", "acquisition_method": method,
            "acquisition_note": record["acquisition_note"]}


def build_plan(events: Sequence[dict], start: date, end: date, config: dict) -> dict:
    seeds: List[str] = []
    eligible = []
    for event in events:
        dates = [parse_date(event.get(key)) for key in ("published_at", "updated_at")]
        if any(value and start <= value <= end for value in dates):
            eligible.append(event)
    eligible.sort(key=lambda item: (-int(item.get("action_priority", 0)), item.get("event_id", "")))
    for event in eligible:
        identifiers = event.get("identifiers", {})
        for key in ("kb", "build"):
            for value in identifiers.get(key, []) or []:
                if str(value) not in seeds:
                    seeds.append(str(value))
    seeds = seeds[:6]
    # Round-robin sources so a budget cannot consume all queries on one KB/domain.
    queries = []
    for seed in seeds:
        for source in config["sources"]:
            queries.append({"source_id": source["id"], "query": "site:{} {} {}".format(
                source["search_domain"], seed, config["risk_intents"][len(queries) % len(config["risk_intents"])])})
    broad = [{"source_id": "workflow", "query": query} for query in config.get("workflow_queries", [])]
    maximum = int(config.get("max_queries", 24))
    queries = queries[:max(0, maximum - len(broad))] + broad[:maximum]
    return {"schema": "discovery-plan-v1", "created_at": utc_now(),
            "window": {"start": start.isoformat(), "end": end.isoformat()},
            "seeds": seeds, "queries": queries,
            "limits": {"max_candidates": config.get("max_candidates", 12)},
            "notice": "查询计划未执行搜索；由调用 Skill 的智能体检索原始页面，不将搜索摘要视作证据。"}


def feed_items(body: bytes) -> List[dict]:
    root = ET.fromstring(body)
    if root.tag.split("}")[-1] not in {"rss", "feed", "RDF"}:
        raise ValueError("返回内容不是 RSS／Atom，可能被拦截或解析器失效")
    entries = [node for node in root.iter() if node.tag.split("}")[-1] in {"item", "entry"}]
    result = []
    for entry in entries:
        fields = {node.tag.split("}")[-1]: node for node in entry}
        def value(key):
            node = fields.get(key)
            return "" if node is None else "".join(node.itertext()).strip()
        links = [node for node in entry if node.tag.split("}")[-1] == "link"]
        link = next((node.get("href") for node in links if node.get("href") and node.get("rel", "alternate") == "alternate"), None)
        link = link or value("link")
        published = value("published") or value("pubDate") or value("date")
        parsed = parse_date(published)
        if published and not parsed:
            try:
                parsed = parsedate_to_datetime(published).date()
            except (ValueError, TypeError, OverflowError):
                pass
        updated = parse_date(value("updated"))
        result.append({"source_url": link, "title": value("title"),
                       "published_at": parsed.isoformat() if parsed else None,
                       "updated_at": updated.isoformat() if updated else None})
    if not entries:
        raise ValueError("订阅未包含条目，无法证明来源覆盖正常")
    return result


class DiscoveryFetcher:
    """Fail closed on robots failures and disallowed redirects; never bypass blocking."""
    def __init__(self, context, config: dict):
        self.context, self.config = context, config
        self.robots: Dict[str, RobotFileParser] = {}

    def fetch(self, url: str, source_id: str, feed: bool = False):
        url = canonical_url(url)
        if feed:
            if not any(url == source.get("feed") for source in self.config["sources"]):
                raise ValueError("订阅地址不在配置白名单内")
        else:
            source_for(url, self.config)
        host = urlsplit(url).netloc
        def same_host(candidate):
            try:
                return urlsplit(canonical_url(candidate)).netloc == host
            except ValueError:
                return False
        def allowed(candidate):
            if not same_host(candidate):
                return False
            if feed:
                return canonical_url(candidate) == url
            try:
                return source_for(candidate, self.config)["id"] == source_id
            except ValueError:
                return False
        if host not in self.robots:
            robots_url = "https://" + host + "/robots.txt"
            try:
                robot_doc = self.context.http.fetch(source_id, robots_url, allowed_url=same_host, max_bytes=512000)
                robot = RobotFileParser()
                robot.parse(robot_doc.body.decode("utf-8", errors="replace").splitlines())
                self.robots[host] = robot
            except Exception as exc:
                raise ValueError("无法核对 robots.txt；停止自动采集，请使用合规授权路径：" + str(exc)) from exc
        agent = self.context.http.settings.user_agent.split("/", 1)[0]
        robot = self.robots[host]
        if not robot.can_fetch(agent, url):
            raise ValueError("robots.txt 不允许该自动访问；未尝试绕过")
        delay = max(float(self.config.get("request_interval_seconds", 1)), robot.crawl_delay(agent) or 0)
        if delay > 30:
            raise ValueError("来源要求的访问间隔超过单轮预算，请改用授权订阅")
        time.sleep(delay)
        document = self.context.http.fetch(source_id, url, allowed_url=allowed, max_bytes=2000000)
        return self.context.store.persist_document(document)


def collect_candidates(context, config: dict, start: date, end: date, targets: Sequence[dict], use_feeds: bool = True) -> dict:
    fetcher = DiscoveryFetcher(context, config)
    warnings, failures, queue, checked = [], [], list(targets), set()
    if use_feeds:
        for source in config["sources"]:
            if not source.get("feed"):
                continue
            checked.add(source["id"])
            try:
                document = fetcher.fetch(source["feed"], source["id"], feed=True)
                items = feed_items(document.body)
                known_dates = [parse_date(item["published_at"]) for item in items if item["published_at"]]
                warnings.append(source["name"] + "：订阅是有限近期列表，不代表历史时间段完整覆盖。")
                if not known_dates:
                    warnings.append(source["name"] + "：条目发布日期未解析，需人工核对时间范围。")
                # A recent community listing is not a search engine. Keep the body
                # budget for Windows/cloud-desktop candidates; workflow search covers
                # posts whose titles lack these generic terms.
                terms = config.get("candidate_terms", ["windows", "kb", "vdi", "citrix", "rdp", "fslogix", "hyper-v", "vmware", "authentication", "regression"])
                queue.extend(item for item in items if any(str(term).casefold() in item["title"].casefold() for term in terms))
            except Exception as exc:
                failures.append({"source_id": source["id"], "error": str(exc)})
    candidates, seen, attempts = [], set(), 0
    limit = int(config.get("max_candidates", 12))
    for item in queue:
        try:
            url = canonical_url(str(item.get("source_url") or ""))
            if url in seen:
                continue
            seen.add(url)
            dates = [parse_date(item.get(key)) for key in ("published_at", "updated_at")]
            if any(dates) and not any(value and start <= value <= end for value in dates):
                continue
            if attempts >= limit:
                warnings.append("达到正文采集预算，剩余条目未获取；不能将其解释为无风险。")
                break
            source = source_for(url, config)
            checked.add(source["id"])
            attempts += 1
            document = fetcher.fetch(url, source["id"])
            text = page_text(document.body)
            if len(text) < 160 or any(token in text.casefold() for token in ("verify you are human", "enable javascript and cookies", "you've been blocked")):
                raise ValueError("正文不足或页面被拦截，未将其计为成功证据")
            candidates.append({"candidate_id": "candidate:" + stable_hash(url)[:24],
                               "source_url": url, "source_id": source["id"], "source_kind": source["kind"],
                               "title": item.get("title") or "标题待核验", "published_at": item.get("published_at"),
                               "updated_at": item.get("updated_at"), "collected_at": document.fetched_at,
                               "raw_hash": document.sha256, "raw_path": document.raw_path,
                               "identifiers": extract_identifiers(text), "text": text,
                               "review_state": "待核验", "date_state": "已提供，待正文核对" if any(dates) else "发布日期待核对"})
        except Exception as exc:
            try:
                failed_id = source_for(str(item.get("source_url") or ""), config)["id"]
            except ValueError:
                failed_id = "专项正文"
            failures.append({"source_id": str(failed_id), "url": str(item.get("source_url") or ""), "error": str(exc)})
    return {"schema": "discovery-run-v1", "created_at": utc_now(), "window": {"start": start.isoformat(), "end": end.isoformat()},
            "candidates": candidates, "warnings": warnings, "failures": failures,
            "sources_checked": sorted(checked), "feeds_enabled": use_feeds,
            "status": "partial" if failures else "success"}


def verified_event(record: dict, context, config: dict) -> Event:
    url = canonical_url(str(record.get("source_url") or ""))
    source = source_for(url, config)
    document = context.store.cached_document(url)
    if document is None or record.get("raw_hash") != document.sha256 or hashlib.sha256(document.body).hexdigest() != document.sha256:
        raise ValueError("核验记录缺少一致的原文快照；先发现采集，再核对最新正文")
    quote = clean_text(str(record.get("evidence") or ""))
    text = page_text(document.body)
    if len(quote) < 30 or quote not in text:
        raise ValueError("证据摘录不在原文快照内，不能入库")
    if not record.get("reviewed_at") or not record.get("review_note"):
        raise ValueError("缺少人工／智能体正文核验时间或判断说明")
    # Dates are an explicit review responsibility; unknown dates do not silently enter a historical run.
    if not parse_date(record.get("published_at")):
        raise ValueError("发布日期未核验，不能进入时间范围报告")
    if not record.get("products") or not all(re.search(r"[\u4e00-\u9fff]", str(record.get(key) or "")) for key in ("summary", "title")):
        raise ValueError("需要有依据的产品范围、中文标题和中文事实摘要")
    if not record.get("claim_key"):
        raise ValueError("需要稳定的 claim_key 区分同页不同问题；改写摘录不能改变事件身份")
    event = signal_event(record)
    event.event_id = "discovery:" + stable_hash([url, record["claim_key"]])[:24]
    event.source_url, event.source_id, event.publisher = url, source["id"], source["name"]
    event.source_tier = source["tier"]
    event.authoritative_evidence = source["kind"] == "official"
    event.confidence = min(event.confidence, 90 if event.authoritative_evidence else 70)
    if event.authoritative_evidence:
        event.confidence = min(90, max(0, int(record.get("confidence", 75))))
    if source["kind"] == "community":
        # A poster claiming "confirmed" does not mean vendor or internal confirmation.
        event.status = "reported"
    if source["kind"] in {"official", "vendor"}:
        for detail in record.get("update_details", []):
            # Patch roles remain product-specific reviewer extraction. A merged KB
            # list or community speculation cannot become a supported fix chain.
            if canonical_url(str(detail.get("source_url") or "")) != url:
                raise ValueError("补丁关系必须引用本次核验原文；其它页面应另建证据")
            excerpt = clean_text(str(detail.get("evidence") or ""))
            if not excerpt or excerpt not in text:
                raise ValueError("补丁关系缺少可回查的原文摘录")
            event.update_details.append(dict(detail))
    origin = canonical_url(str(record.get("original_url") or url))
    source_for(origin, config)
    author = str(record.get("author") or "").strip()
    independent = bool(record.get("independent_observation") is True and author and record.get("independence_note") and origin == url)
    event.evidence_review = {
        "schema": "evidence-review-v1", "source_kind": source["kind"],
        "proof_state": {"official": "官方说明", "vendor": "厂商说明", "community": "用户报告"}[source["kind"]],
        "reviewed_at": record["reviewed_at"], "review_note": record["review_note"],
        "original_url": origin, "author": author,
        "independent_observation": independent,
        "independence_note": str(record.get("independence_note") or ""),
        "reproduction_note": str(record.get("reproduction_note") or "未独立复现"),
        "missing_evidence": list(record.get("missing_evidence") or []),
        "snapshot_hash": document.sha256,
    }
    return event.normalized()


class DiscoveryCollector:
    def collect(self, context, start: date, end: date, config: dict) -> SourceResult:
        settings = json.loads(Path(config["discovery_config"]).read_text(encoding="utf-8"))
        result = SourceResult("discovery")
        path = Path(config["discovery_reviewed_file"])
        latest_run = path.parent / "latest-run.json"
        if latest_run.exists():
            coverage = json.loads(latest_run.read_text(encoding="utf-8"))
            window = coverage.get("window", {})
            covered_start, covered_end = parse_date(window.get("start")), parse_date(window.get("end"))
            if covered_start and covered_end and covered_start <= end and covered_end >= start:
                result.warnings.extend(coverage.get("warnings", []))
                result.coverage_errors.extend("发现访问缺口：" + item.get("source_id", "") + "：" + item["error"] for item in coverage.get("failures", []))
                if len(coverage.get("candidates", [])):
                    result.warnings.append("待核验正文仍需人工／智能体筛选；未入报告不代表无风险。")
        if not path.exists():
            result.warnings.append("尚无已核验专项／社区记录；此来源不自动执行搜索或论坛采集。")
            return result
        for record in read_records(path):
            dates = [parse_date(record.get(key)) for key in ("published_at", "updated_at")]
            if any(dates) and not any(value and start <= value <= end for value in dates):
                continue
            try:
                result.events.append(verified_event(record, context, settings))
            except Exception as exc:
                result.coverage_errors.append(str(record.get("source_url", "")) + "：" + str(exc))
        return result


def run(argv: Optional[Sequence[str]] = None) -> int:
    workspace_default = Path(__file__).resolve().parents[4]
    class ChineseParser(argparse.ArgumentParser):
        def format_usage(self):
            return super().format_usage().replace("usage:", "用法:")

        def format_help(self):
            return super().format_help().replace("usage:", "用法:")

    parser = ChineseParser(description="生成通用发现查询，采集待核验正文；不自动宣称论坛问题已确认。", usage="%(prog)s [选项]", add_help=False)
    parser._optionals.title = "选项"
    parser.add_argument("-h", "--help", action="help", help="显示帮助并退出")
    parser.add_argument("--workspace", type=Path, default=workspace_default)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--plan-only", action="store_true", help="仅生成查询计划，不联网")
    parser.add_argument("--no-feeds", action="store_true", help="仅获取提供的原文地址")
    parser.add_argument("--urls-file", type=Path, help="搜索后选取的原文地址 NDJSON")
    parser.add_argument("--import-file", type=Path, help="合规人工导出／授权工具获取的原文文本 NDJSON，不接受搜索摘要")
    parser.add_argument("--config", type=Path)
    args = parser.parse_args(argv)
    start, end = parse_date(args.start), parse_date(args.end)
    if not start or not end or start > end:
        parser.error("请提供有效且顺序正确的起止日期")
    workspace = args.workspace.resolve()
    config = json.loads((args.config or workspace / "skills/windows-os-intelligence/config/discovery.json").read_text(encoding="utf-8"))
    folder = workspace / "data/discovery"
    folder.mkdir(parents=True, exist_ok=True)
    plan = build_plan(read_records(workspace / "data/normalized/events.ndjson"), start, end, config)
    (folder / "plan.json").write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    (folder / "plan.md").write_text("# 通用风险发现查询计划\n\n" + plan["notice"] + "\n\n" + "\n".join("- " + item["query"] for item in plan["queries"]) + "\n", encoding="utf-8")
    print("查询计划：" + str(folder / "plan.md"), flush=True)
    if args.plan_only:
        return 0
    from .sources import CollectorContext
    store = Store(workspace / "data/state/os-intel.sqlite3", workspace / "data/raw")
    # Short, bounded attempts for optional sources; do not stall the deterministic core.
    context = CollectorContext(HttpClient(HttpSettings(timeout_seconds=15, retries=0)), store)
    result = collect_candidates(context, config, start, end, read_records(args.urls_file) if args.urls_file else [], not args.no_feeds)
    imports = read_records(args.import_file) if args.import_file else []
    budget = int(config.get("max_candidates", 12))
    for record in imports[:budget]:
        try:
            result["candidates"].append(import_snapshot(record, context, config))
        except Exception as exc:
            result["failures"].append({"source_id": "正文导入", "error": str(exc)})
    if len(imports) > budget:
        result["warnings"].append("正文导入超过单轮预算，剩余导出未载入。")
    result["status"] = "partial" if result["failures"] else "success"
    failed_ids = {item["source_id"] for item in result["failures"]}
    for source_id in result["sources_checked"]:
        if source_id in failed_ids:
            errors = [item["error"] for item in result["failures"] if item["source_id"] == source_id]
            store.source_failure("discovery:" + source_id, "；".join(errors))
        else:
            # Health only, not a claim of full historical feed coverage.
            store.source_success("discovery:" + source_id, end.isoformat(), sum(item["source_id"] == source_id for item in result["candidates"]))
    existing = {item["candidate_id"]: item for item in read_records(folder / "candidates.ndjson")}
    history = []
    for item in result["candidates"]:
        prior = existing.get(item["candidate_id"])
        if not prior or prior["raw_hash"] != item["raw_hash"]:
            history.append(item)
        existing[item["candidate_id"]] = item
    write_ndjson(folder / "candidates.ndjson", existing.values())
    if history:
        with (folder / "history.ndjson").open("a", encoding="utf-8") as handle:
            for item in history:
                handle.write(json.dumps(item, ensure_ascii=False) + "\n")
    report = folder / "latest-run.json"
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    with (folder / "runs.ndjson").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({key: value for key, value in result.items() if key != "candidates"}, ensure_ascii=False) + "\n")
    lines = ["# 专项与社区发现结果", "", "正文候选 {} 条；访问失败 {} 项。尚未核验的候选不会进入正式风险报告。".format(len(result["candidates"]), len(result["failures"])), "", "## 待核验原文", ""]
    lines.extend("- [{}]({}) · {}".format(item["candidate_id"], item["source_url"], item["date_state"]) for item in result["candidates"])
    lines.extend(["", "## 覆盖缺口与限制", ""] + ["- " + value for value in result["warnings"]] + ["- " + item["source_id"] + "：" + item["error"] for item in result["failures"]])
    (folder / "latest-run.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("正文候选 {} 条；失败 {} 项。结果：{}".format(len(result["candidates"]), len(result["failures"]), folder / "latest-run.md"), flush=True)
    return 2 if result["failures"] else 0
