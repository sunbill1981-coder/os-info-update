from pathlib import Path
from html.parser import HTMLParser
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.model import Event  # noqa: E402
from osintel.guidance import build_cloud_desktop_guidance  # noqa: E402
from osintel.report import _html_event_card, _html_verification, write_run_html, write_run_report  # noqa: E402
from osintel.patches import phase_tests  # noqa: E402
from osintel.triage import build_triage  # noqa: E402


class DisclosureInspector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack = []
        self.nodes = []
        self.visible_text = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        self.nodes.append((tag, attributes, [node[1].get("class", "") for node in self.stack if node[0] == "details"]))
        self.stack.append((tag, attributes))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        hidden = any(
            tag == "details" and "open" not in attrs
            and not any(child[0] == "summary" for child in self.stack[index + 1:])
            for index, (tag, attrs) in enumerate(self.stack)
        )
        if not hidden:
            self.visible_text.append(data)


class ReportTests(unittest.TestCase):
    def test_source_review_action_text_is_escaped_and_links_are_safe(self):
        value = '<script>alert("action")</script>'
        page = _html_verification({
            "status": "待补外部证据", "owner": "情报分析", "first_action": value,
            "scope": [value], "steps": [value], "record": [value],
            "decisions": [{"when": value, "then": value}], "missing_inputs": [value],
            "basis": [{"label": value, "url": "javascript:alert(1)"}],
        })
        self.assertNotIn("<script>", page)
        self.assertNotIn('href="javascript:', page)
        self.assertIn("&lt;script&gt;", page)

    def test_action_plan_survives_into_digest_and_detail_without_becoming_a_fact(self):
        event = Event(
            event_id="reviewed:profile", title="已有配置文件登录异常", event_type="known issue",
            status="mitigated", source_id="release-health", source_tier="P0",
            source_url="https://example.test/profile", authoritative_evidence=True,
            products=["Windows 11, version 24H2"], builds=["26100.123"],
            components=["FSLogix/profile"], affected_workflows=["文件与配置文件访问"],
            symptoms=["显示或桌面加载异常"], published_at="2026-09-20",
            evidence="Existing user profiles can encounter a blank desktop after sign-in.",
            evidence_review={"source_kind": "official", "proof_state": "官方说明"},
        )
        fact_hash = event.fact_hash()
        event.evidence_review["verification_plan"] = {
            "schema": "verification-plan-v1", "status": "待核对内部范围",
            "owner": "产品研发或测试", "scope_verified": True, "scope_basis": "已核验来源中的配置文件条件。",
            "first_action": "记录代表性桌面的配置文件组件版本及更新前后 Build。",
            "scope": ["Windows 11 24H2；已有用户配置文件"],
            "steps": ["在隔离桌面使用同一账户分别登录已有和新建配置文件，记录桌面是否加载。"],
            "record": ["两组 Build、配置文件状态、登录结果和事件日志。"],
            "decisions": [{"when": "已有配置文件失败且新建配置文件成功", "then": "附两组日志建立复现记录；原因仍待调查。"}],
            "missing_inputs": ["内部是否使用该配置文件组件"],
            "basis": [{"label": "公开触发条件", "url": event.source_url}], "executed": False,
        }
        triage = build_triage([event], run_at="2026-10-02T00:00:00Z")
        with tempfile.TemporaryDirectory() as folder:
            html_path, md_path = Path(folder) / "report.html", Path(folder) / "report.md"
            write_run_html(html_path, ROOT / "assets/report-template.html", 1, "rolling", "2026-09-01", "2026-09-30",
                           [event], {}, [], [], triage=triage)
            write_run_report(md_path, 1, "rolling", "2026-09-01", "2026-09-30", [event], {}, [], [], 10, triage=triage)
            page, markdown = html_path.read_text(), md_path.read_text()
        self.assertEqual(fact_hash, event.fact_hash())
        self.assertEqual(2, page.count('class="verification-plan"'))
        for output in [page, markdown]:
            for key in ["first_action", "steps", "record"]:
                value = event.evidence_review["verification_plan"][key]
                self.assertIn(value if isinstance(value, str) else value[0], output)
            self.assertIn("已有配置文件失败且新建配置文件成功", output)
        self.assertNotIn(triage["queue"][0]["questions"][0], page)
        self.assertIn('class="extended-guidance"', page)

    def test_sparse_clue_stops_at_evidence_verification_in_both_output_formats(self):
        event = Event(
            event_id="sparse", title="Sparse authentication clue", event_type="compatibility",
            status="reported", source_id="external-signal", source_tier="P3",
            source_url="https://example.test/sparse", components=["authentication"],
            affected_workflows=["身份认证与登录"], symptoms=["认证或授权失败"], evidence="",
        )
        guidance = build_cloud_desktop_guidance(event)
        self.assertEqual(1, len(guidance.recommended_tests))
        self.assertIn("先取得原文", guidance.recommended_tests[0])
        self.assertNotIn("暂停扩大面积推送", "".join(guidance.preventive_actions))
        with tempfile.TemporaryDirectory() as folder:
            html_path, md_path = Path(folder) / "report.html", Path(folder) / "report.md"
            write_run_html(html_path, ROOT / "assets/report-template.html", 1, "rolling", "2026-09-01", "2026-09-30", [event], {}, [], [])
            write_run_report(md_path, 1, "rolling", "2026-09-01", "2026-09-30", [event], {}, [], [], 10)
            for page in (html_path.read_text(), md_path.read_text()):
                self.assertNotIn("SSO/MFA", page)
                self.assertNotIn("暂停扩大面积推送", page)
                self.assertIn("先取得原文", page)

    def test_feature_fact_does_not_invent_an_outage(self):
        event = Event(
            event_id="feature", title="新显示功能线索", event_type="feature", status="reported",
            source_id="external-signal", source_tier="P3", source_url="https://example.test/feature",
            components=["GPU/display"], change_kinds=["新功能"], affected_workflows=["图形与显示"],
            summary="下一版本新增可选显示 API，默认关闭，没有报告故障。",
            evidence="The next release introduces an optional display API, disabled by default. No fault is reported.",
        )
        guidance = build_cloud_desktop_guidance(event)
        self.assertIn(event.summary, guidance.problem_summary)
        self.assertNotIn("可能出现功能或可用性异常", guidance.problem_summary)
        self.assertNotIn("暂停扩大面积推送", "".join(guidance.preventive_actions))
        event.event_type = "vulnerability"
        event.change_kinds = ["安全机制收紧"]
        event.title = "Display remote code execution vulnerability"
        event.summary = "Security hardening resolves a remote code execution vulnerability."
        self.assertIn("安全漏洞", build_cloud_desktop_guidance(event).problem_summary)
        self.assertNotIn("特性或行为变化线索", build_cloud_desktop_guidance(event).problem_summary)

    def test_digest_is_bounded_but_overflow_and_full_inventory_remain_accessible(self):
        events = [Event(
            event_id=f"test:{index}", title="用户报告远程会话中断", event_type="known issue",
            status="reported", source_id="microsoft-qa", source_tier="P3",
            source_url=f"https://example.test/{index}", components=["RDP"],
            symptoms=["连接中断"], evidence="A user reports interrupted sessions under the stated conditions.",
        ) for index in range(5)]
        before = [event.payload() for event in events]
        triage = build_triage(events, run_at="2026-10-02T00:00:00Z", config={"display_budget": 2})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.html"
            write_run_html(path, ROOT / "assets/report-template.html", 1, "rolling", "2026-09-01", "2026-09-30",
                           events, {}, [], [], triage=triage)
            page = path.read_text()
        parsed = DisclosureInspector()
        parsed.feed(page)
        self.assertEqual(2, page.count('class="triage-card"'))
        self.assertEqual(5, page.count('class="event-card '))
        visible = "".join(parsed.visible_text)
        self.assertIn("高关注 3 条", visible)
        self.assertIn("故障与兼容性线索", visible)
        self.assertIn("尚未自动调度", visible)
        for tag, attributes, ancestors in parsed.nodes:
            if "event-card" in attributes.get("class", "").split():
                self.assertIn("reference-catalog", ancestors)
        self.assertEqual(before, [event.payload() for event in events])

    def test_unverified_application_failure_is_not_promoted_to_microsoft_confirmation(self):
        event = Event(
            event_id="signal:app", title="Fabrikam Viewer might fail to launch on ARM devices",
            event_type="known issue", status="reported", source_id="external-signal", source_tier="P3",
            source_url="https://example.test/app", evidence="A user says the app fails to launch on ARM devices.",
        )
        summary = build_cloud_desktop_guidance(event).problem_summary
        self.assertNotIn("微软已", summary)
        self.assertIn("待独立核验", summary)

    def test_disclosure_keeps_decision_content_visible_and_evidence_collapsed(self):
        event = Event(
            event_id="layout:sample", title="Remote Desktop Services issue",
            event_type="known issue", status="mitigated", source_id="release-health",
            source_tier="P0", source_url="https://example.test/health#sample",
            products=["Windows 11 Version 24H2", "Windows Server 2022"],
            components=["RDS", "GPU/display", "authentication"], roles=["guest"],
            identifiers={"kb": ["KB5000001", "KB5000002"]},
            risk_score=82, environment_relevance=65, confidence=97, action_priority=78,
            update_details=[{
                "relationship": "update_regression", "products": ["Windows Server 2022"],
                "introduced_kb": ["KB5000001"], "fixed_kb": ["KB5000002"],
                "fix_scope": "partial", "source_url": "https://example.test/server#sample",
                "conditions": ["Windows 远程桌面服务（RDS）"],
            }],
        ).normalized()
        before = (event.payload(), event.fact_hash(), event.assessment_hash())
        text = _html_event_card(event, 1, set())
        parsed = DisclosureInspector()
        parsed.feed(text)
        visible = "".join(parsed.visible_text)
        for heading in ("公开事实摘要", "适用性判断", "对云桌面的潜在影响", "建议测试", "预防与上线门禁", "针对性探索"):
            self.assertIn(heading, visible)
        self.assertIn("部分修复", visible)
        self.assertIn("当前镜像补丁状态：待核对", visible)
        for stage, action in phase_tests(event):
            self.assertIn(stage, visible)
            self.assertIn(action, visible)
        details = [attrs for tag, attrs, _ in parsed.nodes if tag == "details"]
        self.assertEqual({"patch-details", "scope-details", "evidence-details"}, {attrs["class"] for attrs in details})
        self.assertTrue(all("open" not in attrs for attrs in details))
        self.assertTrue(all("patch-details" in parents for tag, _, parents in parsed.nodes if tag == "table"))
        phase_nodes = [parents for _, attrs, parents in parsed.nodes if attrs.get("class") == "phase-tests"]
        self.assertEqual([[]], phase_nodes)
        self.assertNotIn("资产队列", text)
        self.assertIn("Windows 11 版本 24H2", text)
        self.assertIn("KB5000002", text)
        self.assertIn("https://example.test/server#sample", text)
        self.assertEqual(before, (event.payload(), event.fact_hash(), event.assessment_hash()))

    def test_empty_baselines_get_one_report_notice_without_repeated_empty_columns(self):
        events = [Event(event_id=str(index), title="Issue", event_type="known issue", status="reported",
                        source_id="release-health", source_tier="P0", source_url="https://example.test/issue")
                  for index in range(2)]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.html"
            write_run_html(path, ROOT / "assets/report-template.html", 8, "backfill", "2026-09-01", "2026-09-30",
                           events, {}, [], [], {"asset_groups": []})
            text = path.read_text()
            self.assertEqual(1, text.count("尚未配置具体验证基线"))
            self.assertNotIn("未命中已配置资产队列", text)
            write_run_html(path, ROOT / "assets/report-template.html", 8, "backfill", "2026-09-01", "2026-09-30",
                           events, {}, [], [], {"asset_groups": [{"name": "基线 A"}]})
            self.assertNotIn("尚未配置具体验证基线", path.read_text())

    def test_html_report_is_self_contained_and_every_conclusion_has_direct_sources(self):
        event = Event(
            event_id="release-health:123msgdesc", title="Remote Desktop issue",
            event_type="known issue", status="investigating", source_id="release-health",
            source_tier="P0", source_url="https://example.test/health#123msgdesc",
            products=["Windows 11 Version 24H2"], components=["RDP"],
            identifiers={"kb": ["KB5000000"]}, risk_score=82, confidence=97,
            action_priority=76, source_references=[
                {"page_id": "win11-24h2", "url": "https://example.test/24h2#123msgdesc", "raw_hash": "one"},
                {"page_id": "server-2025", "url": "https://example.test/server#123msgdesc", "raw_hash": "two"},
            ],
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.html"
            template = ROOT / "assets/report-template.html"
            write_run_html(
                path, template, 7, "rolling", "2026-09-01", "2026-09-30", [event],
                {"new": 1, "new_ids": [event.event_id]}, ["测试源：<script>alert(1)</script>"], [],
            )
            text = path.read_text(encoding="utf-8")
        self.assertIn("<!doctype html>", text)
        self.assertIn("公开事实摘要", text)
        self.assertIn("对云桌面的潜在影响", text)
        self.assertIn("建议测试", text)
        self.assertIn("预防与上线门禁", text)
        self.assertIn("针对性探索", text)
        self.assertIn("工程推演 · 需验证", text)
        self.assertIn("直达原文", text)
        self.assertIn("触发依据", text)
        self.assertIn("https://example.test/24h2#123msgdesc", text)
        self.assertIn("https://example.test/server#123msgdesc", text)
        self.assertIn('rel="noopener noreferrer"', text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", text)
        self.assertNotIn("{{", text)

    def test_human_report_localizes_source_text(self):
        event = Event(
            event_id="msrc:CVE-2026-12345",
            title="Remote Desktop Client Remote Code Execution Vulnerability",
            event_type="vulnerability",
            status="confirmed",
            source_id="msrc",
            source_tier="P0",
            source_url="https://example.test/CVE-2026-12345",
            products=["Windows 11 Version 24H2"],
            roles=["guest", "host"],
            components=["RDP"],
            identifiers={"cve": ["CVE-2026-12345"], "kb": [], "build": []},
            summary="Critical; CVSS 9.8; Remote Code Execution",
            recommended_action="English action must not be displayed.",
            update_details=[{
                "kb": ["KB5099999"], "fixed_build": "26100.9999",
                "supercedence": "KB5098888", "restart_required": "Yes",
            }],
            risk_score=90,
            confidence=98,
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.md"
            write_run_report(path, 1, "backfill", "2026-08-01", "2026-08-31", [event], {"new": 1}, [], [], 25)
            text = path.read_text(encoding="utf-8")
        self.assertIn("历史回填", text)
        self.assertIn("远程桌面协议（RDP）远程代码执行漏洞", text)
        self.assertIn("可能导致远程代码执行", text)
        self.assertIn("来宾系统、宿主机", text)
        self.assertIn("技术风险 90", text)
        self.assertIn("环境相关度", text)
        self.assertIn("处置优先级", text)
        self.assertIn("Windows 11 版本 24H2", text)
        self.assertIn("补丁关系：KB5099999，修复 Build 26100.9999，取代 KB5098888，重启要求 需要", text)
        self.assertNotIn("Version", text)
        self.assertNotIn(event.title, text)
        self.assertNotIn(event.summary, text)
        self.assertNotIn(event.recommended_action, text)

    def test_incremental_report_hides_unchanged_inventory(self):
        new_event = Event(
            event_id="new", title="New issue", event_type="known issue", status="reported",
            source_id="release-health", source_tier="P0",
            source_url="https://example.test/new", authoritative_evidence=True,
        )
        unchanged = Event(
            event_id="old", title="Old issue", event_type="lifecycle", status="confirmed",
            source_id="lifecycle", source_tier="P0",
            source_url="https://example.test/old", authoritative_evidence=True,
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "report.md"
            write_run_report(
                path, 2, "incremental", "2026-09-01", "2026-09-07",
                [new_event, unchanged],
                {"new": 1, "new_ids": ["new"], "unchanged": 1, "unchanged_ids": ["old"]},
                [], [], 25,
            )
            text = path.read_text(encoding="utf-8")
        self.assertIn("https://example.test/new", text)
        self.assertNotIn("https://example.test/old", text)
        self.assertIn("本轮新增", text)

    def test_guidance_translates_generic_dimensions_into_cloud_desktop_actions(self):
        event = Event(
            event_id="release-health:generic", title="Generic issue",
            event_type="known issue", status="investigating", source_id="release-health",
            source_tier="P0", source_url="https://example.test/issue",
            products=["Windows 11 Version 24H2"], roles=["guest", "directory"],
            components=["RDP", "authentication", "image/recovery"],
            affected_workflows=["桌面镜像与交付", "域加入与信任关系", "远程会话连接"],
            preconditions=["基于镜像或克隆部署"], symptoms=["认证或授权失败"],
            identifiers={"kb": ["KB5000000"]},
        )
        guidance = build_cloud_desktop_guidance(event)
        combined = "".join(
            [guidance.problem_summary, guidance.applicability]
            + guidance.potential_impacts + guidance.recommended_tests
            + guidance.preventive_actions + guidance.exploration_questions
        )
        self.assertIn("加域", combined)
        self.assertIn("重连", combined)
        self.assertIn("金镜像", combined)
        self.assertIn("回滚", combined)
        self.assertIn("不能断言已影响", guidance.applicability)
        self.assertNotIn("SID", combined)

    def test_product_portfolio_guidance_prioritizes_vdi_without_claiming_customer_impact(self):
        event = Event(
            event_id="portfolio:windows", title="Windows image issue",
            event_type="known issue", status="investigating", source_id="release-health",
            source_tier="P0", source_url="https://example.test/portfolio",
            products=["Windows 11 Version 24H2"], roles=["guest"],
            components=["image/recovery"], affected_workflows=["桌面镜像与交付"],
            environment_relevance=80,
        )
        environment = {
            "scope_type": "product_portfolio",
            "delivery_architectures": ["IDV", "VDI", "VAPP", "TCI/VOI"],
            "architecture_priorities": {"VDI": 100, "IDV": 80, "TCI/VOI": 75, "VAPP": 70},
        }
        guidance = build_cloud_desktop_guidance(event, environment)
        self.assertTrue(guidance.recommended_tests[0].startswith("原厂矩阵先在 VDI"))
        self.assertIn("VDI、IDV、TCI/VOI、VAPP", "".join(guidance.exploration_questions))
        self.assertIn("原厂产品验证范围", guidance.applicability)
        self.assertIn("不表示所有客户环境都已受影响", guidance.applicability)


if __name__ == "__main__":
    unittest.main()
