import json
from io import StringIO
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.feishu import (  # noqa: E402
    FeishuClient, FeishuConfigurationError,
    FeishuSettings,
    alert_fingerprint,
    build_publish_plan,
    event_fingerprint,
    event_to_fields,
    load_env_file,
    publish_events,
)
from osintel.feishu_wizard import (  # noqa: E402
    load_event_field_definitions, mask_value, parse_base_location, run_interactive,
)


def sample_event(event_id="test:1", alert_level="正式告警"):
    return {
        "event_id": event_id,
        "title": "Remote Desktop regression",
        "event_type": "known issue",
        "status": "reported",
        "source_id": "release-health",
        "source_tier": "P0",
        "source_url": "https://example.test/windows-risk",
        "publisher": "Microsoft",
        "published_at": "2026-09-01",
        "updated_at": "2026-09-02",
        "products": ["Windows 11 Version 24H2"],
        "editions": ["not specified"],
        "builds": ["26100"],
        "roles": ["guest"],
        "components": ["RDP"],
        "change_kinds": ["behavior change"],
        "preconditions": ["managed environment"],
        "affected_workflows": ["desktop provisioning"],
        "symptoms": ["operation blocked"],
        "correlation_keys": ["component:RDP"],
        "identifiers": {"kb": ["KB0000000"]},
        "summary": "Source summary",
        "evidence": "Source evidence",
        "recommended_action": "Source action",
        "risk_score": 90,
        "environment_relevance": 85,
        "action_priority": 88,
        "confidence": 95,
        "corroboration_count": 1,
        "alert_level": alert_level,
        "authoritative_evidence": True,
        "preview": False,
        "raw_hash": "abc",
    }


class FakeClient:
    def __init__(self, existing=None, send_alerts=True):
        self.settings = FeishuSettings(
            enabled=True,
            api_base="https://open.feishu.cn/open-apis",
            app_id="hidden",
            app_secret="hidden",
            base_token="hidden",
            events_table_id="hidden",
            alert_chat_id="hidden",
            send_alerts=send_alerts,
            alert_levels=("正式告警", "调查预警"),
            max_alerts_per_run=20,
            batch_size=200,
            timeout_seconds=30,
        )
        self.existing = existing or []
        self.created = []
        self.updated = []
        self.messages = []

    def validate_event_table(self, required_fields):
        self.required_fields = list(required_fields)

    def list_event_records(self):
        return self.existing

    def batch_create(self, fields):
        self.created.extend(fields)
        return [f"record-{index}" for index in range(len(fields))]

    def batch_update(self, records):
        self.updated.extend(records)

    def send_text(self, chat_id, text, idempotency_key):
        self.messages.append((chat_id, text, idempotency_key))
        return "message-1"

    def send_card(self, chat_id, card, idempotency_key):
        self.messages.append((chat_id, card, idempotency_key))
        return "message-1"

    def event_record_url(self, record_id):
        return f"https://example.feishu.cn/base/example?record={record_id}"


class FeishuTests(unittest.TestCase):
    def test_example_config_loads_without_remote_values_for_dry_run(self):
        path = ROOT / "config/feishu.example.json"
        settings = FeishuSettings.load(path, environ={}, require_remote=False)
        self.assertFalse(settings.enabled)
        self.assertEqual(200, settings.batch_size)
        self.assertEqual("", settings.app_secret)

    def test_remote_mode_requires_enabled_and_runtime_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "feishu.json"
            payload = json.loads((ROOT / "config/feishu.example.json").read_text(encoding="utf-8"))
            payload["enabled"] = True
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(FeishuConfigurationError) as context:
                FeishuSettings.load(path, environ={}, require_remote=True)
        self.assertIn("应用密钥", str(context.exception))
        self.assertNotIn("FEISHU_APP_SECRET=", str(context.exception))

    def test_mapping_is_chinese_and_does_not_expose_source_action(self):
        event = sample_event()
        fields = event_to_fields(event, synced_at="2026-09-06T00:00:00+00:00")
        self.assertEqual(event["event_id"], fields["事件编号"])
        self.assertIn("已知问题", fields["中文标题"])
        self.assertEqual("已知问题", fields["事件类型"])
        self.assertEqual("已报告", fields["当前状态"])
        self.assertEqual("来宾系统", fields["云桌面角色"])
        self.assertEqual("行为变化", fields["变化类型"])
        self.assertIn("核对关联", fields["建议动作"])
        self.assertNotIn(event["recommended_action"], fields["建议动作"])
        self.assertEqual(event_fingerprint(event), fields["内容指纹"])
        self.assertTrue(fields["权威证据"])
        self.assertTrue(fields["事实指纹"].startswith("fact-v2:"))
        self.assertTrue(fields["证据编号"].startswith("evidence:"))

    def test_plan_is_idempotent_but_retries_an_unsent_alert(self):
        event = sample_event()
        existing = [{
            "record_id": "record-1",
            "fields": {
                "事件编号": event["event_id"],
                "内容指纹": event_fingerprint(event),
                "最近告警指纹": "",
            },
        }]
        plan = build_publish_plan([event], existing, ["正式告警"])
        self.assertEqual(0, len(plan["creates"]))
        self.assertEqual(0, len(plan["updates"]))
        self.assertEqual(1, plan["unchanged"])
        self.assertEqual(1, len(plan["alerts"]))

        existing[0]["fields"]["最近告警指纹"] = alert_fingerprint(event)
        plan = build_publish_plan([event], existing, ["正式告警"])
        self.assertEqual(0, len(plan["alerts"]))

        existing[0]["fields"]["告警状态"] = "发送中"
        plan = build_publish_plan([event], existing, ["正式告警"])
        self.assertEqual(1, len(plan["alerts"]))

    def test_assessment_wording_change_does_not_invalidate_alert_fingerprint(self):
        event = sample_event()
        original_alert = alert_fingerprint(event)
        original_record = event_fingerprint(event)
        event["recommended_action"] = "新的展示建议"
        event["risk_score"] = 91
        self.assertEqual(original_alert, alert_fingerprint(event))
        self.assertNotEqual(original_record, event_fingerprint(event))

    def test_fact_change_invalidates_alert_fingerprint(self):
        event = sample_event()
        original = alert_fingerprint(event)
        event["status"] = "resolved"
        self.assertNotEqual(original, alert_fingerprint(event))

    def test_publish_creates_updates_and_marks_sent_alerts(self):
        changed = sample_event("test:changed")
        created = sample_event("test:new")
        existing = [{
            "record_id": "record-existing",
            "fields": {
                "事件编号": changed["event_id"],
                "内容指纹": "old",
                "最近告警指纹": "old",
            },
        }]
        client = FakeClient(existing)
        result = publish_events(client, [changed, created])
        self.assertEqual(1, result["待新增"])
        self.assertEqual(1, result["待更新"])
        self.assertEqual(2, result["已发送告警"])
        self.assertEqual(1, len(client.created))
        self.assertEqual(2, len(client.messages))
        self.assertIsInstance(client.messages[0][1], dict)
        self.assertIn("在 Base 中处理", json.dumps(client.messages[0][1], ensure_ascii=False))
        marked = [fields for _, fields in client.updated if "最近告警指纹" in fields]
        self.assertEqual(4, len(marked))
        self.assertEqual(2, sum(fields["告警状态"] == "发送中" for fields in marked))
        self.assertEqual(2, sum(fields["告警状态"] == "已发送" for fields in marked))

    def test_publish_without_alerts_marks_historical_alerts_suppressed(self):
        client = FakeClient(send_alerts=False)
        result = publish_events(client, [sample_event()])
        self.assertEqual(0, result["已发送告警"])
        self.assertEqual(1, result["已抑制告警"])
        self.assertEqual(0, len(client.messages))
        marked = [fields for _, fields in client.updated if "最近告警指纹" in fields]
        self.assertEqual(1, len(marked))
        self.assertEqual("已抑制", marked[0]["告警状态"])

    def test_dry_run_never_calls_remote_client(self):
        class NoRemoteClient(FakeClient):
            def list_event_records(self):
                raise AssertionError("演练模式不应连接飞书")

        result = publish_events(NoRemoteClient(), [sample_event()], dry_run=True)
        self.assertTrue(result["演练模式"])
        self.assertEqual(1, result["待新增"])

    def test_bulk_alert_guard_stops_before_writes(self):
        client = FakeClient()
        client.settings.max_alerts_per_run = 1
        with self.assertRaises(FeishuConfigurationError):
            publish_events(client, [sample_event("test:1"), sample_event("test:2")])
        self.assertEqual([], client.created)
        self.assertEqual([], client.updated)
        self.assertEqual([], client.messages)

    def test_current_base_api_request_shapes(self):
        class CapturingClient(FeishuClient):
            def __init__(self, settings):
                super().__init__(settings)
                self.calls = []

            def _request(self, method, path, body=None, query=None, authenticated=True):
                self.calls.append((method, path, body, query))
                if path.endswith("/records"):
                    return {"code": 0, "data": {"records": [], "has_more": False}}
                if path.endswith("/fields"):
                    return {"code": 0, "data": {"fields": [{"field_name": "事件编号"}], "has_more": False}}
                if path.endswith("/batch_create"):
                    return {"code": 0, "data": {"record_id_list": ["record-1"]}}
                return {"code": 0, "data": {}}

        settings = FakeClient().settings
        client = CapturingClient(settings)
        self.assertEqual([], client.list_event_records())
        client.validate_event_table(["事件编号"])
        self.assertEqual(["record-1"], client.batch_create([{"事件编号": "test"}]))
        client.batch_update([("record-1", {"内容指纹": "hash"})])
        client.send_card("chat-1", {"header": {"title": "测试"}}, "idempotency-key")
        paths = [call[1] for call in client.calls]
        self.assertTrue(all(path.startswith("base/v3/bases/") for path in paths[:4]))
        self.assertEqual("im/v1/messages", paths[4])
        self.assertEqual({"create_records": [{"事件编号": "test"}]}, client.calls[2][2])
        self.assertEqual(
            {"update_records": {"record-1": {"内容指纹": "hash"}}},
            client.calls[3][2],
        )
        self.assertEqual("interactive", client.calls[4][2]["msg_type"])
        self.assertEqual({"receive_id_type": "chat_id"}, client.calls[4][3])

    def test_field_creation_uses_current_base_api_shape(self):
        class CapturingClient(FeishuClient):
            def __init__(self, settings):
                super().__init__(settings)
                self.calls = []

            def _request(self, method, path, body=None, query=None, authenticated=True):
                self.calls.append((method, path, body, query))
                return {"code": 0, "data": {}}

        client = CapturingClient(FakeClient().settings)
        created = client.create_fields([
            {"name": "原文链接", "type": "text", "style": {"type": "url"}},
        ])
        self.assertEqual(["原文链接"], created)
        self.assertEqual("POST", client.calls[0][0])
        self.assertTrue(client.calls[0][1].endswith("/fields"))
        self.assertEqual("url", client.calls[0][2]["style"]["type"])

    def test_local_env_round_trip_and_permissions(self):
        from osintel.feishu import write_env_file

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / ".env"
            path.write_text("KEEP=value\nFEISHU_APP_ID=old\n", encoding="utf-8")
            write_env_file(path, {"FEISHU_APP_ID": "new", "FEISHU_APP_SECRET": "secret"})
            values = load_env_file(path, environ={})
            mode = os.stat(path).st_mode & 0o777
        self.assertEqual("value", values["KEEP"])
        self.assertEqual("new", values["FEISHU_APP_ID"])
        self.assertEqual("secret", values["FEISHU_APP_SECRET"])
        self.assertEqual(0o600, mode)

    def test_base_url_parser_and_masking(self):
        token, table_id = parse_base_location(
            "https://example.feishu.cn/base/base_placeholder?table=table_placeholder&view=view_placeholder"
        )
        self.assertEqual("base_placeholder", token)
        self.assertEqual("table_placeholder", table_id)
        self.assertEqual("abcd…wxyz", mask_value("abcdefghijklmnopwxyz"))

    def test_schema_uses_current_url_field_shape(self):
        definitions = load_event_field_definitions(ROOT / "config/feishu-schema.json")
        link = next(item for item in definitions if item["name"] == "原文链接")
        self.assertEqual("text", link["type"])
        self.assertEqual("url", link["style"]["type"])

    def test_interactive_wizard_can_stop_after_local_preview(self):
        with tempfile.TemporaryDirectory() as folder:
            workspace = Path(folder)
            events_path = workspace / "data/normalized/events.ndjson"
            events_path.parent.mkdir(parents=True)
            events_path.write_text(json.dumps(sample_event(), ensure_ascii=False) + "\n", encoding="utf-8")
            answers = iter(["n"])
            output = StringIO()
            result = run_interactive(
                workspace,
                input_fn=lambda _: next(answers),
                secret_fn=lambda _: "",
                output=output,
            )
            local_config = workspace / "skills/windows-os-intelligence/config/feishu.local.json"
            self.assertFalse(local_config.exists())
        self.assertEqual(0, result)
        self.assertIn("本地预览", output.getvalue())


if __name__ == "__main__":
    unittest.main()
