import json
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
    publish_events,
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
        self.assertIn("核对关联", fields["建议动作"])
        self.assertNotIn(event["recommended_action"], fields["建议动作"])
        self.assertEqual(event_fingerprint(event), fields["内容指纹"])

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
        marked = [fields for _, fields in client.updated if "最近告警指纹" in fields]
        self.assertEqual(2, len(marked))
        self.assertTrue(all(fields["告警状态"] == "已发送" for fields in marked))

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
        paths = [call[1] for call in client.calls]
        self.assertTrue(all(path.startswith("base/v3/bases/") for path in paths))
        self.assertEqual({"create_records": [{"事件编号": "test"}]}, client.calls[2][2])
        self.assertEqual(
            {"update_records": {"record-1": {"内容指纹": "hash"}}},
            client.calls[3][2],
        )


if __name__ == "__main__":
    unittest.main()
