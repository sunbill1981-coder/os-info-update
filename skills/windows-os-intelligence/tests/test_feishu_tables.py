import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from osintel.feishu import FeishuSettings  # noqa: E402
from osintel.feishu_tables import (  # noqa: E402
    load_actions, load_applicability, load_changes, load_evidence, load_profile,
    load_runs, publish_supporting_tables, seed_records, sync_records,
)


class SupportingClient:
    def __init__(self, existing=None):
        self.settings = FeishuSettings(
            enabled=True, api_base="https://open.feishu.cn/open-apis",
            app_id="app", app_secret="secret", base_token="base",
            events_table_id="events", alert_chat_id="", send_alerts=False,
            alert_levels=("正式告警",), max_alerts_per_run=20,
            batch_size=2, timeout_seconds=30,
            evidence_table_id="evidence", profiles_table_id="profiles",
            changes_table_id="changes", runs_table_id="runs",
            applicability_table_id="applicability", actions_table_id="actions",
        )
        self.existing = existing or {}
        self.created = []
        self.updated = []

    def missing_fields(self, required_fields, table_id=None):
        return []

    def list_table_records(self, table_id):
        return self.existing.get(table_id, [])

    def batch_create(self, fields, table_id=None):
        self.created.extend((table_id, dict(value)) for value in fields)
        return [f"record-{index}" for index in range(len(fields))]

    def batch_update(self, records, table_id=None):
        self.updated.extend((table_id, record_id, dict(fields)) for record_id, fields in records)


def create_database(path):
    with sqlite3.connect(str(path)) as connection:
        connection.executescript(
            """
            CREATE TABLE events(event_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL);
            CREATE TABLE evidence(
                evidence_id TEXT PRIMARY KEY,event_id TEXT,source_id TEXT,source_tier TEXT,
                publisher TEXT,source_url TEXT,excerpt TEXT,raw_hash TEXT,raw_path TEXT,collected_at TEXT
            );
            CREATE TABLE runs(
                run_id INTEGER PRIMARY KEY,mode TEXT,window_start TEXT,window_end TEXT,
                started_at TEXT,finished_at TEXT,status TEXT,stats_json TEXT,error TEXT
            );
            CREATE TABLE event_changes(
                change_id INTEGER PRIMARY KEY,event_id TEXT,changed_at TEXT,prior_hash TEXT,
                new_hash TEXT,payload_json TEXT,change_type TEXT,changed_fields_json TEXT
            );
            """
        )
        payload = {
            "event_id": "event:1", "title": "风险", "event_type": "known issue",
            "status": "reported", "source_id": "source", "source_tier": "P0",
            "source_url": "https://example.test/source", "products": ["Windows 11, version 24H2"],
            "roles": ["guest"], "environment_relevance": 80, "alert_level": "正式告警",
            "authoritative_evidence": True,
            "published_at": "2026-09-01", "updated_at": "2026-09-02",
        }
        connection.execute("INSERT INTO events VALUES(?,?)", ("event:1", json.dumps(payload)))
        connection.execute(
            "INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("evidence:1", "event:1", "source", "P0", "微软", "https://example.test/source",
             "原文证据", "hash", "raw/path", "2026-09-03T00:00:00+00:00"),
        )
        connection.execute(
            "INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?)",
            (1, "incremental", "2026-09-01", "2026-09-02", "start", "finish", "success",
             json.dumps({"new": 1, "changed": 2, "sources_failed": 0}), None),
        )
        connection.execute(
            "INSERT INTO event_changes VALUES(?,?,?,?,?,?,?,?)",
            (1, "event:1", "2026-09-03", "old", "new", "{}", "fact_change",
             json.dumps(["status", "builds"])),
        )


class FeishuSupportingTableTests(unittest.TestCase):
    def test_loaders_keep_chinese_fields_and_source_index(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            database = root / "state.sqlite3"
            environment = root / "environment.json"
            create_database(database)
            environment.write_text(json.dumps({
                "profile_name": "生产云桌面", "products": ["Windows 11 24H2"],
                "roles": ["guest"], "workflow_criticality": {"加域": 90},
            }, ensure_ascii=False), encoding="utf-8")
            evidence = load_evidence(database)
            runs = load_runs(database)
            changes = load_changes(database)
            profiles = load_profile(environment)
            applicability = load_applicability(database, environment)
            actions = load_actions(database)
        self.assertEqual("https://example.test/source", evidence[0]["原文链接"])
        self.assertEqual("2026-09-01", evidence[0]["发布时间"])
        self.assertEqual(1, runs[0]["新增数"])
        self.assertEqual("成功", runs[0]["运行状态"])
        self.assertEqual("当前状态、构建号", changes[0]["变更摘要"])
        self.assertEqual("生产云桌面", profiles[0]["环境名称"])
        self.assertEqual("建议优先核验", applicability[0]["适用性"])
        self.assertEqual("待分派", actions[0]["处置状态"])

    def test_supporting_tables_are_optional_and_idempotent(self):
        records = [{"运行编号": "1", "运行状态": "成功"}]
        client = SupportingClient()
        result = sync_records(client, "runs", "运行编号", records)
        self.assertEqual({"待新增": 1, "待更新": 0, "未变化": 0}, result)
        self.assertEqual("runs", client.created[0][0])

        existing = {"runs": [{"record_id": "record-1", "fields": dict(records[0])}]}
        unchanged_client = SupportingClient(existing)
        result = sync_records(unchanged_client, "runs", "运行编号", records)
        self.assertEqual(1, result["未变化"])
        self.assertEqual([], unchanged_client.created)
        self.assertEqual([], unchanged_client.updated)

        records[0]["运行状态"] = "失败"
        result = sync_records(unchanged_client, "runs", "运行编号", records)
        self.assertEqual(1, result["待更新"])
        self.assertEqual("record-1", unchanged_client.updated[0][1])

    def test_publisher_syncs_machine_tables_and_seeds_human_workflow(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            database = root / "state.sqlite3"
            environment = root / "environment.json"
            create_database(database)
            environment.write_text(json.dumps({"profile_name": "测试环境"}), encoding="utf-8")
            client = SupportingClient()
            summary = publish_supporting_tables(client, database, environment)
        self.assertEqual(
            {"证据来源", "Windows 环境画像", "变更历史", "采集任务", "适用性判断", "验证与处置"},
            set(summary),
        )
        self.assertEqual(
            {"evidence", "profiles", "changes", "runs", "applicability", "actions"},
            {item[0] for item in client.created},
        )

    def test_human_workflow_seed_never_overwrites_existing_record(self):
        records = [{"处置编号": "action:1", "处置状态": "待分派"}]
        existing = {
            "actions": [{
                "record_id": "record-1",
                "fields": {"处置编号": "action:1", "处置状态": "验证完成", "负责人": "张三"},
            }],
        }
        client = SupportingClient(existing)
        result = seed_records(client, "actions", "处置编号", records)
        self.assertEqual({"待新增": 0, "待更新": 0, "未变化": 1}, result)
        self.assertEqual([], client.updated)


if __name__ == "__main__":
    unittest.main()
