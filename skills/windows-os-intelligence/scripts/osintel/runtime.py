"""Isolated run spaces. Legacy data is never implicitly adopted."""
from __future__ import annotations

from dataclasses import dataclass
import json
import hashlib
from pathlib import Path
from typing import Optional

from .model import stable_hash

PURPOSES = ("debug", "trial", "production")
TARGETS = ("none", "pilot", "formal")
VERSIONS = {"schema": "baseline-v1", "assessment": "assessment-v2",
            "continuity": "continuity-v1", "package": "dataset-v1"}


@dataclass(frozen=True)
class RunSpace:
    project: Path
    purpose: str = "trial"

    def __post_init__(self):
        if self.purpose not in PURPOSES:
            raise ValueError("运行用途必须为 debug/trial/production")
        object.__setattr__(self, "project", self.project.resolve())
        if self.root.resolve() != self.root:
            raise ValueError("运行空间不能使用符号链接")

    @property
    def root(self) -> Path:
        return self.project / "runtime" / self.purpose

    @property
    def db(self) -> Path:
        return self.root / "data/state/os-intel.sqlite3"

    def ensure(self) -> None:
        marker = self.root / "space.json"
        if marker.exists() and json.loads(marker.read_text()).get("purpose") != self.purpose:
            raise ValueError("运行空间标记与用途不一致")
        self.root.mkdir(parents=True, exist_ok=True)
        if not marker.exists():
            marker.write_text(json.dumps({"schema": "run-space-v1", "purpose": self.purpose}, ensure_ascii=False))

    def input(self, path: Optional[Path], relative: str) -> Path:
        result = path.resolve() if path else self.root / relative
        parent = self.project / "runtime"
        if result.is_relative_to(parent) and not result.is_relative_to(self.root):
            raise ValueError("采集/发布不能直接读取其它用途空间；请通过已验收基线导入")
        return result

    def metadata(self) -> dict:
        return {"run_purpose": self.purpose, "run_space": str(self.root),
                "dataset_status": "candidate", "versions": VERSIONS}


def target_fingerprint(settings) -> str:
    return stable_hash([settings.api_base, settings.base_token, settings.events_table_id,
                        settings.alert_chat_id, settings.evidence_table_id,
                        settings.profiles_table_id, settings.changes_table_id,
                        settings.runs_table_id, settings.applicability_table_id,
                        settings.actions_table_id])


def validate_publication(space: RunSpace, target: str, config: dict, settings) -> None:
    if target not in TARGETS or target == "none":
        raise ValueError("真实发布必须指定 pilot 或 formal；none 仅允许预览")
    if space.purpose == "debug" or (space.purpose == "trial" and target != "pilot"):
        raise ValueError("debug 禁止外发；trial 只允许 pilot")
    binding = config.get("publish", {}).get("binding", {})
    if binding.get("target") != target or binding.get("fingerprint") != target_fingerprint(settings):
        raise ValueError("发布目标未绑定或资源已变化；请先 dry-run 检查目标指纹并配置 binding")


def report_resources(space, report):
    """Bind the portable report as a whole, including topic files and ZIP."""
    resources = []
    if report.get('html_report'):
        resources.append(Path(report['html_report']))
    bundle = report.get('engineer_report')
    if bundle:
        folder = Path(bundle['index']).parent
        resources.extend(p for p in folder.rglob('*') if p.is_file())
        resources.append(Path(bundle['zip']))
    result = {}
    for value in resources:
        path = space.input(value, '')
        if not path.is_relative_to(space.root) or value.is_symlink():
            raise ValueError('报告资源必须位于当前运行空间且不能是符号链接')
        result[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def reviewed_publication_input(space, target, *, explicit=None, send_alerts=False):
    """Validate frozen review against the currently selected report, before networking."""
    marker = space.root / "space.json"
    if not marker.exists() or json.loads(marker.read_text()).get("purpose") != space.purpose:
        raise ValueError("运行空间未初始化或标记不一致")
    review = json.loads((space.root / "publication.json").read_text())
    if review.get("schema") != "publication-review-v1" or review.get("target") != target or review.get("run_purpose") != space.purpose:
        raise ValueError("缺少匹配的本地报告审阅凭据")
    # Avoid opening/migrating the database during publication.
    import sqlite3
    with sqlite3.connect(space.db.as_uri() + "?mode=ro", uri=True) as connection:
        row = connection.execute("SELECT payload_json FROM metadata WHERE key='latest-report'").fetchone()
    if not row or json.loads(row[0]) != review["report"]:
        raise ValueError("已有更新报告，旧签收已失效；请重新审阅")
    report_path = space.input(Path(review['report']), '')
    report = json.loads(report_path.read_text())
    if report.get('engineer_report') or review.get('report_sha256'):
        if hashlib.sha256(report_path.read_bytes()).hexdigest() != review.get('report_sha256') or report_resources(space, report) != review.get('resources'):
            raise ValueError('审阅后首页、主题详情或离线报告包发生变化，需重新审阅')
    data = space.input(Path(review["input"]), "")
    triage = space.input(Path(review["triage"]), "")
    if not data.is_relative_to(space.root) or not triage.is_relative_to(space.root):
        raise ValueError("待发布快照必须位于当前运行空间")
    if explicit and data != space.input(explicit, ""):
        raise ValueError("发布输入与已审阅报告不一致")
    if hashlib.sha256(data.read_bytes()).hexdigest() != review["sha256"] or hashlib.sha256(triage.read_bytes()).hexdigest() != review["triage_sha256"]:
        raise ValueError("审阅后数据或风险判断发生变化，需重新审阅")
    if send_alerts and not review["send_alerts_allowed"]:
        raise ValueError("历史导入、回填、重评与复核报告只能同步，不得补发历史告警")
    return data
