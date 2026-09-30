#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
import re
import sys
from typing import List, Optional


def _values(prompt: str) -> List[str]:
    return [value.strip() for value in re.split(r"[;；]", input(prompt)) if value.strip()]


def _optional_bool(prompt: str) -> Optional[bool]:
    answer = input(prompt + " [y/n/?]：").strip().casefold()
    if answer in {"y", "yes", "是"}:
        return True
    if answer in {"n", "no", "否"}:
        return False
    return None


def main() -> int:
    if not sys.stdin.isatty():
        print("环境画像向导需要在交互式终端中运行。", file=sys.stderr)
        return 2
    workspace = Path(__file__).resolve().parents[3]
    target = workspace / "skills/windows-os-intelligence/config/environment.local.json"
    print("Windows 云桌面环境画像向导")
    print("只填写产品和部署方式概况；不要填写 IP、主机名、账号或密钥。")
    profile_name = input("环境名称（例如：主力办公云桌面）：").strip() or "本地云桌面环境"
    platform_name = input("云桌面平台（例如：锐捷云桌面）：").strip()
    platform_profile = "ruijie-cloud-desktop" if "锐捷" in platform_name else ""
    delivery_architectures = _values("已确认的架构（VDI;IDV;TCI/VOI;VAPP，未确认可留空）：")
    platform_components = _values("已确认的平台组件（如 RCDC;RCCP;分布式存储;vGPU;EST/HEST;影子克隆）：")
    products = _values("Windows 产品/版本/Edition，多项用分号分隔：")
    roles = _values("角色（guest;host;directory;profile/file service）：")
    components = _values("已使用组件（如 RDP;FSLogix/profile;Hyper-V;authentication）：")
    editions = _values("主要 Edition（如 Enterprise;Pro，可留空）：")
    builds = _values("当前 Build，多项用分号分隔（可留空）：")
    installed_kbs = _values("基线镜像已安装 KB，多项用分号分隔（可留空）：")
    asset_count_text = input("该环境约包含多少台资产（可留空）：").strip()
    asset_count = int(asset_count_text) if asset_count_text.isdigit() else 0
    payload = {
        "profile_name": profile_name,
        "platform_profile": platform_profile,
        "platform_name": platform_name,
        "delivery_architectures": delivery_architectures,
        "platform_components": platform_components,
        "products": products,
        "roles": roles,
        "components": components,
        "asset_groups": [{
            "id": "primary-cloud-desktop",
            "name": profile_name,
            "products": products,
            "editions": editions,
            "builds": builds,
            "roles": roles,
            "components": components,
            "installed_kbs": installed_kbs,
            "asset_count": asset_count,
            "criticality": 100,
            "enabled": True,
        }],
        "workflow_criticality": {
            "桌面镜像与交付": 100,
            "身份认证与登录": 100,
            "域加入与信任关系": 95,
            "远程会话连接": 100,
            "补丁安装与升级": 90
        },
        "deployment_patterns": {
            "基于镜像或克隆部署": _optional_bool("是否基于镜像或克隆部署"),
            "未受支持的配置": None,
            "补丁状态不一致": _optional_bool("是否可能存在补丁状态不一致"),
            "特定驱动或硬件": _optional_bool("是否使用特定 GPU、驱动或外设"),
            "企业或托管环境": True
        },
        "blast_radius": input("故障影响范围（low/medium/high/unknown）：").strip() or "unknown",
        "rollback_capability": input("回滚能力（image-recompose/snapshot/unknown）：").strip() or "unknown"
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    if input("确认保存到本地忽略配置 [y/N]：").strip().casefold() not in {"y", "yes", "是"}:
        print("已取消，未修改配置。")
        return 0
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"环境画像已保存：{target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
