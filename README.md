# Windows OS 情报探查

这是一个面向云桌面质量保障的 Windows 情报采集 Skill。当前版本先跑通本地闭环：从微软官方来源采集、结构化、风险评估、去重、保留变更历史并生成报告；飞书多维表格尚未接入。

面向人的报告和命令行进度统一使用简体中文。为保证可追溯性，NDJSON/SQLite 仍保留微软官方英文标题和证据原文；产品名、CVE、KB、Build 和 RDP 等标准标识不作翻译。

## 当前来源

- Microsoft Security Response Center（MSRC CVRF API）：CVE、严重性、CVSS、利用状态、影响产品。
- Windows Release Health：Windows 10、Windows 11、Windows Server 的已知问题和解决状态。
- Microsoft Lifecycle：版本支持和退役节点。
- Windows Insider 官方 Sitemap：新预览版本信号。由于博客正文会拦截无人值守请求，本阶段只记录官方 Sitemap 信号并降低置信度。

目标产品为 Windows 10、Windows 11、Windows Server 2019/2022/2025。产品版本、Edition 和构建号仅在来源提供证据时填写，不作猜测。

## 快速运行

需要 Python 3.9 或更高版本，无第三方依赖。

```bash
python3 skills/windows-os-intelligence/scripts/collect.py \
  --mode backfill \
  --start 2026-08-01 \
  --end 2026-08-31
```

日常增量：

```bash
python3 skills/windows-os-intelligence/scripts/collect.py --mode incremental
```

Windows 环境可按安装方式将 `python3` 换成 `py` 或 `python`。查看完整参数：

```bash
python3 skills/windows-os-intelligence/scripts/collect.py --help
```

## 本地产物

- `data/raw/`：按内容哈希保存的官方原文快照。
- `data/normalized/events.ndjson`：当前规范化事件全集。
- `data/state/os-intel.sqlite3`：来源检查点、事件和变更历史。
- `reports/run-*.md`：适合人工阅读的本轮摘要。
- `reports/run-*.json`：适合定时任务读取的运行结果。

以上运行产物已加入 `.gitignore`，不会误提交大体积或持续变化的数据。脚本退出码 `0` 表示全部选中来源成功；`2` 表示部分来源失败，已成功来源仍会正常落盘。

## 测试

```bash
python3 -m unittest discover -s skills/windows-os-intelligence/tests -v
```

配置位于 `skills/windows-os-intelligence/config/sources.json`。采集和评估规则见 Skill 的 `SKILL.md` 与 `references/`。
