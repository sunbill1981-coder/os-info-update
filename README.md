# Windows OS 情报探查

这是一个面向云桌面质量保障的 Windows 情报采集 Skill。当前版本已跑通本地闭环：从微软官方来源采集、结构化、风险评估、去重、保留变更历史并生成报告。另提供可选的飞书发布器，将情报幂等写入多维表格，并对新增或实质变化的预警发送群消息。

面向人的报告和命令行进度统一使用简体中文。为保证可追溯性，NDJSON/SQLite 仍保留微软官方英文标题和证据原文；产品名、CVE、KB、Build 和 RDP 等标准标识不作翻译。

风险评估采用四个独立指标：技术风险、环境相关度、置信度和处置优先级。通用分类规则位于 `config/risk-taxonomy.json`。仓库默认画像为保守的“未配置”状态，不会把所有 Windows 和云桌面组件自动当作已命中。未知值使用 `null`，不会被当作匹配项。

## 当前来源

- Microsoft Security Response Center（MSRC CVRF API）：CVE、严重性、CVSS、利用状态、影响产品。
- Windows Release Health：Windows 10、Windows 11、Windows Server 的已知问题和解决状态。
- Microsoft Lifecycle：版本支持和退役节点。
- Windows Insider 官方 Sitemap：新预览版本信号。由于博客正文会拦截无人值守请求，本阶段只记录官方 Sitemap 信号并降低置信度。

目标产品为 Windows 10、Windows 11、Windows Server 2019/2022/2025。产品版本、Edition 和构建号仅在来源提供证据时填写，不作猜测。

## 快速运行

需要 Python 3.9 或更高版本，无第三方依赖。

首次使用先生成本地环境画像（该文件已被 Git 忽略）：

```bash
python3 skills/windows-os-intelligence/scripts/setup_environment.py
```

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

Windows 无人值守运行建议设置 `PYTHONUTF8=1`，并用“任务计划程序”按日执行 incremental 采集和飞书发布。`data/state` 必须位于本地磁盘；SQLite WAL 状态库不应放在 SMB/NFS 等网络共享盘。

## 从旧版升级

```bash
python3 skills/windows-os-intelligence/scripts/migrate.py --dry-run
python3 skills/windows-os-intelligence/scripts/migrate.py --apply
```

迁移会先生成 SQLite 一致性备份，再归一化无效日期并建立 v2 事实/评估/记录指纹。启用群告警前，先不带 `--send-alerts` 执行一次飞书同步以建立新基线。

网页研究或其他来源发现的候选情报可以按一行一个 JSON 对象写入 `data/inbox/signals.ndjson`，再执行：

```bash
python3 skills/windows-os-intelligence/scripts/collect.py \
  --mode rolling --days 30 --sources signals
```

同一风险的不同来源应使用相同的 `correlation_keys`；仅共享同一个 KB 不足以关联。具体方法见 `references/risk-discovery.md`。

## 飞书发布

飞书是可选的协作与告警界面，不替代本地审计数据。仓库仅保存通用 Base 结构和配置模板；真实应用密钥、Base/表/群/用户标识全部从本地环境或部署平台密钥管理中注入。

首次使用推荐直接运行交互向导：

```bash
python3 skills/windows-os-intelligence/scripts/setup_feishu.py
```

向导会先展示本地中文预览，再按步骤收集本地配置、检查应用鉴权和 Base 表结构。“情报事件”表必填；“证据来源”“Windows 环境画像”“变更历史”“采集任务”四张辅助表可选。只有使用者在每个写操作前明确确认，它才会补齐缺失字段、写入一条真实样例、建立历史基线或发送一条测试消息。应用密钥使用隐藏输入，本地 `.env` 权限设为 `600`。

只看预览或只检查已有配置：

```bash
python3 skills/windows-os-intelligence/scripts/setup_feishu.py --preview
python3 skills/windows-os-intelligence/scripts/setup_feishu.py --check
```

不连接飞书的演练：

```bash
python3 skills/windows-os-intelligence/scripts/publish_feishu.py \
  --config skills/windows-os-intelligence/config/feishu.example.json \
  --dry-run
```

实际使用前，复制 `skills/windows-os-intelligence/config/feishu.example.json` 为同目录的 `feishu.local.json`，设置 `enabled=true`，并通过环境变量提供真实资源信息。发布器会幂等同步已配置的机器维护表；对“适用性判断”和“验证与处置”只初始化新事件，已有记录及团队填写内容永不自动覆盖。默认只同步 Base；要发送群预警时显式增加 `--send-alerts`。群预警使用中文卡片，包含官方原文和可选的 Base 记录入口。

```bash
python3 skills/windows-os-intelligence/scripts/publish_feishu.py
python3 skills/windows-os-intelligence/scripts/publish_feishu.py --send-alerts
```

飞书完整配置、幂等策略和公开仓库脱敏要求见 `references/feishu-integration.md`。

## 本地产物

- `data/raw/`：按内容哈希保存的官方原文快照。
- `data/normalized/events.ndjson`：当前规范化事件全集。
- `data/state/os-intel.sqlite3`：来源检查点、事件和变更历史。
- `reports/run-*.md`：适合人工阅读的本轮摘要。
- `reports/run-*.json`：适合定时任务读取的运行结果。
- `examples/sample-incremental-report.md`：脱敏的标准增量报告样例。

以上运行产物已加入 `.gitignore`，不会误提交大体积或持续变化的数据。脚本退出码 `0` 表示全部选中来源成功；`2` 表示部分来源失败，已成功来源仍会正常落盘。

## 测试

```bash
python3 -m unittest discover -s skills/windows-os-intelligence/tests -v
python3 scripts/check_public_repo.py
```

配置位于 `skills/windows-os-intelligence/config/sources.json`。采集和评估规则见 Skill 的 `SKILL.md` 与 `references/`。
