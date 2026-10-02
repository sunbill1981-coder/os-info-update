# Windows OS 情报探查

这是一个面向云桌面质量保障的 Windows 情报采集 Skill。当前版本已跑通本地闭环：从微软官方来源采集、结构化、风险评估、去重、保留变更历史，并把每个事件转换为“具体问题—云桌面潜在影响—建议测试—上线门禁—待验证问题”的行动分析卡，最终生成 Markdown、JSON 与离线 HTML 报告。另提供可选的飞书发布器，将情报幂等写入多维表格，并对新增或实质变化的预警发送群消息。

面向人的报告和命令行进度统一使用简体中文。为保证可追溯性，NDJSON/SQLite 仍保留微软官方英文标题和证据原文；产品名、CVE、KB、Build 和 RDP 等标准标识不作翻译。

风险评估保留四个独立核心指标：技术风险、环境相关度、置信度和处置优先级。漏洞另有“威胁紧迫度”，用 CISA KEV、微软已利用判定和 FIRST EPSS 表示现实攻击迫近程度，它不代替技术影响或置信度。通用分类规则位于 `config/risk-taxonomy.json`。仓库默认画像为保守的“未配置”状态，不会把所有 Windows 和云桌面组件自动当作已命中。未知值使用 `null`，不会被当作匹配项。

## 当前来源

- Microsoft Security Response Center（MSRC CVRF API）：CVE、严重性、CVSS、利用状态、影响产品。
- Windows Release Health：Windows 10、Windows 11、Windows Server 的已知问题和解决状态。
- Microsoft Lifecycle：版本支持和退役节点。
- Windows Insider 官方 Sitemap：新预览版本信号。由于博客正文会拦截无人值守请求，本阶段只记录官方 Sitemap 信号并降低置信度。
- CISA Known Exploited Vulnerabilities（KEV）：标记已知在野利用、要求日期和勒索软件利用情况。
- FIRST EPSS：为 CVE 补充未来 30 天被利用概率与百分位。
- 可选发现增强：微软 Support／Troubleshoot／Windows IT Pro、Citrix 专项公告和 Microsoft Q&A、r/sysadmin、r/Citrix 用户反馈。提供动态搜索计划、受限订阅／正文采集、合规正文导入、核验后入库；不是自动全网搜索或无限历史爬虫。

目标产品为 Windows 10、Windows 11、Windows Server 2019/2022/2025。产品版本、Edition 和构建号仅在来源提供证据时填写，不作猜测。

交互式 HTML 提供“本期阅读入口 → 风险阶段分组目录 → 详细分析卡片”，安全漏洞按组件主题进一步展开，目录与筛选同步。CPU 架构（ARM/ARM64/x64/x86）与 VDI 等交付架构分开；公开摘要及建议保留特定应用、条件和排除范围，支持 CPU 和适用性核验筛选。没有真实基线时核验为“未知”，不因高相关度宣称已受影响。当前不改数值评分、不自动过滤不匹配条目、不引入永久 UUID；范围解析仍需核对完整原文，详见 [范围判读](skills/windows-os-intelligence/references/scope-interpretation.md)。

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

默认会为带 CVE 的事件增强 KEV/EPSS。临时离线运行或排查数据源时可加 `--no-enrichment`。增强源失败会记入本轮覆盖缺口，不会伪装成“明确无记录”；已有事件保留上一次成功增强值，避免临时断网造成批量历史扰动。

Windows 环境可按安装方式将 `python3` 换成 `py` 或 `python`。查看完整参数：

```bash
python3 skills/windows-os-intelligence/scripts/collect.py --help
```

Windows 无人值守运行建议设置 `PYTHONUTF8=1`，并用“任务计划程序”按日执行 incremental 采集和飞书发布。`data/state` 必须位于本地磁盘；SQLite WAL 状态库不应放在 SMB/NFS 等网络共享盘。

## 月度修订与完整范围

月度回填先检查微软官方 CVRF 索引，再读取当月文档和回看范围内有后续更新的旧文档，避免漏掉旧 CVE 的当月修订。默认回看前 24 个月，历史文档预算 48 份；实际检查数量、范围外文档数量和当前原文回填的时间边界会写入报告。配置位于 `sources.json` 的 `msrc`：`revision_lookback_months=null` 表示检查全部历史候选，仍受 `max_history_documents` 限制；预算不足、索引失败或文档异常会形成部分成功，不推进来源检查点。回填旧月份不会倒退已有增量检查点。

Release Health 先确定当月活动的问题编号，再保留这些问题在全部已配置产品页面上的说明。跨月份回填不再因页面修复日期不同而裁掉平台、Build 或补丁关系。CVE 的当前源更新时间也不随报告月份改写；`source_activity` 保留原始修订时间与说明。当前原文可能包含月底之后的信息，不能用于声称当时已经预警。

集合型补丁关系、产品编号和标识列表统一排序去重，首次相同原文复跑也不应产生假变化。已有数据库按相同规则比较新旧记录；旧事实指纹兼容键只用于保留已有告警去重，真实事实变化会清除兼容键，不压制新告警。升级仍可先运行下面的迁移演练并保留备份。

## 从旧版升级

```bash
python3 skills/windows-os-intelligence/scripts/migrate.py --dry-run
python3 skills/windows-os-intelligence/scripts/migrate.py --apply
```

迁移会先生成 SQLite 一致性备份，再归一化无效日期并建立 v4 事实指纹、v2 评估指纹和当前记录指纹。v4 使用微软 Release Health 问题编号合并 active/resolved 及多产品页面，同时保留全部官方页面引用。启用群告警前，先不带 `--send-alerts` 执行一次飞书同步以建立新基线。

## 环境画像与资产队列

`setup_environment.py` 会创建本地忽略的 `environment.local.json`。除了 Windows 产品、Edition、Build、Guest/Host/域控角色和组件，还可以按同一基线划分“资产队列”，例如“Windows 11 24H2 标准桌面”或“Server 2022 域控”。系统会在报告和飞书中给出命中队列和候选影响数量；这是基于公开事实和本地画像的候选范围，不是已证实受影响数。详见 `skills/windows-os-intelligence/references/environment-profile.md`。

项目另保留了一份基于锐捷官网的云桌面公开能力基线，覆盖 VDI、IDV、TCI/VOI、VAPP、RCDC、RCCP、vGPU、EST/HEST 和影子克隆等风险路由。该基线只用于扩展测试思路，不会把厂商公开能力当成现场已启用配置。详见 `skills/windows-os-intelligence/references/ruijie-cloud-desktop-profile.md`。

锐捷云桌面知识库 MCP 是推荐的**可选增强**。执行 Skill 的智能体在已连接时可按需查询产品规格、镜像／代理／驱动升级和会话依赖，细化测试建议并记录版本与出处；未连接、调用失败或证据不足时，继续使用官方公开来源、公开能力画像和已确认的本地基线。采集脚本仍仅依赖 Python 标准库，不要求挂载知识库，也不包含内部地址或凭据。知识库回答不自动入库为 Windows 事实、不改变评分或触发告警。接入及证据边界见 [可选产品知识库](skills/windows-os-intelligence/references/optional-product-knowledge.md)。

网页研究或其他来源发现的候选情报可以按一行一个 JSON 对象写入 `data/inbox/signals.ndjson`，再执行：

```bash
python3 skills/windows-os-intelligence/scripts/collect.py \
  --mode rolling --days 30 --sources signals
```

同一风险的不同来源应使用相同的 `correlation_keys`；仅共享同一个 KB 不足以关联。具体方法见 `references/risk-discovery.md`。

## 专项与论坛风险发现（灰度）

先运行常规采集，再让 Skill 的智能体执行“发现增强”：

```bash
python3 skills/windows-os-intelligence/scripts/discover.py --start 2026-09-01 --end 2026-09-30 --plan-only
```

读取 `data/discovery/plan.md`，用当前平台提供的搜索／原文读取能力完成定向调研；查询由当轮 KB、Build 和通用工作流生成，不固化某次事故。脚本本身没有搜索服务依赖，Codex／WorkBuddy 的可用搜索能力由调用者提供；没有搜索能力就明确报告缺口。

不加 `--plan-only` 可尝试配置中的 RSS／Atom。自动访问遵守 robots、白名单、请求与文档大小预算；访问受限、空列表会形成缺口，不能宣称“没有问题”。Reddit 若禁止自动访问，需使用允许的授权来源或人工正文导出，不能绕过。原始地址可通过 `--urls-file` 提供，完整正文可通过 `--import-file` 导入，契约详见 [风险发现指南](skills/windows-os-intelligence/references/risk-discovery.md)。

候选原文保存在 `data/discovery/candidates.ndjson`。智能体／人工核对正文、时间、架构、触发条件及独立报告后，按指南写入 `data/discovery/reviewed.ndjson`，再接入原有评估、SQLite 历史和中文 HTML：

```bash
python3 skills/windows-os-intelligence/scripts/collect.py \
  --mode backfill --start 2026-09-01 --end 2026-09-30 \
  --sources discovery --no-enrichment
```

发现状态／核验文件存在时，后续默认采集会纳入已核验事件及本轮发现访问缺口；显式 `--sources` 保持来源选择语义。候选不会自动晋升结论，社区不能自报官方确认；同作者／转载不会虚增独立佐证。HTML 显示“用户报告／厂商说明／官方说明”、原文摘录、核验说明及待补证据。该版本不新增 UUID、不填资产基线、不自动发布飞书或配置定时任务。

先灰度四周，记录有效线索、提前量、审核成本、误报及新增测试／门禁。此阶段不伪造 ROI，也不承诺补丁发布即预判；收益评估方法及跨平台用法均见上述指南。所有候选、原文导出与运行报告保持本地忽略，不进入公开仓库。

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
- `reports/latest.html`：最近一次运行的交互式中文报告，可在 macOS 或 Windows 上直接用浏览器打开；公开事实与工程推演分层展示，每条结论、影响与建议都提供官方原文直达链接。

以上运行产物已加入 `.gitignore`，不会误提交大体积或持续变化的数据。脚本退出码 `0` 表示全部选中来源成功；`2` 表示部分来源失败，已成功来源仍会正常落盘。

## 测试

```bash
python3 -m unittest discover -s skills/windows-os-intelligence/tests -v
python3 scripts/check_public_repo.py
```

配置位于 `skills/windows-os-intelligence/config/sources.json`。采集和评估规则见 Skill 的 `SKILL.md` 与 `references/`。
