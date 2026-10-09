# Windows OS 情报探查

这是一个面向云桌面质量保障的 Windows 外部风险雷达 Skill，帮助产品团队在客户受影响前发现值得调查的线索。观察范围包括约束收紧、生态故障、新特性，以及其它缺陷、安全和兼容性风险；普通企业 PC 的相关症状也在范围内。默认不依赖内部资料或产品知识库，内部适用性未知不等于外部风险低。

项目保留完整的采集、结构化、去重和变更历史，提供“工程师行动摘要 → 风险主题详情 → 全量档案”的离线 HTML 报告包，以及可追溯的 Markdown、JSON/NDJSON。测试场景、产品改造和支持建议是核验后的可能动作，不为每条 CVE 强制派发全套测试门禁。另提供可选的飞书发布器，将情报幂等写入多维表格，并在获得授权且显式启用时对新增或实质变化的预警发送群消息。

面向人的报告和命令行进度统一使用简体中文。为保证可追溯性，NDJSON/SQLite 仍保留微软官方英文标题和证据原文；产品名、CVE、KB、Build 和 RDP 等标准标识不作翻译。

现有风险评估保留四个独立核心指标：技术风险、环境相关度、置信度和处置优先级。漏洞另有“威胁紧迫度”，用 CISA KEV、微软已利用判定和 FIRST EPSS 表示现实攻击迫近程度，它不代替技术影响或置信度。通用分类规则位于 `skills/windows-os-intelligence/config/risk-taxonomy.json`。仓库默认画像为保守的“未配置”状态，不会把所有 Windows 和云桌面组件自动当作已命中。未知值使用 `null`，不会被当作匹配项；外部核验线索的筛选与内部环境相关度分开，不能因未配置画像就停止调查。

## 当前工作版：0.5.0-dev 工程师报告

已生成“轻量首页 → 主题详情 → 全量档案”离线报告包，默认展示5个经外部范围评审的主题，重大溢出明确提示；分析补证据与工程动作分开。最早信号、影响扩大、大规模爆发和生效/修复时间分别保留，无证据的日期显示未知。主题稳定标识与修订审计沿用本地存储，历史重评后需要重新评审。操作、契约和边界见 [工程师报告指南](skills/windows-os-intelligence/references/engineer-report.md)，本轮验收见 [报告改造记录](docs/engineer-report-implementation.md)。

新入口位于运行JSON的 `engineer_report.index`，最新导航在对应用途空间的 `reports/latest-engineer.html`；原 `reports/latest.html` 仍为旧格式全量报告。没有经过评审的主题时不会自动产生工程师任务，需要在采集之后核对原文并提交主题。仍未自动执行产品测试或群发主题报告。

工程师先读 [报告阅读指引](docs/report-reading-guide.md)，情报负责人按 [主题评审与生成指南](skills/windows-os-intelligence/references/engineer-report.md) 操作。首页展示预算与原始线索摘要预算分别配置；主题归并不删除事件，共同验证批次也不合并各风险的适用范围和结论。

实施前状态已同步至GitHub并发布 [2026-10-09改造前快照](https://github.com/sunbill1981-coder/os-info-update/releases/tag/snapshot-2026-10-09-before-report-redesign)，内容对应0.4.0-rc.1。下面保留该版本的说明；0.5.0-dev是后续工作版，不属于该快照。

## 0.4.0-rc.1：预上线候选

新增 debug/trial/production 隔离空间、外部约束与跨期组合评审记录、候选/已验收公共数据包、基线导入/回退、历史重评差异和私有反馈。发布默认关闭，真实外发需要当前报告审阅凭据及资源目标绑定。**本版本为通过本地验收的代码预发布版；真实历史样板和试点运营尚未验收，尚未群发或上传新版数据。** 版本变化与验证边界见 [发布说明](docs/release-v0.4.0-rc.1.md)。

操作命令和记录契约见 [预发布操作指南](skills/windows-os-intelligence/references/pre-release-operations.md)，完成情况与剩余工作见 [实施验收记录](docs/pre-release-implementation.md)。跨期召回无30天淘汰，但首版只自动召回共享组件/工作流，仍需智能体或人工做机制评审；统一历史网页重解析与跨期风险自动群发尚未实现。

默认 `--purpose trial`。下文短路径 `data/...`、`reports/...` 用于说明运行空间内位置，例如最新工程师导航在 `runtime/trial/reports/latest-engineer.html`，旧格式全量报告在 `runtime/trial/reports/latest.html`。命令里的显式文件参数按当前工作目录解析，需要写 `runtime/trial/...` 或绝对路径；`manage.py` 的全局参数必须放在子命令前。旧根目录数据不自动接纳，也不自动认定为正式历史；显式迁入 trial 的方法见操作指南。配置/本地凭据仍在原位置。

## 当前来源

- Microsoft Security Response Center（MSRC CVRF API）：CVE、严重性、CVSS、利用状态、影响产品。
- Windows Release Health：Windows 10、Windows 11、Windows Server 的已知问题和解决状态。
- Microsoft Lifecycle：版本支持和退役节点。
- Windows Insider 官方 Sitemap：新预览版本信号。由于博客正文会拦截无人值守请求，本阶段只记录官方 Sitemap 信号并降低置信度。
- CISA Known Exploited Vulnerabilities（KEV）：标记已知在野利用、要求日期和勒索软件利用情况。
- FIRST EPSS：为 CVE 补充未来 30 天被利用概率与百分位。
- 可选发现增强：微软 Support／Troubleshoot／Windows IT Pro、Citrix 专项公告和 Microsoft Q&A、r/sysadmin、r/Citrix 用户反馈。提供动态搜索计划、受限订阅／正文采集、合规正文导入、核验后入库；不是自动全网搜索或无限历史爬虫。

目标产品为 Windows 10、Windows 11、Windows Server 2019/2022/2025。产品版本、Edition 和构建号仅在来源提供证据时填写，不作猜测。

工程师首页展示经评审的行动与验证主题。完整档案保留原交互式 HTML 的风险阶段分组、组件目录和详细事件卡片，目录与筛选同步。CPU 架构（ARM/ARM64/x64/x86）与 VDI 等交付架构分开；公开摘要及建议保留特定应用、条件和排除范围，支持 CPU 和适用性核验筛选。没有真实基线时核验为“未知”，不因高相关度宣称已受影响。当前不改数值评分、不自动过滤不匹配条目、不引入永久 UUID；范围解析仍需核对完整原文，详见 [范围判读](skills/windows-os-intelligence/references/scope-interpretation.md)。

## 快速运行

需要 Python 3.9 或更高版本，无第三方依赖。

首次使用可以直接采集，不需要先整理环境画像：

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

如果已有具体产品或现场资料，并希望进一步核验内部适用性，可选运行 `python3 skills/windows-os-intelligence/scripts/setup_environment.py`。生成的本地环境画像已被 Git 忽略；资料不完整时继续保留未知。

默认会为带 CVE 的事件增强 KEV/EPSS。临时离线运行或排查数据源时可加 `--no-enrichment`。增强源失败会记入本轮覆盖缺口，不会伪装成“明确无记录”；已有事件保留上一次成功增强值，避免临时断网造成批量历史扰动。

Windows 环境可按安装方式将 `python3` 换成 `py` 或 `python`。查看完整参数：

```bash
python3 skills/windows-os-intelligence/scripts/collect.py --help
```

Windows 无人值守运行建议设置 `PYTHONUTF8=1`，可用“任务计划程序”按日执行带明确用途的 incremental 采集；试点期间发布先人工审阅，不先配置无人值守群发。`data/state` 必须位于本地磁盘；SQLite WAL 状态库不应放在 SMB/NFS 等网络共享盘。

## 原始线索摘要与工程师入口

轻量工程师入口和已评审主题见上文。原格式报告每次采集会在 Markdown／HTML 报告开头生成“外部风险核验摘要”，并输出 `reports/run-NNNNNN.triage.json`。运行 JSON 中的 `triage_report` 指向该文件，`triage_summary` 提供概览，`discovery_coverage` 说明发现查询的实际执行情况。

摘要依据外部公开维度独立筛选和排序，使用“优先核验／计划核验／留存待查”等定性标签；“直接链路候选／共性流程候选”只表示潜在外部关联，不是已确认影响锐捷。内部画像为空时仍能生成摘要。全量事实、既有归档顺序、事件评分、事实指纹和正式告警规则保持原有语义。

展示预算等通用配置位于 `skills/windows-os-intelligence/config/triage.json`，可用 `--triage-config` 指定其它配置。阅读预算限制不会删除事实，也不表示未入选条目安全。摘要提出外部核验动作及复查条件；当前不自动调度复查，不直接执行产品测试。发现计划与执行台账的操作见 [风险发现指南](skills/windows-os-intelligence/references/risk-discovery.md)。

## 月度修订与完整范围

月度回填先检查微软官方 CVRF 索引，再读取当月文档和回看范围内有后续更新的旧文档，避免漏掉旧 CVE 的当月修订。默认回看前 24 个月，历史文档预算 48 份；实际检查数量、范围外文档数量和当前原文回填的时间边界会写入报告。配置位于 `sources.json` 的 `msrc`：`revision_lookback_months=null` 表示检查全部历史候选，仍受 `max_history_documents` 限制；预算不足、索引失败或文档异常会形成部分成功，不推进来源检查点。回填旧月份不会倒退已有增量检查点。

Release Health 先确定当月活动的问题编号，再保留这些问题在全部已配置产品页面上的说明。跨月份回填不再因页面修复日期不同而裁掉平台、Build 或补丁关系。CVE 的当前源更新时间也不随报告月份改写；`source_activity` 保留原始修订时间与说明。当前原文可能包含月底之后的信息，不能用于声称当时已经预警。

集合型补丁关系、产品编号和标识列表统一排序去重，首次相同原文复跑也不应产生假变化。已有数据库按相同规则比较新旧记录；旧事实指纹兼容键只用于保留已有告警去重，真实事实变化会清除兼容键，不压制新告警。升级仍可先运行下面的迁移演练并保留备份。

## 从旧版升级

旧数据先保留为未分类存量。要使用新隔离空间，可以显式接纳到trial，不会改写旧目录：

```bash
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial stage-legacy \
  --input data/normalized/events.ndjson
```

只有确需升级旧库指纹时才运行下面的legacy迁移；已接纳的数据不会因迁移自动成为正式基线：

```bash
python3 skills/windows-os-intelligence/scripts/migrate.py --legacy --dry-run
python3 skills/windows-os-intelligence/scripts/migrate.py --legacy --apply
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

同一风险的不同来源应使用相同的 `correlation_keys`；仅共享同一个 KB 不足以关联。具体方法见 [风险发现指南](skills/windows-os-intelligence/references/risk-discovery.md)。

## 专项与论坛风险发现（灰度）

完整风险雷达先运行常规采集，再让 Skill 的智能体执行“发现增强”：

```bash
python3 skills/windows-os-intelligence/scripts/discover.py --start 2026-09-01 --end 2026-09-30 --plan-only
```

读取 `data/discovery/plan.md`，用当前平台提供的搜索／原文读取能力完成定向调研，并按 [风险发现指南](skills/windows-os-intelligence/references/risk-discovery.md) 记录实际执行结果；生成计划不等于完成搜索。查询结合当轮实体、通用工作流、症状和变更意图，不以出现 KB 或云桌面关键词为前提，不为 SID、TPM 或某次事故设置特权规则。脚本本身没有搜索服务依赖，Codex／WorkBuddy 的可用搜索能力由调用者提供；没有搜索能力或未完成计划时明确报告缺口。

不加 `--plan-only` 可尝试配置中的 RSS／Atom。自动访问遵守 robots、白名单、请求与文档大小预算；访问受限、空列表会形成缺口，不能宣称“没有问题”。Reddit 若禁止自动访问，需使用允许的授权来源或人工正文导出，不能绕过。原始地址可通过 `--urls-file` 提供，完整正文可通过 `--import-file` 导入，契约详见 [风险发现指南](skills/windows-os-intelligence/references/risk-discovery.md)。

候选原文保存在 `data/discovery/candidates.ndjson`。智能体／人工核对正文、时间、架构、触发条件及独立报告后，按指南写入 `data/discovery/reviewed.ndjson`，再接入原有评估、SQLite 历史和中文 HTML：

```bash
python3 skills/windows-os-intelligence/scripts/collect.py \
  --mode backfill --start 2026-09-01 --end 2026-09-30 \
  --sources discovery --no-enrichment
```

发现状态／核验文件存在时，后续默认采集会纳入已核验事件及本轮发现访问缺口；显式 `--sources` 保持来源选择语义。候选不会自动晋升结论，社区不能自报官方确认；同作者／转载不会虚增独立佐证。HTML 显示“用户报告／厂商说明／官方说明”、原文摘录、核验说明及待补证据。该版本不新增 UUID、不填资产基线、不自动发布飞书或配置定时任务。

先灰度四周，记录有效线索、调查动作、审核成本、误报与未决项。提前预警以客户暴露前仍有机会采取动作衡量，不承诺补丁发布前预判；只有具有历史证据和时间依据时才计算提前量。复查条件和建议日期只是计划信息，当前不会据此自动配置定时任务。收益评估方法及跨平台用法见上述指南。所有候选、原文导出与运行报告保持本地忽略，不进入公开仓库。

## 飞书发布

飞书是可选的协作与告警界面，不替代本地审计数据。仓库仅保存通用 Base 结构和配置模板；真实应用密钥、Base/表/群/用户标识全部从本地环境或部署平台密钥管理中注入。

首次使用推荐直接运行交互向导：

```bash
python3 skills/windows-os-intelligence/scripts/setup_feishu.py --purpose trial --target pilot
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

实际使用前，复制 `skills/windows-os-intelligence/config/feishu.example.json` 为同目录的 `feishu.local.json`，设置 `enabled=true`，并通过环境变量提供真实资源信息。发布器会幂等同步已配置的机器维护表；对“适用性判断”和“验证与处置”只初始化新事件，已有记录及团队填写内容永不自动覆盖。默认只同步 Base。真实发布前必须签收当前报告、明确 pilot/formal，并绑定实际资源指纹；要发送群预警时还须显式增加 `--send-alerts`。历史回填、导入与重评不能补发群预警；跨期风险先人工分享审阅后的报告。群预警使用中文卡片，包含官方原文和可选的 Base 记录入口。

```bash
# 先按操作指南签收当前报告并绑定资源；以下才是实际发布命令
python3 skills/windows-os-intelligence/scripts/publish_feishu.py --purpose trial --target pilot
python3 skills/windows-os-intelligence/scripts/publish_feishu.py --purpose trial --target pilot --send-alerts
```

飞书完整配置、签收与绑定步骤、幂等策略见 [飞书接入指南](skills/windows-os-intelligence/references/feishu-integration.md)。

## 本地产物

- `reports/latest-engineer.html`：最新工程师报告的导航入口。
- `reports/run-*.engineer/index.html` 或 `reports/analysis-*.engineer/index.html`：经评审主题的轻量首页。
- 对应报告目录的 `topics/*.html`：独立主题详情、工程步骤、结果处理及外部时间线。
- 对应报告目录的 `archive.html`：完整活动库事件与交互筛选，支持事件与主题双向跳转。
- 对应报告目录的 `data/` 和 `coverage.json`：全部规范化事件、主题/可用修订、反向关联及覆盖说明。
- `reports/run-*.zip` 或 `reports/analysis-*.zip`：对应报告的完整离线包。解压后保留整个目录并打开 `index.html`；原采集网页快照不包含在ZIP中。
- `data/raw/`：按内容哈希保存的官方原文快照。
- `data/normalized/events.ndjson`：当前规范化事件全集。
- `data/state/os-intel.sqlite3`：来源检查点、事件和变更历史。
- `reports/run-*.md`：适合人工阅读的本轮摘要。
- `reports/run-*.json`：适合定时任务读取的运行结果。
- `reports/run-*.triage.json`：独立的外部风险筛选结果与核验建议；不改写全量事件与正式告警。
- [合成格式样例](skills/windows-os-intelligence/examples/sample-incremental-report.md)：展示核验动作与跨期跟进，不代表真实事件或正式历史数据。
- `reports/latest.html`：最近一次运行的旧格式全量中文报告，可在 macOS 或 Windows 上直接用浏览器打开；公开事实与工程推演分层展示，每条结论、影响与建议保留对应公开来源直达链接；社区线索不会被写成官方确认。

以上 `data/` 和 `reports/` 短路径相对运行空间。新增产物还包括 `reports/analysis-*.changes.json` 重评差异、`data/backfill/*/ledger.json` 回填台账，以及显式指定位置的数据包/私有反馈；数据版本入口见操作指南。

代码和说明文档通过GitHub同步，`runtime/debug/`试跑报告、数据库及原文保留本地。克隆仓库不会自动获得这些试跑产物。正式公共历史数据需要单独导出、验收并按授权上传；数据版本与Skill代码版本独立。当前Release快照保存的是改造前版本，`main`中的0.5.0-dev报告能力不属于该Release。

运行空间已加入 `.gitignore`，不会误提交大体积或持续变化的数据。collect.py 的退出码 `0` 表示选中采集来源成功，`2` 表示部分来源失败；运行JSON的 acquisition_status 记录采集状态，status 还包含发现/跨期覆盖缺口，可以在退出0时仍为partial。其它入口的返回码按各自校验和管理操作解释，不能一概视为采集状态。采集源成功不代表发现查询已执行或已发现全部风险；报告应分别说明采集状态、发现执行与证据缺口。

## 测试

```bash
python3 -m unittest discover -s skills/windows-os-intelligence/tests -v
python3 scripts/check_public_repo.py
```

配置位于 `skills/windows-os-intelligence/config/sources.json`。采集和评估规则见 Skill 的 `SKILL.md` 与 `references/`。
