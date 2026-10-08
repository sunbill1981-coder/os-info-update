# 隔离运行、跨期评审与数据版本操作

实现候选版本：0.4.0-rc.1。所有命令从项目根目录运行，Python 3.9+，无新增第三方依赖。这里是本地操作流程；不会自行上传 GitHub、启用定时任务或群发。

## 1. 四个独立选择

| 选择 | 值 | 含义 |
|---|---|---|
| 运行用途 | debug / trial / production | 数据、检查点、报告和业务状态分别放在 runtime 对应目录；默认 trial |
| 采集方式 | backfill / rolling / incremental | 时间窗口，与用途无关 |
| 数据状态 | candidate / approved | 候选需要公开内容与覆盖范围验收；生产空间的采集输出也不是自动验收的数据包 |
| 发布目标 | none / pilot / formal | 默认 none，只可预览；trial 只能 pilot，debug 禁止外发 |

`runtime/<purpose>/` 是运行空间。`data/raw`、`data/discovery`、`data/inbox`、`data/normalized`、`data/state`、`reports` 均相对该空间。不同空间不共享可写原文缓存；配置和本地凭据仍在项目原位置。采集器不会自动继承上次用途，调度/调用时须显式指定期望用途。`runtime/` 整体忽略，不提交状态库、报告或原文。包文件必须显式选择公开导出位置再上传。

本文短路径只用于说明空间内的位置。命令中显式提供的 --input、--output、--urls-file、--import-file、--record-file 等文件参数按当前工作目录解析，不会自动加 runtime/trial 前缀；从项目根目录运行时，应写 runtime/trial/... 或绝对路径。manage.py 的 --workspace/--purpose 必须放在子命令之前。配置路径保持项目/Skill原位置。

同一项目 runtime 下跨用途直接读采集输入被拒绝。已验收公共包通过 import 转入目标空间。`stage-legacy` 是明确接纳未分类旧数据的唯一便捷入口，仅允许 trial/debug，保留原目录。

```bash
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial stage-legacy \
  --input data/normalized/events.ndjson
python3 skills/windows-os-intelligence/scripts/collect.py --purpose trial \
  --mode rolling --days 7
```

旧库无须迁移就能保留。若确需升级其指纹，显式运行 `migrate.py --legacy --dry-run`，核对后 `--legacy --apply`；工具会先备份。默认 migrate 针对 trial 库。新表是增量建表，既有事件身份不变。

## 2. 每轮必须做的跨期评审

采集后读取本轮 triage JSON 的 `continuity`。`constraints` 是外部约束，`candidates` 是关联待评审队列，`risks` 是独立的组合判断，`feedback` 是私有执行记录。不能只看本期事件列表。

1. 在有原文支撑的约束/默认行为/前提变化中提取 constraint。核对变化前后、条件、版本、排除边界和生效时间；未知保持未知。不要从标题、KB 或推测填补约束。
2. 从新事件与仍有效/有效性未知的历史约束召回候选。当前脚本按声明的组件和工作流召回，无 30 天淘汰；预算默认 50，超额显式保留；持续风险摘要默认8条，优先需要重审、本次变化及公开证据支持的未关闭判断，其余仍可展开。二者都在 config/continuity.json 调整，不代表已完整评审。它不是完整的语义依赖检索，会漏掉跨组件、隐含前提联系。智能体需补查来源明确的依赖关系，不能把自动候选数当成完整覆盖。
3. 对候选核对共同生效的版本、配置、路径和时间。共享维度不是风险证明。版本不相交记录 dismissed；不明确则 hypothesis + unknown；公开证据支持也不意味着产品已受影响。
4. 将评审记录保存到库，再重新生成报告。风险引用不同事件及可选约束修订，原始事件和日期不被改写。未完成候选跨周保留；来源或约束修订变化会标记旧结论需要重审。
5. 安静周也检查持续风险、重审标记和上期私有反馈。记录失败证据、未执行和无人负责，不能以没有新事件关闭事项。

collect.py 的 acquisition_status/退出码只反映选定来源采集，status 还反映发现与跨期缺口。manage.py report/import/reprocess 生成本地复核视图，固定标partial；签收时需要说明其范围并明确 --allow-partial，不能把重评视图当作新一轮完整采集。

### 评审记录契约

输入支持单个 JSON、JSON 数组或 NDJSON。记录格式固定 v1，未知字段拒绝。constraint/risk 的 id 可以省略；feedback 的 id 必须显式提供。前两类标识由事件身份集合和稳定 claim_key 生成；改措辞、结论或适用范围时复用 claim_key。换 claim_key 会建立新判断，不能用于回避原结论历史。

事件引用用 `event_refs=[{"event_id":"实际标识","fact_hash":"实际 fact-v4 指纹"}]`。指纹用 `Event(**记录).fact_hash()` 计算，不是 raw_hash。依据用 `basis=[{"event_id":"同一事件","url":"该事件保存的具体来源URL","quote":"该URL保存原文的精确摘录"}]`；至少20字符，每个引用事件都要有依据，引用别的网页摘录会被拒绝。不要引用模型解释当作来源。

| 类型 | 必填字段 |
|---|---|
| constraint | schema=constraint-v1；claim_key、title、mechanism、before、after、status、review_note；products、components、workflows、conditions、exclusions 字符串列表；event_refs、basis |
| risk | schema=risk-v1；claim_key、title、mechanism、status、coexistence、coexistence_basis、first_action、review_note；missing_inputs、steps、record 字符串列表；event_refs、basis；decisions 对象列表 |
| feedback | schema=feedback-v1；id、subject_kind、subject_id、subject_revision、applicability、action_clear、executed、baseline、owner、next_action、recorded_at |

constraint：status 为 active/unknown/retired；effective_at 可空，不猜生效日期。撤销/替代用同一约束修订并写明原文依据。products/conditions/exclusions 必须带来源原意的版本和限制；空列表表示没有已提取信息，不能表示全版本适用。

risk：至少两个不同事件。status 为 hypothesis/supported/dismissed/closed；coexistence 为 compatible/unknown/disjoint；disjoint 只允许 dismissed，unknown 不允许 supported。`constraint_refs=[{"id":"约束标识","revision_hash":"实际约束修订"}]` 可选；如引用约束，其所有原始事件必须同时列入 risk.event_refs 并提供 basis；`suggested_role` 可选。`decisions=[{"when":"观察结果","then":"后续动作"}]`；steps 必须描述具体操作，record 描述交付记录。review_note 只记公开证据评审，不写客户或内部产品信息。

```bash
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial review \
  --kind constraint --input runtime/trial/reviews/constraints.ndjson
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial review \
  --kind risk --input runtime/trial/reviews/risks.ndjson
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial report
```

文件不存在时请先完成原文评审再创建输入，不要用空的示例字段假装已经核验。保存是整批先校验、再事务写入。相同记录重复提交无新修订。报告显示上次判断、修订字段差异、原始依据、下一步与建议承接角色；措辞与事实关系变化仍需人辨别，脚本只分类字段变化。

## 3. 私有反馈

subject_kind 是 event/risk。event 的 subject_revision 使用 `record_hash()`；risk 使用库中 revision_hash。新反馈必须引用当前修订。applicability 是适用/不适用/未知；action_clear 和 executed 是布尔值。已执行必须填写 result；note 可选。baseline 填实际测试基线或明确未知，owner/next_action 写负责人或待分派与下一步。

```bash
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial review \
  --kind feedback --input runtime/trial/reviews/feedback.ndjson
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial export-feedback \
  --output runtime/trial/private-feedback.json
```

反馈与外部事实独立保存。对象修订后，旧结果保留并标记复查。未复现不自动关闭风险。反馈仅显式私有导出；公共包不包含它，报告仅显示反馈数量和过期数量。详细待办从 triage JSON 的 continuity.feedback 读取，不自动进入群消息或公共导出。

## 4. 候选包、验收与活动基线

数据包 manifest.status 的 candidate/approved 与运行报告的 dataset_status 分开；活动基线由 active_dataset/active_dataset_status 表示。导入已验收包后的报告仍待本轮发布审阅，不能因此把报告或新观察自动标成已验收。

coverage.json 由评审者整理，必须提供 start/end、sources、input_runs、limitations（后三项为非空字符串列表）；sources 必须声明包内所有来源编号。另外补充逐来源覆盖、待评审数量、来源使用条件及排除范围。**日期范围、条数不能代替覆盖核对。**

```bash
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial export \
  --dataset-id windows-history --version 0.1.0 \
  --coverage runtime/trial/coverage.json --output runtime/trial/history-0.1.0-candidate.json.gz
python3 skills/windows-os-intelligence/scripts/manage.py approve \
  --input runtime/trial/history-0.1.0-candidate.json.gz \
  --output runtime/trial/history-0.1.0-approved.json.gz \
  --reviewer reviewer --note '已核对公开内容、来源使用条件及覆盖缺口；详见覆盖清单'
python3 skills/windows-os-intelligence/scripts/manage.py --purpose production import \
  --input runtime/trial/history-0.1.0-approved.json.gz --dry-run
python3 skills/windows-os-intelligence/scripts/manage.py --purpose production import \
  --input runtime/trial/history-0.1.0-approved.json.gz
```

approve 是记录已完成的人/智能体审阅，不会代替阅读或来源核验。仅改 approved flag 没有验收记录会被拒绝；本地操作者可信，机制不提供数字签名或防篡改身份认证。

导出含公开事实、来源指纹和评审判断，排除画像、现场匹配、私有反馈、任意嵌套元数据、凭据和发布状态。仅接受无凭据/查询参数的公开 HTTPS 来源。字段白名单不能识别自由文本里是否夹了客户信息；验收时仍须检查摘要、摘录、评审说明和 coverage 全部内容，以及引用许可。包含最小来源摘录，不是全网页归档；完整快照继续在受控原文存储。GitHub 是公开可访问的数据发布，不因“不群发”而变成私有。

包版本和文件不可原地覆盖；清单记录格式/规则/skill/实现指纹、范围、校验值和验收说明。实现指纹覆盖脚本、配置、SKILL.md 和 references；后续文档修正也可能改变当前实现指纹，旧包保留创建时指纹，不改写、不自动失效。导入先完整校验，再原子激活，幂等，不推进来源检查点或发历史消息。现地采集的同身份观察优先保留并计入 live_preserved；这不是悄悄切换数据，需要审阅报告中的混合基线情况。

## 5. 更新历史数据与回退

四种变化分开处理：来源事实变了，需要重读原文；提取规则变了，需要重解析可得原文快照；评估/关联规则变了，重评结构化事实；格式变了，显式迁移。不要从旧模型解释重建原文事实。

```bash
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial import \
  --input runtime/trial/history-0.1.0-approved.json.gz
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial reprocess \
  --dataset windows-history:0.1.0
# 可加 --events '实际事件标识1,实际事件标识2' 和 --taxonomy 新评估配置
```

本入口固定使用保守的 config/environment.json（不自动读 environment.local.json，未提供 --environment 参数），可能使内部相关度和告警级别与原报告不同；这不表示微软事实变化。本入口执行评估和已有多源关联重算，不自动重解析三年网页、不自动改写人工的约束/组合结论。重评输出 `.changes.json`，记录处理阶段、基线版本、实现指纹、事件及字段前后值，保留来源事实。受影响的旧约束/组合判断会标记需重审，即使事实指纹没有改变；未提交重新评审前禁止导出候选新版。定向评估后，相连事件的佐证结果也可能变化，会一并列出。

提取升级时，在 trial 用已有授权快照通过 discover 的 `--import-file` 路径重新建立候选，核对正文并提交新的 reviewed 记录；常规源则按可获取性重新采集受影响窗口。原快照不足时标缺口，重新抓到的现有页面必须声明当前抓取，不能称作当时快照。首版尚无统一的自动历史网页重解析入口。

然后重审有依赖变化的约束/风险，导出新版本（如0.2.0），验收、预览并导入 production。旧包和过去实际测试记录保留，不覆盖改写。

```bash
python3 skills/windows-os-intelligence/scripts/manage.py --purpose production activate \
  --dataset windows-history:0.1.0 --dry-run
python3 skills/windows-os-intelligence/scripts/manage.py --purpose production activate \
  --dataset windows-history:0.1.0
```

切换会恢复缓存的已验收包，隐藏非活动基线专属条目，但保留审计、现场采集和人工反馈；本地观察继续优先。这里是本地基线回退，不会删除飞书已有记录或撤回已发消息。重新评审当前报告后才允许同步。

## 6. 按月可恢复回填

```bash
python3 skills/windows-os-intelligence/scripts/backfill.py --purpose trial \
  --start 2026-07-01 --end 2026-09-30 --plan-only
python3 skills/windows-os-intelligence/scripts/backfill.py --purpose trial \
  --start 2026-07-01 --end 2026-09-30
```

账本位于 `runtime/trial/data/backfill/<批次>/ledger.json`，记录每月运行状态、来源覆盖、失败、缺口和报告；重复执行跳过采集成功月份并重试失败/中断月份。新增来源或修改采集配置创建不同批次。语义核验/搜索未完成不会被当作采集失败，也不会由重试自动完成；按账本缺口另做发现和评审，必要时 --retry-all。只允许 trial/debug，不触碰production增量状态。同一用途内回填与日常采集仍使用同一来源数据库/检查点，账本独立不等于检查点独立；避免在同一trial空间交错执行不同覆盖策略。

默认来源仍受各来源历史可获取性限制：Release Health 当前页面不是完整历史库，近期订阅不是三年档案，Insider 索引不是已核实行为。包装器解决分批/恢复，不增加网页档案或自动搜索能力。回填前必须补核目标版本历史入口、KB说明和安全加固专题；逐月明确未覆盖来源。后续先扩展这些来源，再宣称更长覆盖。没有当时可得快照和客户暴露日期，不计算提前量。

## 7. 本地签收与显式发布

先读 HTML、所有高关注溢出、待评审组合及覆盖缺口；再签收当前报告：

```bash
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial approve-publication \
  --target pilot --reviewer reviewer --note '已读本期报告与缺口，核对试点发送范围' --allow-partial
python3 skills/windows-os-intelligence/scripts/publish_feishu.py --purpose trial --target pilot --dry-run
```

dry-run 默认读取运行空间的 data/normalized/events.ndjson；真实发布读取签收报告的冻结 report_data。精确核对该报告的待发布数量时，在 dry-run 中显式加 --input，并填入报告JSON中的实际 report_data 路径。dry-run 输出统计与目标指纹，不是完整消息正文预览。

`--allow-partial` 只在审阅者明确接受有披露的缺口时使用。没有它，覆盖不足报告不能签收。签收绑定冻结的事件/triage快照及校验值；新报告产生、数据被修改或基线切换后必须重签收。

`feishu.local.json` 的 publish.binding 要包含目标和实际资源指纹。可由向导在确认资源后绑定，也可核对 dry-run 指纹后手动配置：`{"target":"pilot","fingerprint":"实际输出值"}`。资源变更或目标不符会在联网前拒绝。试点向导必须指定 `--purpose trial --target pilot`；未签收时可检查/建字段，但跳过数据写入。向导的写记录和连接测试仍需各自显式确认。

真实发布仍须用户明确授权的目标与范围；再运行 `publish_feishu.py --purpose trial --target pilot`。它默认仅同步 Base；`--send-alerts` 是独立显式开关，仅允许签收凭据允许发送的本期采集报告，历史导入/回填/重评/复核均禁止补发。现有事件告警保持其幂等规则。**跨期组合风险暂由人工审阅后分享报告，不自动逐条群发；签收不自动发送报告。** 没有发送成功回执不能宣称发布成功。

## 8. 建议预发布顺序

先做最近一季度真实资料样板，逐来源补缺、提取少量长期约束并完成不同机制的跨期评审。验证候选包、空空间恢复和新版本回退。达到可审阅状态后建立首版带缺口说明的历史基线；不要先投入三年全量并等它完成。

指定情报负责人和测试协调人各一名（可兼职）。首次试点人工审阅并分享一次，再按周试4–6期，记录操作清晰度、适用范围、实际执行结果、误报/遗漏和耗时。稳定后月度汇总，同时保留近期监测与重要变化及时提醒。三年剩余回填、历史来源完善和更深入依赖检索并行推进。
