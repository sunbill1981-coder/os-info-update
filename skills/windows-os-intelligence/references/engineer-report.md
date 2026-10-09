# 工程师报告与主题评审

0.5.0-dev 工作版。面向工程师的入口是轻量首页，正文主题与全量事件分开加载。采集和 `manage.py report/review` 同时生成旧格式报告和新报告包；运行 JSON 的 `engineer_report.index` 指向新首页，`engineer_report.zip` 指向离线包，`latest_engineer_report` 是本用途空间内的最新入口。`reports/latest.html` 继续保留旧格式全量报告。

## 从线索到可承接主题

采集程序生成待评审线索，不自动把评分最高的事件包装成工程师任务。由智能体或情报负责人读完整原文、核对适用条件与补丁角色，再写入 `theme-v1`。首次没有主题的报告会显示“尚无已完成外部范围评审、可承接的主题”，同时列出全部未被就绪主题覆盖的高关注线索；这不是没有风险。

1. 阅读来源覆盖和原文，确认变更/故障机制、产品版本、角色、配置、应用、排除条件、引入/修复/缓解更新。网页索引、共同KB或共同组件只能用于召回。
2. 同一机制、相同触发条件的多来源观察可以组成 `same-risk`。共同首步核查任务可组成 `verification-batch`，但每项独立风险必须保留自己的范围、动作和结果，不能宣称同源或相互导致。即使只有一项事件也可形成主题。
3. 缺外部条件或正文证据时进入 `evidence`；已核实外部条件、需匹配内部基线时进入 `verify`；已能提出具体处置动作时进入 `action`；暂不需要操作的已评审事项进入 `watch`。内部适用性未知允许先核对配置/补丁，不能转述为产品已发生故障。
4. 首页只写风险、条件、为何现在、具体首步、证据与外部时间。首步应包含对象及需要取得的记录，不能只写“回归测试”。详情列出步骤、交付记录和不同结果如何处理；不猜测命令、阈值或内部组件实现。
5. 简短描述。可展示主题不足3项时不凑数。预算由 `config/engineer-report.json` 设置，默认5项；重大事项优先，同级按队列和稳定标识排序。超出预算的每项都有显式入口，重大溢出单列数量；其余就绪事项仍需承接。

高关注判断沿用已有外部线索规则，不代表全量分析完成。811条档案有7条高关注，也不能声称其它804条安全。未被主题覆盖的高关注线索从完整活动库计算，不因本周没有新增而消失。首页不能把这种分析补证据任务交给工程师当作就绪测试。

## 记录契约

提交JSON对象或数组。保存前校验，任何一项无效则不写入。完整示例结构可参考测试中的合成 `theme()` 构造函数；事故特有事实只进入运行数据或测试，不进入生产分类规则。

| 字段 | 要求 |
|---|---|
| schema | `theme-v1` |
| claim_key / id | 机制级稳定语义键；id由键生成，不随标题、证据增加或日期修订改变。不同机制不能复用同一个键 |
| title / risk / mechanism | 简体中文短标题、可能故障/限制、机制判断 |
| relation / grouping_note | `same-risk` 或 `verification-batch`；说明支持归并的证据与边界 |
| event_refs | `event_id`＋当前 `fact_hash`，每项唯一且存在 |
| basis | 每项事件至少一份 `event_id/url/quote`；公开HTTPS地址，引用必须是该页已保存原文的连续摘录（至少20字符） |
| scope | 非空文字数组；保留产品、条件、角色及排除边界 |
| queue / critical | 四类队列之一；重大性由评审者解释。不是新增漏洞评分规则 |
| why_now / first_action / owner | 本期关注理由、可开始执行的首步、承接角色 |
| steps / record / decisions | 非空步骤、记录列表；结果处理为 `when/then` 对象数组 |
| evidence_state / source_verified | 证据状态文字与外部范围是否完成核验；未核验不能进入action/verify |
| reviewed_at / review_note | 带时区的评审时间；审阅哪些来源、剩余局限、是否执行测试 |
| subitems | 每项含 `event_ids/scope/action/expected`；验证批次必须覆盖全部独立风险；版本/处置不同也应保留子项 |
| timeline | 下述节点数组；缺省为空，不根据采集日期自动生成 |
| closed | 布尔值；关闭主题退出行动摘要，仍在档案可追溯 |

原文可从事件 `evidence`、相同URL的 `source_references` 摘录，或同页 `update_details.evidence/exclusions_evidence` 引用。校验能证明摘录与事件事实修订一致，**不能证明评审者的日期、规模或因果解释正确**；发布前仍须检查语义。引用未保存的完整原文时先通过既有发现流程保留证据，不能往冻结事件里任意补写解释。

```bash
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial review \
  --kind theme --input runtime/trial/review/themes.json
python3 skills/windows-os-intelligence/scripts/manage.py --purpose trial report
```

主题沿用SQLite派生记录的修订历史。新证据增加或发现更早信号时更新相同键，保留旧判断；`event_refs`事实变化、证据从活动基线消失，或 `reprocess` 标记待语义重审时，主题降到 `evidence` 并显示原时间线与重审原因。完成原文复审后重新 `review`，不是仅取消提示。没有新增的一周仍保留未关闭主题；首页注明是否有窗口内发布/修订记录，该标记不等于精确的实质变化判定。

## 外部时间线

节点字段：`kind`、`date`、可选 `end`、`note`、已知日期的 `basis`；爆发节点还需 `scale_basis: explicit-source`。

| kind | 含义 |
|---|---|
| first_signal | 已保存且审阅过的最早外部信号；必须说明是官方Opened、公告或用户反馈，不能称为无条件的全球首次 |
| spread | 有证据的影响扩大迹象，仍不等于大规模爆发 |
| outbreak | 来源明确说明规模且日期有依据的大范围故障/攻击；本版要求权威来源，不能由帖子数、KEV收录、已利用标记或首次官方确认推定 |
| enforcement | 约束强制生效；公告日期与强制日期区分 |
| release | 新功能正式发布/推出；分批推出需注明范围 |
| mitigation / resolution | 缓解/修复；保留部分修复和各产品更新的差异 |

已知日期使用 `YYYY-MM-DD`；只有月/区间证据时使用有依据的 `date/end`，注明精度。未知使用 `date: null`，不能填报告日、采集日、评审日；历史回填只能声称当前证据能够追溯到的日期。源码只能检查格式及引用，日期与摘录的真实对应关系需要评审。

新特性、约束变化不一定存在“爆发”；首页没有证据时显示未知，详情可以解释不适用/尚未证实。跨期联动仍由 constraint/risk 记录负责；主题是阅读与承接层，不替代共同生效条件的机制评审。

## 离线报告包

- `index.html`：少量行动/验证主题，持续观察入口、高关注补证据队列、全部覆盖缺口。
- `topics/*.html`：步骤、记录、结果处理、独立子项、外部时间线、原文和评审历史。
- `archive.html`：完整活动库，旧格式筛选和全部事件卡片；事件与主题双向链接。
- `data/events.ndjson`、`themes.json`、`event-themes.json`：完整规范化事件、当前主题及可用修订、反向映射。
- `coverage.json`：窗口、用途、版本、事实集合摘要、数量和覆盖限制；未上传/未执行测试声明。
- 同名ZIP：以上所有文件使用相对链接，解压后打开首页；原采集网页快照仍保留在来源运行目录，不复制进此包。主题原文链接联网访问。

不要单独转发首页，分享整个ZIP或完整托管目录。可用的修订历史来自本地Store；离线输入只有当前主题时不会伪造历史。生成目录和ZIP不可覆盖，复审后生成新包；已发布快照不改写。

冻结数据演练不创建数据库、不采集、不更新检查点、不上传：

```bash
python3 skills/windows-os-intelligence/scripts/build_report.py \
  --input runtime/debug/tests/frozen/events.ndjson \
  --source-report runtime/debug/tests/frozen/run.json \
  --themes runtime/debug/tests/review/themes.json \
  --start 2026-09-01 --end 2026-09-30 --purpose debug \
  --output runtime/debug/tests/engineer-preview-v1
```

`--themes`可省略；输出明确尚无就绪主题。原运行JSON有窗口时必须与请求一致，不能重新标成其它月份。事实指纹不会因生成HTML而改变，离线样板不证明新采集覆盖或真实跨期风险发现能力。

主题可进入公共候选数据包，清单显式标记 `theme_schema: theme-v1`；含主题包须使用0.5.0或后续兼容实现，旧版会拒绝扩展数据字段。旧无主题包继续可读，切换/回退沿用基线与实时记录隔离。自由文本仍须人工检查公开性，私有反馈不导出。包中保留当前主题，既有已发布包与本地修订审计保留旧版本，不宣称新版包含全部SQLite历史。

签收绑定运行JSON、首页、所有主题/数据文件及ZIP；增加/改写/删掉报告文件会使签收失效。Feishu仍同步事件、按既有门禁发送事件告警；主题/跨期风险报告分享仍需人工审阅和用户授权，不宣称已经自动群发或执行测试。
