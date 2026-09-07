# 飞书发布与运行

## 边界

采集、关联、评分和告警判定始终由版本化的 Skill 代码与配置完成。飞书 Base 保存结果和人工处置状态，不用 Base 公式替代风险模型，也不在工作流中硬编码某个 KB、错误码或事故案例。

公开仓库只保存：

- `config/feishu-schema.json`：通用 Base 表结构。
- `config/feishu.example.json`：仅包含环境变量名的示例配置。
- 飞书转换、幂等同步、发送和脱敏检查代码。

真实应用密钥、Base 标识、数据表标识、群标识、用户标识和 Webhook 不得进入 Git。

## Base 结构

`config/feishu-schema.json` 声明七张通用表：

1. 情报事件
2. 证据来源
3. Windows 环境画像
4. 适用性判断
5. 变更历史
6. 采集任务
7. 验证与处置

发布器自动维护前五类机器数据中的以下五张表：

- 情报事件：当前事件、中文结论、四指标、证据入口和告警投递状态。
- 证据来源：逐事件的原文链接、证据摘录和采集时间。
- Windows 环境画像：本地画像的只读投影，便于解释相关度；真实配置仍以本地忽略文件为准。
- 变更历史：来源事实或评估变化的时间线。
- 采集任务：最近 100 次运行的新鲜度、数量和来源失败摘要。

“适用性判断”和“验证与处置”是人工闭环表。发布器仅按稳定编号初始化尚不存在的记录：前者写入“待人工判断”或“建议优先核验”，后者只为正式告警/调查预警建立“待分派”验证项。一旦该编号已存在，发布器不更新、不删除记录，避免覆盖负责人、测试结论和上线决策。变更历史同步最近 1000 条作为 Base 热数据，本地 SQLite 保留完整审计历史。表字段类型刻意使用文本、数字、链接和复选框等稳定基础类型，避免高基数产品或构建号被固化为选项集。

## 首次配置

推荐在项目根目录直接运行：

```bash
python3 skills/windows-os-intelligence/scripts/setup_feishu.py
```

向导会依次完成本地预览、飞书资源准备提示、隐藏密钥输入、Base 链接解析、连接检查、主表与可选辅助表结构检查、单条试写、历史基线和测试消息。每张表补字段、写数据、导入基线和发消息都有独立确认，取消任何一步不会自动执行后续外部写操作。

向导也提供两个只读模式：

```bash
python3 skills/windows-os-intelligence/scripts/setup_feishu.py --preview
python3 skills/windows-os-intelligence/scripts/setup_feishu.py --check
```

1. 在目标飞书租户创建自建应用，启用机器人能力，并为应用授予 Base 记录读写与发送消息的必要权限。
2. 按 `config/feishu-schema.json` 创建 Base 和必需的“情报事件”表。建议同时创建“证据来源”“Windows 环境画像”“变更历史”“采集任务”；“适用性判断”和“验证与处置”可在启用人工闭环时创建。
3. 将应用加入 Base 协作者范围，将机器人加入目标告警群。
4. 复制 `config/feishu.example.json` 为 `config/feishu.local.json`，将 `enabled` 改为 `true`。
5. 在部署平台的密钥管理中注入 `.env.example` 列出的环境变量。本地调试可放入项目根目录 `.env`，该文件已被忽略。

Base 数据读写使用应用身份，权限由应用 scope 与 Base 资源权限共同决定。不应在代码中将应用身份自动切换成个人身份。

本地 `.env` 的资源变量为：

- 必需：`FEISHU_APP_ID`、`FEISHU_APP_SECRET`、`FEISHU_BASE_TOKEN`、`FEISHU_EVENTS_TABLE_ID`。
- 可选辅助表：`FEISHU_EVIDENCE_TABLE_ID`、`FEISHU_PROFILES_TABLE_ID`、`FEISHU_CHANGES_TABLE_ID`、`FEISHU_RUNS_TABLE_ID`、`FEISHU_APPLICABILITY_TABLE_ID`、`FEISHU_ACTIONS_TABLE_ID`。
- 告警体验：`FEISHU_ALERT_CHAT_ID`；如需卡片跳转 Base，再配置 `FEISHU_BASE_URL`。

以上变量都只保存于本地 `.env` 或部署平台密钥管理中。公开仓库中的 JSON 只保存环境变量名，不包含任何租户资源位置。

## 演练与发布

首先使用示例配置演练。演练模式不发起网络请求，也不需要密钥：

```bash
python3 skills/windows-os-intelligence/scripts/publish_feishu.py \
  --config skills/windows-os-intelligence/config/feishu.example.json \
  --dry-run
```

实际同步只写入 Base，不发群消息：

```bash
python3 skills/windows-os-intelligence/scripts/publish_feishu.py
```

显式允许发送新增或变化预警：

```bash
python3 skills/windows-os-intelligence/scripts/publish_feishu.py --send-alerts
```

Windows 上可将 `python3` 换成 `py` 或 `python`。

## 幂等与重试

- 事件以“事件编号”定位。“内容指纹”决定 Base 记录是否刷新；“事实指纹”与“评估指纹”用于区分原文事实和派生评估。
- 如果 Base 存在重复事件编号，发布器停止，不猜测保留哪一条。
- 告警标识由“事件编号 + 事实指纹 + 告警级别”生成；普通评分或话术调整不会使它失效。
- 调用消息接口前先写入“发送中”和稳定指纹。如果运行中断，下次使用相同幂等键重试；成功后标记“已发送”。
- 未启用群告警的发布会将当前版本标记为“已抑制”。以后启用告警时不会突然补发整批历史事件；该事件再次发生实质变化后，新指纹仍会触发告警。
- 飞书消息请求同时携带稳定幂等键，降低超时重试造成重复消息的概率。
- 历史回填默认不应携带 `--send-alerts`，只同步数据并生成摘要。
- 群预警采用交互卡片，展示中文风险摘要、四指标、建议动作和证据编号；配置 Base 网页地址后同时提供“在 Base 中处理”入口。
- 待发送告警数默认超过 20 条时，发布器在写入 Base 之前中止。只有已核对受众和数量时才使用 `--allow-bulk-alerts`；该选项不应写入日常调度脚本。

## 公开仓库安全

推送前运行：

```bash
python3 scripts/check_public_repo.py
```

检查器扫描 Git 已跟踪和待跟踪文件，拦截常见飞书 Webhook、密钥字面量、应用编号、Base 标识、表标识、群标识和用户标识。GitHub Actions 也会执行同一检查。

如果密钥曾进入 Git 历史，删除当前文件不足以恢复安全；必须立即轮换密钥，并按公开仓库的泄漏响应流程处理历史。
