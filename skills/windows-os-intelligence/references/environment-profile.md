# Windows 环境画像与资产队列

## 目的

环境画像是可选增强，用于把“公开情报可能影响什么”进一步转成“我们哪些基线需要先核验”。默认外部风险雷达不依赖画像：无内部资料时照常发现和筛选外部线索，把内部适用性标为“未知”。不要要求使用者先整理完整画像，也不要因空画像造成的低环境相关度而排除值得调查的外部风险。仓库中的 `environment.json` 是保守空画像；实际环境写入已忽略的 `environment.local.json`，不提交到公开 GitHub。

可以只使用当次已有的部分资料。记录其来源、适用产品版本和核验时间；过期、矛盾或未确认项保留未知，不沿用为当前产品结论。产品实现、支持矩阵与客户配置是不同层次：产品支持某能力不证明客户启用了该能力，某客户未启用也不排除产品线其它验证范围。

`scope_type` 支持两种语义：`deployment` 表示某个客户或生产现场；`product_portfolio` 表示原厂产品组合的验证范围。后者可将多种交付架构同时纳入，并通过 `architecture_priorities` 排定验证顺序。“命中产品验证范围”不等于“所有客户已受影响”。

平台厂商画像和实际分析范围是两层数据。例如，锐捷官网显示产品线支持 VDI、IDV、TCI/VOI 和 VAPP，但客户现场模式下只有现场确认的架构和组件才能参与评分；原厂产品组合模式下，由产品团队声明的完整验证范围可参与评估，但不得外推为每个客户都已受影响。

## 与运行隔离、重评的关系

配置文件仍位于 Skill 的 config 目录，environment.local.json 不按用途自动分成多份。不同目的的采集若需要不同画像，用 collect.py 的 --environment 显式选择。画像不会被公共历史包导出；导入包保留来源事实和公共维度，不能替代目标环境配置。

manage.py reprocess 当前固定使用仓库的保守 environment.json，不自动读取 environment.local.json，也没有 --environment 参数；重评可能因此改变内部相关度、处置优先级和告警等级。复核实际环境时，在相应空间采集阶段使用可靠画像；不要把保守重评的变化解释成微软来源变化。运行目录、私有反馈与历史更新边界见 [预发布操作指南](pre-release-operations.md)。

## 如何划分队列

把使用同一 Windows 版本、Edition、Build、角色和组件基线的资产放入同一队列。常见例子：

- Windows 11 24H2 Enterprise 标准办公桌面（Guest + RDP + FSLogix）。
- Windows Server 2022 RDS 会话主机。
- Windows Server 2022 域控。
- Windows Server 2025 Hyper-V 宿主机。

每个 `asset_groups` 对象包含：

| 字段 | 用途 |
|---|---|
| `id` / `name` | 稳定标识与人可读名称 |
| `products` | Windows 产品与版本 |
| `editions` / `builds` | Edition 与 Build 基线；未知时留空 |
| `roles` | `guest`、`host`、`directory`、`profile/file service` 等 |
| `components` | RDP、FSLogix/profile、Hyper-V、authentication、GPU 等 |
| `cpu_architectures` | 真实 CPU 架构，如 `x64`、`ARM64`；不是 VDI 等交付架构，未知时留空 |
| `applications` | 基线确认使用的受影响应用清单；不填表示未知，空数组只在确认未使用时填写 |
| `scope_conditions` | 对公开条件线索的内部核验，如 `fresh_image`、`store_app_updates`；未知不填，false 不自动排除 |
| `installed_kbs` | 基线镜像已知安装的 KB；只在有可靠清单时填写 |
| `asset_count` | 该队列大致资产数，用于候选影响面排序 |
| `criticality` | 0–100 的内部业务重要性 |
| `enabled` | 是否参与当前评估 |

环境顶层还可记录：

| 字段 | 用途 |
|---|---|
| `platform_profile` / `platform_name` | 厂商产品画像和平台名称 |
| `scope_type` | `deployment` 客户现场或 `product_portfolio` 原厂产品组合 |
| `delivery_architectures` | 现场已确认使用的 VDI、IDV、TCI/VOI、VAPP |
| `architecture_priorities` | 各架构的验证优先级，用于建议排序，不用于宣称客户受影响 |
| `platform_components` | 现场已确认的 RCDC、RCCP、分布式存储、vGPU、EST/HEST、影子克隆等 |

## 判读结果

同时保留两种判断：外部潜在影响回答“哪些云桌面工作流可能遇到该变化”，内部适用性回答“已有资料能否确认与本产品／基线匹配”。前者可以在没有内部资料时成立；后者未知不等于风险低。当前采集器中的环境分数仍反映已配置条件，不应被解释成完整的外部预警结论。

“命中资产队列”是候选核验范围。“候选影响数量”是命中队列的资产数汇总，不代表这些设备已出现故障。需结合 Edition/Build/KB 的更精确证据和灰度验证才能收窄范围。

报告另提供“适用性核验：匹配／不匹配／未知”，保留 CPU、特定应用与条件差异；未提供具体基线时为未知。它与粗粒度队列匹配和数值相关度分开，不会自动隐藏信息或宣称已受影响。详见 [范围判读](scope-interpretation.md)。

## 按需补充产品依赖

当一条外部线索需要更精确的产品判断时，再补充与它相关的实现或依赖资料，例如镜像身份处理、认证路径、驱动、会话或用户配置流程。记录“依据与适用版本—所依赖的 Windows 行为—尚未确认的问题”即可，不需要先建设完整依赖库。知识库使用与证据边界见 [可选产品知识库](optional-product-knowledge.md)。这些资料用于智能体层的限定分析；不要把未经实现的字段写成采集器已支持的自动匹配能力。

## 安全边界

只保存评估所需的聚合信息。不要写入主机名、IP、用户、域名、密钥、内部 URL 或资产明细。如果队列名称本身敏感，使用中性名称，例如“标准桌面 A”。
