# Windows 环境画像与资产队列

## 目的

环境画像把“公开情报影响什么”转成“我们哪些基线需要先验证”。仓库中的 `environment.json` 是保守空画像；实际环境写入已忽略的 `environment.local.json`，不提交到公开 GitHub。

`scope_type` 支持两种语义：`deployment` 表示某个客户或生产现场；`product_portfolio` 表示原厂产品组合的验证范围。后者可将多种交付架构同时纳入，并通过 `architecture_priorities` 排定验证顺序。“命中产品验证范围”不等于“所有客户已受影响”。

平台厂商画像和实际分析范围是两层数据。例如，锐捷官网显示产品线支持 VDI、IDV、TCI/VOI 和 VAPP，但客户现场模式下只有现场确认的架构和组件才能参与评分；原厂产品组合模式下，由产品团队声明的完整验证范围可参与评估，但不得外推为每个客户都已受影响。

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

“命中资产队列”是候选核验范围。“候选影响数量”是命中队列的资产数汇总，不代表这些设备已出现故障。需结合 Edition/Build/KB 的更精确证据和灰度验证才能收窄范围。

## 安全边界

只保存评估所需的聚合信息。不要写入主机名、IP、用户、域名、密钥、内部 URL 或资产明细。如果队列名称本身敏感，使用中性名称，例如“标准桌面 A”。
