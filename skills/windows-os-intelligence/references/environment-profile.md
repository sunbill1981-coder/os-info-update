# Windows 环境画像与资产队列

## 目的

环境画像把“公开情报影响什么”转成“我们哪些基线需要先验证”。仓库中的 `environment.json` 是保守空画像；实际环境写入已忽略的 `environment.local.json`，不提交到公开 GitHub。

平台厂商画像和现场画像是两层数据。例如，锐捷官网显示产品线支持 VDI、IDV、TCI/VOI 和 VAPP，但只有项目现场确认的架构和组件才能参与环境相关度评分。厂商公开能力只用于扩展风险路由、测试思路和待确认问题。

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
| `delivery_architectures` | 现场已确认使用的 VDI、IDV、TCI/VOI、VAPP |
| `platform_components` | 现场已确认的 RCDC、RCCP、分布式存储、vGPU、EST/HEST、影子克隆等 |

## 判读结果

“命中资产队列”是候选核验范围。“候选影响数量”是命中队列的资产数汇总，不代表这些设备已出现故障。需结合 Edition/Build/KB 的更精确证据和灰度验证才能收窄范围。

## 安全边界

只保存评估所需的聚合信息。不要写入主机名、IP、用户、域名、密钥、内部 URL 或资产明细。如果队列名称本身敏感，使用中性名称，例如“标准桌面 A”。
