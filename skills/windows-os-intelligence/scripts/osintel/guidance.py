from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence

from .model import Event


@dataclass(frozen=True)
class CloudDesktopGuidance:
    """把公开事实转换为可评审的云桌面行动建议。

    problem_summary 是来源事实的中文概括；其余字段都是工程推演，
    必须在展示层标明“需内部验证”，不得冒充已确认的内部影响。
    """

    problem_summary: str
    potential_impacts: List[str]
    recommended_tests: List[str]
    preventive_actions: List[str]
    exploration_questions: List[str]
    applicability: str


STATUS_ZH = {
    "confirmed": "已确认", "reported": "已报告", "investigating": "调查中",
    "mitigated": "已缓解", "resolved": "已解决",
}

COMPONENT_ZH = {
    "RDP": "远程桌面协议（RDP）", "RDS": "远程桌面服务（RDS）", "Hyper-V": "Hyper-V 虚拟化",
    "VBS": "虚拟化安全（VBS）", "Credential Guard": "凭据保护", "GPU/display": "显卡与显示链路",
    "FSLogix/profile": "FSLogix 与用户配置文件", "authentication": "身份认证",
    "networking": "网络", "printing": "打印", "peripheral redirection": "外设重定向",
    "Windows Update": "Windows 更新", "image/recovery": "镜像与恢复",
    "audio/media": "音频与多媒体", "application compatibility": "应用兼容性",
}

WORKFLOW_ZH = {
    "desktop provisioning": "桌面交付", "domain join": "加入域", "image deployment": "镜像部署",
    "user logon": "用户登录", "patch deployment": "补丁部署", "in-place upgrade": "就地升级",
    "桌面镜像与交付": "桌面镜像与交付", "身份认证与登录": "身份认证与登录",
    "域加入与信任关系": "域加入与信任关系", "远程会话连接": "远程会话连接",
    "文件与配置文件访问": "文件与配置文件访问", "补丁安装与升级": "补丁安装与升级",
    "启动与恢复": "启动与恢复", "图形与显示": "图形与显示", "打印与外设": "打印与外设",
    "应用启动与兼容": "应用启动与兼容",
}

SYMPTOM_ZH = {
    "operation blocked": "操作被阻止", "authentication failure": "身份认证失败",
    "installation failure": "安装失败", "connection failure": "连接失败",
    "performance degradation": "性能下降", "认证或授权失败": "认证或授权失败",
    "连接中断": "连接中断", "安装或升级失败": "安装或升级失败", "崩溃或无响应": "崩溃或无响应",
    "蓝屏或无法启动": "蓝屏或无法启动", "数据损坏或丢失": "数据损坏或丢失", "性能下降": "性能下降",
    "功能不可用": "功能不可用", "显示或桌面加载异常": "显示或桌面加载异常",
    "配置被重置或丢失": "配置被重置或丢失", "状态或通知显示错误": "状态或通知显示错误",
}


def _unique(values: Iterable[str], limit: int = 5) -> List[str]:
    result: List[str] = []
    for value in values:
        if value and value not in result:
            result.append(value)
        if len(result) >= limit:
            break
    return result


def _labels(values: Sequence[str], mapping: Dict[str, str]) -> str:
    return "、".join(mapping.get(value, value) for value in values)


def _identifiers(event: Event) -> str:
    values: List[str] = []
    for key in ("cve", "kb", "build", "safeguard_hold"):
        values.extend(str(value) for value in event.identifiers.get(key, []) or [])
    return "、".join(_unique(values, 6))


def _security_impact(event: Event) -> str:
    text = f"{event.title} {event.summary}".casefold()
    for token, label in (
        ("remote code execution", "远程代码执行"), ("elevation of privilege", "权限提升"),
        ("information disclosure", "信息泄露"), ("denial of service", "拒绝服务"),
        ("security feature bypass", "安全功能绕过"), ("spoofing", "欺骗"), ("tampering", "篡改"),
    ):
        if token in text:
            return label
    return _labels(event.symptoms[:2], SYMPTOM_ZH) or "安全性、可用性或数据保护风险"


def _problem_summary(event: Event) -> str:
    identifiers = _identifiers(event)
    component = _labels(event.components[:3], COMPONENT_ZH) or "Windows 相关功能"
    symptoms = _labels(event.symptoms[:3], SYMPTOM_ZH)
    workflows = _labels(event.affected_workflows[:3], WORKFLOW_ZH)
    status = STATUS_ZH.get(event.status, event.status)
    suffix = f"；关联标识：{identifiers}" if identifiers else ""

    if event.event_type == "feature preview":
        return "官方预览渠道发布了新版本信号，当前仅验证到公告索引，未核验正文细节，不能视为已确认故障。"
    if event.event_type == "lifecycle":
        return f"微软公布了产品支持生命周期节点，需核对内部镜像、宿主机与服务端版本{suffix}。"
    if event.event_type == "vulnerability":
        impact = _security_impact(event)
        return f"微软已发布 {component} 安全漏洞，可能导致{impact}，当前状态为{status}{suffix}。"
    effect = symptoms or "功能或可用性异常"
    workflow_clause = f"，并影响{workflows}" if workflows else ""
    return f"微软已记录：{component}可能出现{effect}{workflow_clause}，当前状态为{status}{suffix}。"


IMPACT_BY_WORKFLOW = {
    "桌面镜像与交付": "金镜像制作、克隆或池扩容可能失败，也可能产生状态不一致的桌面。",
    "desktop provisioning": "桌面创建、克隆或池扩容可能失败，影响交付成功率。",
    "image deployment": "金镜像制作或发布后可能把问题批量复制到整个桌面池。",
    "身份认证与登录": "用户可能无法登录、重连或获取完整会话，造成业务中断和工单激增。",
    "user logon": "用户可能无法登录或获取完整桌面会话。",
    "域加入与信任关系": "新建、回收或重置的桌面可能无法加域，或在重启后丢失信任关系。",
    "domain join": "新建或回收的桌面可能无法加域，影响自动化交付。",
    "远程会话连接": "会话建立、重连、断线恢复或 RemoteApp 可能失败，直接影响用户可用性。",
    "文件与配置文件访问": "用户配置文件可能挂载失败、临时化或写入异常，伴随数据一致性风险。",
    "补丁安装与升级": "金镜像、存量桌面和宿主机的补丁节奏可能被打断，并出现混合版本风险。",
    "patch deployment": "补丁发布可能失败或产生混合版本，增大回滚与维护成本。",
    "in-place upgrade": "就地升级可能失败或破坏业务应用、驱动与配置。",
    "启动与恢复": "桌面池或宿主机可能无法启动或恢复，导致批量不可用并拉长回滚时间。",
    "图形与显示": "可能出现黑屏、渲染异常、分辨率或多屏问题，在 GPU/vGPU 场景中影响更大。",
    "打印与外设": "USB、打印、摄像头、智能卡或音频重定向可能失效，影响专用业务场景。",
    "应用启动与兼容": "镜像内关键业务应用可能无法启动、崩溃或行为改变，影响池化桌面的统一交付。",
}

TEST_BY_WORKFLOW = {
    "桌面镜像与交付": "用代表性金镜像执行升级、封装、克隆、首启、加域和回收再利用的端到端测试。",
    "desktop provisioning": "执行桌面创建、批量克隆、首启、策略下发和回收再利用测试。",
    "image deployment": "比较补丁前后的金镜像，验证发布、回滚以及新老镜像混合运行。",
    "身份认证与登录": "覆盖域账号、本地账号、缓存登录、NLA、SSO/MFA 和密码过期后的登录与重连。",
    "user logon": "验证新老用户的首次登录、并发登录、断线重连和策略加载。",
    "域加入与信任关系": "测试新克隆机加域、重启后登录、安全通道校验、退域再加域和信任修复。",
    "domain join": "测试新建与回收桌面的加域、重启、登录和信任通道校验。",
    "远程会话连接": "覆盖首次连接、断线重连、网络抖动、并发会话、RemoteApp 和长时间挂机恢复。",
    "文件与配置文件访问": "覆盖新建/存量配置文件、挂载/卸载、网络中断、存储延迟和并发登录。",
    "补丁安装与升级": "在金镜像、存量桌面和宿主机分别验证安装、重启、业务冒烟、卸载与回滚。",
    "patch deployment": "覆盖清洁安装、存量升级、重启、回滚和混合补丁状态。",
    "in-place upgrade": "用代表性镜像测试就地升级、回滚、驱动保留和关键应用启动。",
    "启动与恢复": "验证冷/热启动、意外断电恢复、快照恢复、补丁卸载与恢复环境。",
    "图形与显示": "按物理 GPU、vGPU 和软件渲染分组，测试重连、分辨率切换、多屏和视频负载。",
    "打印与外设": "覆盖 USB、打印、摄像头、智能卡和音频重定向的连接、重连与并发会话。",
    "应用启动与兼容": "建立镜像内关键应用清单，对启动、登录、读写、升级和退出执行自动化冒烟。",
}


def _potential_impacts(event: Event) -> List[str]:
    values = [IMPACT_BY_WORKFLOW[key] for key in event.affected_workflows if key in IMPACT_BY_WORKFLOW]
    components = set(event.components)
    roles = set(event.roles)
    if "Hyper-V" in components or "host" in roles:
        values.append("如果命中宿主机，单点异常可能扩大为多台虚拟桌面同时受影响。")
    if "directory" in roles:
        values.append("如果涉及目录服务或认证链路，影响面可能跨越多个桌面池和业务组。")
    if "FSLogix/profile" in components or "profile/file service" in roles:
        values.append("配置文件或文件服务问题可能跨多台桌面跟随同一用户，需防止数据不一致。")
    if event.event_type == "vulnerability":
        values.append("在可外部到达、多用户或共享宿主场景中，漏洞可放大横向移动、权限提升或服务中断风险。")
    return _unique(values or ["公开资料尚不足以确定云桌面影响链路，需先核对触发条件、组件和实际资产。"])


def _is_product_portfolio(environment: Optional[Mapping[str, object]]) -> bool:
    return bool(environment and environment.get("scope_type") == "product_portfolio")


def _architecture_order(environment: Optional[Mapping[str, object]]) -> List[str]:
    if not environment:
        return []
    architectures = [str(value) for value in environment.get("delivery_architectures", []) or []]
    priorities = environment.get("architecture_priorities", {}) or {}
    if not isinstance(priorities, Mapping):
        priorities = {}
    return sorted(
        architectures,
        key=lambda value: (-int(priorities.get(value, 0) or 0), value),
    )


def _recommended_tests(
    event: Event, environment: Optional[Mapping[str, object]] = None,
) -> List[str]:
    values = [TEST_BY_WORKFLOW[key] for key in event.affected_workflows if key in TEST_BY_WORKFLOW]
    components = set(event.components)
    if "RDP" in components or "RDS" in components:
        values.append("在不同客户端、NLA 配置和网络质量下验证 RDP 建连、重连、剪贴板、磁盘和外设重定向。")
    if "Hyper-V" in components:
        values.append("建立补丁前/后宿主机与来宾系统组合矩阵，覆盖启停、迁移、快照、网络和设备共享。")
    if "GPU/display" in components:
        values.append("覆盖物理 GPU、vGPU 与软件渲染的显示、重连、分辨率和多屏回归。")
    if event.event_type == "vulnerability":
        values.append("在代表性来宾镜像与宿主机完成补丁安装、重启、核心业务冒烟和回滚验证。")
    if event.event_type == "feature preview":
        values.append("仅在隔离实验环境安装预览版，对比现网基线的登录、会话、镜像和应用行为。")
    architectures = _architecture_order(environment)
    if _is_product_portfolio(environment) and "VDI" in architectures:
        values.insert(
            0,
            "原厂矩阵先在 VDI 高优先级基线验证金镜像、克隆、首启、加域、"
            "用户登录、EST/HEST 会话、断线重连和回滚，再向其他架构扩展。",
        )
    return _unique(values or ["先用与生产一致的版本、Edition、补丁和角色复现公开触发条件，再执行核心交付流程冒烟。"])


def _preventive_actions(event: Event) -> List[str]:
    values: List[str] = []
    if event.preview or event.event_type == "feature preview":
        values.append("保持实验室观察，在正文、适用范围和稳定版本路径核验前不进入生产镜像。")
    elif event.status in {"reported", "investigating"}:
        values.append("暂停扩大面积推送，仅在小规模灰度环执行，并保留可验证的镜像或快照回滚点。")
    elif event.status == "mitigated":
        values.append("先核对临时缓解措施的适用范围、副作用和撤销条件，再自动化下发。")
    elif event.status == "resolved":
        values.append("确认已安装微软标明的修复 KB/Build，通过专项回归后再恢复常规推送。")
    else:
        values.append("通过金丝雀环、分批发布和明确的停止条件控制扩散面。")
    values.append("在变更前固化快照/镜像/补丁卸载路径，并设定可用性、登录成功率与创建成功率的中止阈值。")
    if "host" in event.roles or "directory" in event.roles:
        values.append("宿主机或目录服务的故障半径较大：使用独立维护窗口、更小灰度单元和双重回滚验证。")
    return _unique(values, 4)


def _exploration_questions(
    event: Event, environment: Optional[Mapping[str, object]] = None,
) -> List[str]:
    values = ["我们实际的 Windows 版本、Edition、Build、KB 和安装角色，是否与官方适用范围精确相交？"]
    if event.preconditions:
        values.append("官方触发条件中的镜像、驱动、补丁组合或管理方式，哪些存在于我们的交付链路？")
    values.append("清洁安装、存量升级、镜像克隆与回收桌面的表现是否不同？")
    values.append("复现时需要固化哪些 Windows 事件日志、崩溃转储、会话日志、交付任务日志和性能指标？")
    if "host" in event.roles or "guest" in event.roles:
        values.append("宿主机与来宾系统的补丁前/后混合组合中，问题的边界和最小触发条件是什么？")
    values.append("临时缓解、修复版本和回滚路径是否均已在代表性环境证明可用？")
    architectures = _architecture_order(environment)
    if _is_product_portfolio(environment) and architectures:
        values.insert(
            1,
            f"该变化分别通过哪条链路影响 {'、'.join(architectures)}？"
            "哪些是共性 Windows 风险，哪些只在特定交付架构成立？",
        )
    return _unique(values)


def _applicability(
    event: Event, environment: Optional[Mapping[str, object]] = None,
) -> str:
    if event.asset_matches:
        count = f"，候选影响数量 {event.affected_asset_count}" if event.affected_asset_count else ""
        return f"已命中内部资产队列：{'、'.join(event.asset_matches)}{count}。这仅表示版本/角色可能相交，仍需通过复现确认实际影响。"
    if _is_product_portfolio(environment) and event.environment_relevance > 0:
        architectures = _architecture_order(environment)
        scope = "、".join(architectures) or "已配置架构"
        return (
            f"已命中原厂产品验证范围，需按 {scope} 分架构核验；"
            "这表示产品组合需要覆盖，不表示所有客户环境都已受影响。"
        )
    return "尚未命中可用的内部资产画像，因此只能给出潜在影响，不能断言已影响本项目。请优先核对版本、Edition、Build、Guest/Host 角色和关键组件。"


def build_cloud_desktop_guidance(
    event: Event, environment: Optional[Mapping[str, object]] = None,
) -> CloudDesktopGuidance:
    event.normalized()
    return CloudDesktopGuidance(
        problem_summary=_problem_summary(event),
        potential_impacts=_potential_impacts(event),
        recommended_tests=_recommended_tests(event, environment),
        preventive_actions=_preventive_actions(event),
        exploration_questions=_exploration_questions(event, environment),
        applicability=_applicability(event, environment),
    )
