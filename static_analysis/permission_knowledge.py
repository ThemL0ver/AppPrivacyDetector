"""
Android 权限知识库模块 (Permission Knowledge Base)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
模块功能概述：
  本模块是 App 隐私检测系统的核心知识引擎，负责:
  1. 维护 Android 系统权限与厂商自定义权限的结构化知识目录
  2. 提供权限风险等级（低/中/中高/高/极高）的标准化定义
  3. 支持精确权限查找 + 关键词模糊匹配 + 保护级别兜底 三级分类策略
  4. 提供 CSV / Excel 格式的知识库导出能力

设计依据：
  - GB/T 35273-2020《个人信息安全规范》
  - GB/T 41391-2022《App收集个人信息基本要求》
  - Android 运行时权限模型与保护级别机制
  - 移动智能终端补充设备标识识别规则
  - 最小必要原则

使用示例：
  >>> kb = PermissionKnowledgeBase(DEFAULT_PERMISSION_ROWS)
  >>> result = kb.classify("android.permission.CAMERA", source="requested_permission")
  >>> print(result["风险等级"])  # 输出: 高
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, Iterable, List, Optional

# ──────────────────────────────────────────────────
# 权限目录表头定义
# ──────────────────────────────────────────────────
# 定义知识库 CSV 文件的列名，覆盖权限标识、中文名、风险分级、隐私属性和判定依据
CATALOG_HEADERS = [
    "权限名",
    "权限中文名",
    "风险等级",
    "权限说明",
    "Android保护级别",
    "隐私属性",
    "风险维度",
    "判定依据",
    "备注",
]

# ──────────────────────────────────────────────────
# 风险等级量化映射表
# ──────────────────────────────────────────────────
# 将中文风险等级映射为整数优先级，数值越大表示风险越高
# 用于排序、加权计算等场景
RISK_PRIORITY = {"低": 1, "中": 2, "中高": 3, "高": 4, "极高": 5}

# 风险权重表，与 RISK_PRIORITY 值一致，用于计算综合风险等级
# 当需要按权重汇总多个权限的风险得分时使用
RISK_WEIGHT = {
    "低": 1,
    "中": 2,
    "中高": 3,
    "高": 4,
    "极高": 5,
}


def row(
    permission: str,
    title: str,
    risk: str,
    description: str,
    protection: str,
    privacy: str,
    dimension: str,
    basis: str,
    note: str = "",
) -> Dict[str, str]:
    """构造一条结构化的权限知识条目。

    将分散的权限属性字段组装为标准字典格式，统一作为知识库的基本数据单元。

    参数:
        permission:  Android 权限常量名，如 "android.permission.CAMERA"
        title:       权限中文名称，如 "拍摄照片和视频"
        risk:        风险等级（低/中/中高/高/极高）
        description: 权限功能说明
        protection:  Android 保护级别描述（危险权限/普通权限/特殊权限/签名权限/厂商/自定义）
        privacy:     隐私属性分类（强隐私/中隐私/弱隐私/非隐私）
        dimension:   风险维度分类（隐私泄露/设备控制/后台行为/网络能力/跨应用数据/系统兼容）
        basis:       风险判定依据（引用的法规标准或评估规则）
        note:        补充备注信息，默认空字符串

    返回:
        Dict[str, str]: 包含全部字段的标准权限条目字典
    """
    return {
        "权限名": permission,
        "权限中文名": title,
        "风险等级": risk,
        "权限说明": description,
        "Android保护级别": protection,
        "隐私属性": privacy,
        "风险维度": dimension,
        "判定依据": basis,
        "备注": note,
    }


# ──────────────────────────────────────────────────
# 内置权限分组（按风险等级划分）
# ──────────────────────────────────────────────────
# 每个分组以元组形式组织：(风险等级, 保护级别, 隐私属性, 风险维度, 判定依据, [权限列表])
# 权限列表中每条为 (权限常量名, 中文名, 功能说明)
PERMISSION_GROUPS = [
    # ── 极高风险：涉及短信、通话记录、日志、无障碍等强隐私数据 ──
    (
        "极高",
        "危险权限",
        "强隐私",
        "隐私泄露",
        "GB/T 35273、GB/T 41391、最小必要原则",
        [
            ("android.permission.READ_SMS", "读取短信", "允许读取短信正文、验证码等通信内容"),
            ("android.permission.RECEIVE_SMS", "接收短信", "允许监听和接收短信内容"),
            ("android.permission.SEND_SMS", "发送短信", "允许主动发送短信或触发资费行为"),
            ("android.permission.WRITE_SMS", "写入短信", "允许修改、插入或删除短信数据"),
            ("android.permission.READ_CALL_LOG", "读取通话记录", "允许访问通话记录、号码和时长"),
            ("android.permission.WRITE_CALL_LOG", "写入通话记录", "允许篡改或写入通话记录"),
            ("android.permission.PROCESS_OUTGOING_CALLS", "处理外拨电话", "允许监听或重定向外拨行为"),
            ("android.permission.READ_LOGS", "读取系统日志", "允许读取应用与系统运行日志"),
            ("android.permission.PACKAGE_USAGE_STATS", "读取应用使用情况", "允许统计应用启动、驻留和切换行为"),
            (
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "绑定无障碍服务",
                "允许接管界面事件、读取屏幕内容并执行自动化操作",
            ),
            ("android.permission.READ_PRIVILEGED_PHONE_STATE", "读取特权电话状态", "允许获取高敏感设备识别信息"),
            ("android.permission.MANAGE_EXTERNAL_STORAGE", "管理全部外部存储", "允许访问整个共享存储空间"),
        ],
    ),
    # ── 高风险：Android 运行时危险权限，涉及位置、摄像头、麦克风、通讯录等 ──
    (
        "高",
        "危险权限",
        "强隐私",
        "隐私泄露",
        "Android 运行时权限、GB/T 35273、敏感个人信息识别要求",
        [
            ("android.permission.READ_CONTACTS", "读取通讯录", "允许读取联系人、手机号和备注等数据"),
            ("android.permission.WRITE_CONTACTS", "写入通讯录", "允许修改或新增联系人信息"),
            ("android.permission.READ_PHONE_STATE", "读取电话状态", "允许读取 SIM、设备标识和通话状态"),
            ("android.permission.READ_PHONE_NUMBERS", "读取本机号码", "允许访问本机号码等标识"),
            ("android.permission.CAMERA", "拍摄照片和视频", "允许使用摄像头采集图像或视频"),
            ("android.permission.RECORD_AUDIO", "录制音频", "允许使用麦克风采集语音"),
            ("android.permission.ACCESS_FINE_LOCATION", "精确位置", "允许获取 GPS 等高精度位置"),
            ("android.permission.ACCESS_BACKGROUND_LOCATION", "后台位置", "允许持续获取后台位置"),
            ("android.permission.READ_EXTERNAL_STORAGE", "读取外部存储", "允许访问图片、文件、音视频等数据"),
            ("android.permission.WRITE_EXTERNAL_STORAGE", "写入外部存储", "允许新增、修改或删除共享存储文件"),
            ("android.permission.READ_MEDIA_IMAGES", "读取图片媒体", "允许访问设备图片和相册数据"),
            ("android.permission.READ_MEDIA_VIDEO", "读取视频媒体", "允许访问设备视频数据"),
            ("android.permission.READ_MEDIA_AUDIO", "读取音频媒体", "允许访问设备音频数据"),
            ("android.permission.READ_CALENDAR", "读取日历", "允许读取行程、会议和提醒数据"),
            ("android.permission.WRITE_CALENDAR", "写入日历", "允许修改日历和提醒事项"),
            ("android.permission.GET_ACCOUNTS", "读取账户", "允许访问设备已登录账户信息"),
            ("android.permission.BODY_SENSORS", "读取身体传感器", "允许访问运动、心率等生理数据"),
            ("android.permission.QUERY_ALL_PACKAGES", "查询全部应用", "允许枚举设备上已安装应用"),
        ],
    ),
    # ── 中高风险：特殊权限，涉及系统弹窗、生物识别、蓝牙/截屏感知等 ──
    (
        "中高",
        "特殊权限",
        "中隐私",
        "设备控制",
        "系统特殊权限、越权控制面评估、跨应用可见性约束",
        [
            ("android.permission.SYSTEM_ALERT_WINDOW", "悬浮窗显示", "允许在其他应用之上绘制界面"),
            ("android.permission.WRITE_SETTINGS", "修改系统设置", "允许修改系统配置项"),
            ("android.permission.REQUEST_INSTALL_PACKAGES", "请求安装应用", "允许发起 APK 安装流程"),
            ("android.permission.ACCESS_COARSE_LOCATION", "粗略位置", "允许获取基站/Wi-Fi 级位置"),
            ("android.permission.BLUETOOTH_SCAN", "蓝牙扫描", "允许扫描周边蓝牙设备"),
            ("android.permission.BLUETOOTH_CONNECT", "蓝牙连接", "允许与周边蓝牙设备建立连接"),
            ("android.permission.NEARBY_WIFI_DEVICES", "附近 Wi-Fi 设备", "允许枚举附近 Wi-Fi 设备"),
            ("android.permission.DETECT_SCREEN_CAPTURE", "检测截屏", "允许感知用户截屏行为"),
            ("android.permission.DETECT_SCREEN_RECORDING", "检测录屏", "允许感知用户录屏行为"),
            ("android.permission.USE_BIOMETRIC", "生物识别", "允许使用人脸、指纹等认证能力"),
            ("android.permission.USE_FINGERPRINT", "指纹识别", "允许调用指纹认证能力"),
            ("org.fidoalliance.uaf.permissions.FIDO_CLIENT", "FIDO 身份认证", "允许调用 FIDO 生物认证能力"),
            ("android.permission.SCHEDULE_EXACT_ALARM", "精确定时任务", "允许精确闹钟和持续后台唤醒"),
        ],
    ),
    # ── 中风险：拨号、通知、任务栈等涉及后台行为的普通权限 ──
    (
        "中",
        "普通权限",
        "弱隐私",
        "后台行为",
        "最小必要原则、后台唤醒和跨应用交互约束",
        [
            ("android.permission.CALL_PHONE", "直接拨号", "允许应用直接发起电话呼叫"),
            ("android.permission.ANSWER_PHONE_CALLS", "接听电话", "允许程序代接电话"),
            ("android.permission.POST_NOTIFICATIONS", "发送通知", "允许在系统通知栏推送通知"),
            ("android.permission.REORDER_TASKS", "重排任务栈", "允许影响任务切换顺序"),
            ("android.permission.GET_PACKAGE_SIZE", "读取包体大小", "允许读取应用存储占用情况"),
            ("android.permission.CHANGE_CONFIGURATION", "修改系统配置", "允许调整部分运行配置"),
            ("android.permission.READ_MEDIA_VISUAL_USER_SELECTED", "读取用户选定媒体", "允许访问用户授权的部分照片或视频"),
            ("android.permission.READ_BASIC_PHONE_STATE", "读取基础设备状态", "允许访问去标识化后的设备基础状态"),
            ("android.permission.FOREGROUND_SERVICE_CAMERA", "前台相机服务", "允许以前台服务方式持续调用相机"),
            ("android.permission.FOREGROUND_SERVICE_MICROPHONE", "前台麦克风服务", "允许以前台服务方式持续调用麦克风"),
        ],
    ),
    # ── 低风险：网络、震动、壁纸等基础设施类权限，不直接触及个人信息 ──
    (
        "低",
        "普通权限",
        "非隐私",
        "网络能力",
        "网络连通和基础运行能力，一般不直接触及个人信息",
        [
            ("android.permission.INTERNET", "访问网络", "允许建立网络连接和访问互联网"),
            ("android.permission.ACCESS_NETWORK_STATE", "获取网络状态", "允许读取网络连接状态"),
            ("android.permission.ACCESS_WIFI_STATE", "获取 Wi-Fi 状态", "允许读取 Wi-Fi 连接状态"),
            ("android.permission.CHANGE_NETWORK_STATE", "改变网络状态", "允许变更网络连接状态"),
            ("android.permission.CHANGE_WIFI_STATE", "改变 Wi-Fi 状态", "允许变更 Wi-Fi 连接状态"),
            ("android.permission.CHANGE_WIFI_MULTICAST_STATE", "Wi-Fi 组播", "允许接收 Wi-Fi 组播数据"),
            ("android.permission.FOREGROUND_SERVICE", "前台服务", "允许以前台服务方式持续运行"),
            ("android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK", "媒体播放前台服务", "允许播放类前台服务"),
            ("android.permission.FOREGROUND_SERVICE_DATA_SYNC", "数据同步前台服务", "允许同步类前台服务"),
            ("android.permission.WAKE_LOCK", "保持唤醒", "允许设备在后台任务期间保持唤醒"),
            ("android.permission.VIBRATE", "震动控制", "允许调用震动器"),
            ("android.permission.MODIFY_AUDIO_SETTINGS", "音频设置", "允许修改音频输出模式"),
            ("android.permission.BLUETOOTH", "蓝牙基础访问", "允许使用基础蓝牙能力"),
            ("android.permission.BLUETOOTH_ADMIN", "蓝牙管理", "允许管理蓝牙连接"),
            ("android.permission.SET_WALLPAPER_HINTS", "壁纸提示", "允许更新壁纸建议区域"),
            ("android.permission.HIGH_SAMPLING_RATE_SENSORS", "高采样传感器", "允许访问高采样率传感器"),
        ],
    ),
]

# ──────────────────────────────────────────────────
# 厂商自定义及特殊权限条目
# ──────────────────────────────────────────────────
# 这些权限并非标准 Android AOSP 权限，而是由各手机厂商或行业联盟定义的
# 主要覆盖：OAID/DID 等设备标识、桌面快捷方式、角标控制、推送服务等
# 使用 row() 辅助函数统一构造结构化条目
SPECIAL_PERMISSION_ROWS = [
    # ── 设备标识类权限（高风险）──
    row(
        "com.nemu.oaid.permission.read",
        "读取 OAID",
        "高",
        "允许读取设备开放匿名标识 OAID",
        "厂商/自定义",
        "强隐私",
        "跨应用数据",
        "移动智能终端补充设备标识识别规则、最小必要原则",
    ),
    row(
        "com.nemu.oaid.permission.write",
        "写入 OAID",
        "高",
        "允许写入或维护设备开放匿名标识",
        "厂商/自定义",
        "强隐私",
        "跨应用数据",
        "移动智能终端补充设备标识识别规则、最小必要原则",
    ),
    row(
        "com.vivo.identifier.permission.OAID_STATE",
        "访问 OAID 状态",
        "高",
        "允许访问 vivo 设备的匿名标识状态",
        "厂商/自定义",
        "强隐私",
        "跨应用数据",
        "厂商标识接口能力、最小必要原则",
    ),
    row(
        "com.asus.msa.SupplementaryDID.ACCESS",
        "访问补充设备标识",
        "高",
        "允许访问厂商补充设备标识 DID/AAID",
        "厂商/自定义",
        "强隐私",
        "跨应用数据",
        "终端标识接口约束、最小必要原则",
    ),
    row(
        "freemme.permission.msa.SECURITY_ACCESS",
        "访问设备标识服务",
        "高",
        "允许访问厂商移动安全联盟设备标识能力",
        "厂商/自定义",
        "强隐私",
        "跨应用数据",
        "MSA 设备标识接口约束、最小必要原则",
    ),
    row(
        "com.bun.msa.permission.ACCESS",
        "访问 MSA 标识",
        "高",
        "允许访问移动安全联盟设备标识服务",
        "厂商/自定义",
        "强隐私",
        "跨应用数据",
        "MSA 设备标识接口约束、最小必要原则",
    ),
    # ── 桌面快捷方式类权限（中风险）──
    row(
        "com.android.launcher.permission.INSTALL_SHORTCUT",
        "安装桌面快捷方式",
        "中",
        "允许应用在桌面创建快捷方式",
        "厂商/自定义",
        "非隐私",
        "跨应用数据",
        "跨应用展示面控制、最小必要原则",
    ),
    row(
        "com.android.launcher.permission.UNINSTALL_SHORTCUT",
        "卸载桌面快捷方式",
        "中",
        "允许应用移除桌面快捷方式",
        "厂商/自定义",
        "非隐私",
        "跨应用数据",
        "跨应用展示面控制、最小必要原则",
    ),
    # ── 桌面设置与角标类权限（低风险）──
    row(
        "com.android.launcher.permission.READ_SETTINGS",
        "读取桌面设置",
        "低",
        "允许读取桌面启动器设置",
        "厂商/自定义",
        "非隐私",
        "系统兼容",
        "厂商桌面兼容适配",
    ),
    row(
        "com.android.launcher3.permission.READ_SETTINGS",
        "读取桌面设置",
        "低",
        "允许读取 Launcher3 启动器设置",
        "厂商/自定义",
        "非隐私",
        "系统兼容",
        "厂商桌面兼容适配",
    ),
    row(
        "com.huawei.android.launcher.permission.CHANGE_BADGE",
        "修改华为角标",
        "低",
        "允许更新华为桌面角标",
        "厂商/自定义",
        "非隐私",
        "系统兼容",
        "厂商消息角标兼容适配",
    ),
    row(
        "com.huawei.android.launcher.permission.READ_SETTINGS",
        "读取华为桌面设置",
        "低",
        "允许读取华为桌面设置",
        "厂商/自定义",
        "非隐私",
        "系统兼容",
        "厂商桌面兼容适配",
    ),
    row(
        "com.vivo.notification.permission.BADGE_ICON",
        "控制 vivo 角标",
        "低",
        "允许控制 vivo 设备桌面角标显示",
        "厂商/自定义",
        "非隐私",
        "系统兼容",
        "厂商消息角标兼容适配",
    ),
    row(
        "com.xiaomi.permission.AUTH_SERVICE",
        "小米认证服务",
        "低",
        "允许对接小米系统服务或推送鉴权接口",
        "厂商/自定义",
        "非隐私",
        "系统兼容",
        "厂商推送/系统服务兼容适配",
    ),
    # ── 厂商推送服务类权限（低风险）──
    row(
        "com.coloros.mcs.permission.RECIEVE_MCS_MESSAGE",
        "OPPO 推送消息",
        "低",
        "允许接收 OPPO/ColorOS 推送消息",
        "厂商/自定义",
        "非隐私",
        "后台行为",
        "厂商推送服务接入",
    ),
    row(
        "com.heytap.mcs.permission.RECIEVE_MCS_MESSAGE",
        "HeyTap 推送消息",
        "低",
        "允许接收 OPPO/HeyTap 推送消息",
        "厂商/自定义",
        "非隐私",
        "后台行为",
        "厂商推送服务接入",
    ),
    row(
        "com.hihonor.push.permission.READ_PUSH_NOTIFICATION_INFO",
        "荣耀推送通知信息",
        "低",
        "允许读取荣耀推送通知展示信息",
        "厂商/自定义",
        "非隐私",
        "后台行为",
        "厂商推送服务接入",
    ),
    # ── FIDO 生物认证（中高风险）──
    row(
        "org.fidoalliance.uaf.permissions.FIDO_CLIENT",
        "FIDO 客户端认证",
        "中高",
        "允许对接 FIDO 生物特征认证流程",
        "厂商/自定义",
        "中隐私",
        "设备控制",
        "身份认证增强能力、最小必要原则",
    ),
]

# ──────────────────────────────────────────────────
# 构建默认权限知识条目列表
# ──────────────────────────────────────────────────
# 第一步：遍历 PERMISSION_GROUPS，将每个分组的元数据与具体权限组合成 row 字典
# 第二步：追加 SPECIAL_PERMISSION_ROWS（厂商自定义权限）
DEFAULT_PERMISSION_ROWS: List[Dict[str, str]] = []
for risk, protection, privacy, dimension, basis, items in PERMISSION_GROUPS:
    for permission, title, description in items:
        DEFAULT_PERMISSION_ROWS.append(
            row(permission, title, risk, description, protection, privacy, dimension, basis)
        )
DEFAULT_PERMISSION_ROWS.extend(SPECIAL_PERMISSION_ROWS)


# ──────────────────────────────────────────────────
# 关键词模糊匹配规则
# ──────────────────────────────────────────────────
# 当权限名无法精确匹配知识库条目时，按关键词子串匹配进行分类
# 每条规则包含: 关键词列表(patterns)、对应的风险等级、隐私属性、风险维度、保护级别、备注
# 匹配顺序即规则列表顺序，命中第一条即返回
KEYWORD_RULES = [
    # 规则1：极高风险关键词 —— 短信、通话记录、日志、无障碍等高敏感模式
    {
        "patterns": ("read_sms", "receive_sms", "send_sms", "write_sms", "call_log", "accessibility", "read_logs"),
        "风险等级": "极高",
        "隐私属性": "强隐私",
        "风险维度": "隐私泄露",
        "Android保护级别": "危险权限",
        "备注": "命中短信、通话记录、日志或无障碍高敏感规则",
    },
    # 规则2：高风险关键词 —— 设备标识、位置、音视频、应用枚举等敏感模式
    {
        "patterns": (
            "oaid",
            "msa",
            "identifier",
            "device_id",
            "did",
            "phone_state",
            "contacts",
            "camera",
            "record_audio",
            "microphone",
            "fine_location",
            "background_location",
            "external_storage",
            "read_media",
            "calendar",
            "query_all_packages",
        ),
        "风险等级": "高",
        "隐私属性": "强隐私",
        "风险维度": "隐私泄露",
        "Android保护级别": "危险权限",
        "备注": "命中设备标识、位置、音视频或应用枚举规则",
    },
    # 规则3：中高风险关键词 —— 位置、浮窗、系统设置、生物识别等设备控制模式
    {
        "patterns": (
            "coarse_location",
            "system_alert_window",
            "overlay",
            "write_settings",
            "install_packages",
            "biometric",
            "fingerprint",
            "bluetooth_scan",
            "bluetooth_connect",
            "detect_screen_capture",
            "detect_screen_recording",
            "fido",
        ),
        "风险等级": "中高",
        "隐私属性": "中隐私",
        "风险维度": "设备控制",
        "Android保护级别": "特殊权限",
        "备注": "命中设备控制、截屏感知或认证增强规则",
    },
    # 规则4：中风险关键词 —— 快捷方式、通知、推送、桌面设置等后台行为模式
    {
        "patterns": (
            "install_shortcut",
            "uninstall_shortcut",
            "notifications",
            "notification",
            "push",
            "badge",
            "change_configuration",
            "get_package_size",
            "read_settings",
            "launcher.permission",
        ),
        "风险等级": "中",
        "隐私属性": "弱隐私",
        "风险维度": "后台行为",
        "Android保护级别": "厂商/自定义",
        "备注": "命中通知、推送、快捷方式或兼容设置规则",
    },
]


def normalize_risk_level(value: Optional[str]) -> str:
    """标准化风险等级字符串。

    将各种格式（中文、英文、组合格式）的风险等级统一映射为
    标准的中文风险等级（低/中/中高/高/极高）。

    参数:
        value: 待标准化的风险等级，支持中文/英文/组合格式，可为 None

    返回:
        str: 标准化后的中文风险等级，默认为 "低"
    """
    # 去除空白并统一为小写，消除格式差异
    raw = str(value or "").strip().lower()
    # 空值兜底为最低风险等级
    if not raw:
        return "低"
    # 极高：匹配英文极高级别或中文"极高"
    if raw in {"very_high", "critical", "extreme"} or "极高" in raw:
        return "极高"
    # 高：精确匹配
    if raw == "high" or raw == "高":
        return "高"
    # 中高：匹配英文组合格式或中文
    if raw in {"medium_high", "mid_high"} or "中高" in raw:
        return "中高"
    # 中：精确匹配
    if raw == "medium" or raw == "中":
        return "中"
    # 其余情况统一归为低
    return "低"


def normalize_protection_level(value: Optional[str]) -> str:
    """标准化 Android 权限保护级别字符串。

    支持三种输入格式的标准化：
    - 十六进制值（如 0x1）：按 Android protectionLevel 位掩码解析
    - 英文描述（如 dangerous, signature）：关键词匹配
    - 中文描述：原样保留

    参数:
        value: 待标准化的保护级别，支持十六进制/英文/中文，可为 None

    返回:
        str: 标准化后的中文保护级别描述
    """
    # 去除空白并统一为小写
    raw = str(value or "").strip().lower()
    # 空值或无级别 → 未知
    if not raw or raw == "none":
        return "未知"
    # ── 十六进制模式解析 ──
    # Android protectionLevel 是一个位掩码整数，低 4 位表示基础级别
    if raw.startswith("0x"):
        try:
            # 解析十六进制并取低 4 位，屏蔽 flags 位
            base_value = int(raw, 16) & 0xF
        except ValueError:
            base_value = -1
        # Android 保护级别映射:
        # 0x0 = normal(普通), 0x1 = dangerous(危险), 0x2/0x3 = signature(签名), 0x4 = privileged(特权)
        mapping = {
            0: "普通权限",
            1: "危险权限",
            2: "签名权限",
            3: "签名权限",
            4: "特权权限",
        }
        return mapping.get(base_value, "未知")
    # ── 英文关键词匹配 ──
    if "dangerous" in raw:
        return "危险权限"
    if "signature" in raw:
        return "签名权限"
    if "privileged" in raw or "special" in raw or "appop" in raw:
        return "特殊权限"
    if "normal" in raw:
        return "普通权限"
    # 未命中任何规则
    return "未知"


class PermissionKnowledgeBase:
    """权限知识库。

    该类是隐私检测系统的权限分类引擎，职责如下：
    1. 从 CSV 文件或内置规则中加载权限目录数据
    2. 提供 O(1) 级别的精确权限名称查找
    3. 实现三级分类策略：精确匹配 → 关键词模糊匹配 → 保护级别兜底
    4. 支持将知识库导出为 CSV 和 Excel 格式

    属性:
        rows:    所有权限条目的列表（List[Dict[str, str]]）
        by_name: 权限名 → 权限条目的快速查找字典（Dict[str, Dict[str, str]]）

    分类策略优先级:
        第1级 — 精确名称匹配（lookup）
        第2级 — 关键词模糊匹配（KEYWORD_RULES）
        第3级 — 声明型签名权限降级处理
        第4级 — Android 标准权限根据保护级别推断
        第5级 — 厂商/自定义权限兜底归类
    """

    def __init__(self, rows: Iterable[Dict[str, str]]):
        """初始化知识库实例。

        参数:
            rows: 权限条目可迭代集合，每条为包含完整字段的字典
        """
        # 深拷贝避免外部修改影响内部状态
        self.rows = [dict(row) for row in rows]
        # 构建权限名 → 条目的 O(1) 查找索引
        self.by_name = {row["权限名"]: row for row in self.rows if row.get("权限名")}

    @classmethod
    def from_csv(cls, csv_path: Path) -> "PermissionKnowledgeBase":
        """从 CSV 文件加载知识库（工厂方法）。

        如果 CSV 文件不存在，则回退使用内置默认权限条目。

        参数:
            csv_path: CSV 文件的路径对象

        返回:
            PermissionKnowledgeBase: 加载完成的知识库实例
        """
        # CSV 文件缺失时使用内置规则兜底
        if not csv_path.exists():
            return cls(DEFAULT_PERMISSION_ROWS)

        # 使用 utf-8-sig 编码处理 BOM 头，newline="" 保持原始换行
        with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            rows = []
            for raw_row in reader:
                # 按标准表头清洗每个字段，去除首尾空白
                row_data = {header: str(raw_row.get(header, "")).strip() for header in CATALOG_HEADERS}
                # 仅保留有效权限名的条目，并对风险等级做标准化处理
                if row_data["权限名"]:
                    row_data["风险等级"] = normalize_risk_level(row_data.get("风险等级"))
                    rows.append(row_data)
        # 如果 CSV 有效条目为空，回退到内置规则
        return cls(rows or DEFAULT_PERMISSION_ROWS)

    def lookup(self, permission_name: str) -> Optional[Dict[str, str]]:
        """按权限名称精确查找。

        参数:
            permission_name: Android 权限常量名（如 "android.permission.CAMERA"）

        返回:
            Optional[Dict[str, str]]: 匹配的权限条目字典；未找到返回 None
        """
        return self.by_name.get(permission_name)

    def classify(
        self,
        permission_name: str,
        *,
        source: str = "requested_permission",
        label: str = "",
        description: str = "",
        raw_protection_level: str = "",
    ) -> Dict[str, str]:
        """对权限进行分级分类。

        采用多级分类策略，按优先级依次尝试：

        1. 知识库精确匹配 → 直接返回已知条目
        2. 关键词模糊匹配 → 遍历 KEYWORD_RULES 按子串命中分类
        3. 声明型签名权限降级 → 应用内部自定义签名权限标为低风险
        4. Android 标准权限兜底 → 根据保护级别推断风险等级
        5. 厂商自定义权限最低优先级 → 按来源区分中/低风险

        参数:
            permission_name:      权限全名
            source:               权限来源类型，"requested_permission"(请求型) 或 "declared_permission"(声明型)
            label:                可选的中文标签，缺失时用权限名最后一段
            description:          可选的权限说明
            raw_protection_level: 原始保护级别字符串（支持十六进制/英文），用于归一化

        返回:
            Dict[str, str]: 分类后的标准权限条目字典，包含完整的 9 个字段
        """
        # ── 第1级：精确匹配 ──
        entry = self.lookup(permission_name)
        if entry:
            return dict(entry)

        # ── 预处理：统一为小写便于关键词匹配 ──
        permission_lower = permission_name.lower()
        # 标准化保护级别，供后续推断使用
        normalized_protection = normalize_protection_level(raw_protection_level)

        # ── 第2级：关键词模糊匹配 ──
        # 遍历 KEYWORD_RULES 列表，按定义顺序匹配，命中第一条即返回
        for rule in KEYWORD_RULES:
            if any(pattern in permission_lower for pattern in rule["patterns"]):
                return {
                    "权限名": permission_name,
                    "权限中文名": label or permission_name.split(".")[-1],
                    "风险等级": rule["风险等级"],
                    "权限说明": description or "依据权限命名规则进行归类",
                    "Android保护级别": normalized_protection if normalized_protection != "未知" else rule["Android保护级别"],
                    "隐私属性": rule["隐私属性"],
                    "风险维度": rule["风险维度"],
                    "判定依据": "命名规则归类 + GB/T 35273 + GB/T 41391",
                    "备注": rule["备注"],
                }

        # ── 第3级：声明型签名权限降级处理 ──
        # 应用内部自定义的签名权限通常用于组件间安全通信，不涉及用户隐私
        if source == "declared_permission" and normalized_protection == "签名权限":
            return {
                "权限名": permission_name,
                "权限中文名": label or permission_name.split(".")[-1],
                "风险等级": "低",
                "权限说明": description or "应用自定义签名权限，主要用于组件内部隔离",
                "Android保护级别": normalized_protection,
                "隐私属性": "非隐私",
                "风险维度": "跨应用数据",
                "判定依据": "应用内部签名权限默认低风险，除非命中敏感关键字",
                "备注": "声明型签名权限，通常不直接构成隐私越界",
            }

        # ── 第4级：Android 标准权限兜底推断 ──
        # 对于 android.permission.* 命名的标准权限，根据其保护级别推断风险
        if permission_name.startswith("android.permission."):
            inferred_risk = "低"
            privacy = "非隐私"
            dimension = "系统兼容"
            # 危险权限 → 中高风险
            if normalized_protection == "危险权限":
                inferred_risk = "中高"
                privacy = "中隐私"
                dimension = "隐私泄露"
            # 特殊/特权权限 → 中高风险
            elif normalized_protection in {"特殊权限", "特权权限"}:
                inferred_risk = "中高"
                dimension = "设备控制"
            return {
                "权限名": permission_name,
                "权限中文名": label or permission_name.split(".")[-1],
                "风险等级": inferred_risk,
                "权限说明": description or "未命中精确规则，按照 Android 保护级别进行归类",
                "Android保护级别": normalized_protection,
                "隐私属性": privacy,
                "风险维度": dimension,
                "判定依据": "Android 保护级别兜底归类",
                "备注": "建议结合业务场景进一步校准",
            }

        # ── 第5级：厂商/自定义权限最低优先级兜底 ──
        # 既不是 android.permission.*，也未命中关键词规则的自定义权限
        # 按来源类型区分：请求型权限默认中风险，声明型默认低风险
        # 隐私属性根据权限名中的关键字进行启发式判断
        return {
            "权限名": permission_name,
            "权限中文名": label or permission_name.split(".")[-1],
            "风险等级": "中" if source == "requested_permission" else "低",
            "权限说明": description or "厂商或应用自定义权限，未命中显式规则时按中低风险处理",
            "Android保护级别": normalized_protection if normalized_protection != "未知" else "厂商/自定义",
            "隐私属性": "弱隐私" if any(token in permission_lower for token in ("provider", "share", "query")) else "非隐私",
            "风险维度": "跨应用数据",
            "判定依据": "自定义权限兜底归类",
            "备注": "如命中 OAID、位置、音视频等关键字会被提升风险等级",
        }

    def export(self, csv_path: Path, xlsx_path: Optional[Path] = None) -> None:
        """将知识库导出为 CSV（及可选 Excel）文件。

        导出的条目按风险等级降序排列，同等风险下按权限名升序排列。

        参数:
            csv_path:  CSV 输出文件路径
            xlsx_path: 可选的 Excel 输出文件路径，为 None 则跳过 Excel 导出
        """
        # 按风险优先级降序、权限名字母升序排列
        # 使用负号实现降序：高风险排在前面便于审阅
        sorted_rows = sorted(
            self.rows,
            key=lambda item: (-RISK_PRIORITY.get(item.get("风险等级", "低"), 0), item.get("权限名", "")),
        )
        # 确保输出目录存在
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        # 写入 CSV（utf-8-sig 保证 Excel 正确识别中文）
        with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=CATALOG_HEADERS)
            writer.writeheader()
            writer.writerows(sorted_rows)

        # 可选 Excel 导出（按需导入 pandas 避免强制依赖）
        if xlsx_path:
            import pandas as pd

            xlsx_path.parent.mkdir(parents=True, exist_ok=True)
            pd.DataFrame(sorted_rows, columns=CATALOG_HEADERS).to_excel(xlsx_path, index=False)


def export_default_catalog(base_dir: Path) -> None:
    """导出内置默认权限目录到指定目录。

    生成两个文件：
    - apk系统权限与风险.csv（CSV 格式）
    - apk系统权限与风险.xlsx（Excel 格式）

    参数:
        base_dir: 导出目标目录路径
    """
    # 使用内置默认权限条目构建知识库实例
    knowledge = PermissionKnowledgeBase(DEFAULT_PERMISSION_ROWS)
    # 同时导出 CSV 和 Excel 两种格式
    knowledge.export(
        base_dir / "apk系统权限与风险.csv",
        base_dir / "apk系统权限与风险.xlsx",
    )


# ──────────────────────────────────────────────────
# 模块直接执行入口
# ──────────────────────────────────────────────────
# 当直接运行此模块时，将默认权限目录导出到项目的 docs 目录
if __name__ == "__main__":
    export_default_catalog(Path(__file__).resolve().parents[1] / "docs")
