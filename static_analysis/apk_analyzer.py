# APK 静态分析器 - 负责解析 Android APK 文件，提取 Manifest、权限、组件及第三方库信息
# 核心功能：
# 1. 使用 androguard 库解析 APK 的 AndroidManifest.xml
# 2. 结合权限知识库对权限进行风险分级
# 3. 通过签名匹配检测第三方 SDK、框架和加固方案
# 4. 支持批量分析并导出 JSON 结果

from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# 定位项目根目录（当前文件向上两级）
PROJECT_ROOT = Path(__file__).resolve().parents[1]
# 将虚拟环境的 site-packages 添加到搜索路径，确保依赖库可被导入
SITE_PACKAGES = PROJECT_ROOT / ".venv" / "Lib" / "site-packages"
if str(SITE_PACKAGES) not in sys.path and SITE_PACKAGES.exists():
    sys.path.append(str(SITE_PACKAGES))

# 配置 loguru 日志库：抑制 androguard 的详细日志输出，仅显示错误级别
try:
    from loguru import logger as loguru_logger

    loguru_logger.remove()
    loguru_logger.add(sys.stderr, level="ERROR")
except Exception:
    loguru_logger = None

# 配置标准 logging：将所有 androguard 相关 logger 级别设为 ERROR，减少干扰输出
logging.basicConfig(level=logging.ERROR)
for logger_name in list(logging.Logger.manager.loggerDict):
    if "androguard" in logger_name.lower():
        logging.getLogger(logger_name).setLevel(logging.ERROR)

# 导入 androguard 核心模块（由于路径设置需放在 sys.path 修改之后）
from androguard.core.apk import APK  # noqa: E402
from androguard.core.axml import AXMLPrinter  # noqa: E402

# 导入自定义的权限知识库模块
from static_analysis.permission_knowledge import (  # noqa: E402
    PermissionKnowledgeBase,
    normalize_protection_level,
    normalize_risk_level,
)

# Android XML 命名空间前缀，用于解析 Manifest 中的 android:xxx 属性
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
# 风险等级列表，从低到高排列
RISK_LEVELS = ("低", "中", "中高", "高", "极高")
# 高及以上风险等级集合，用于筛选敏感权限
HIGH_RISK_LEVELS = {"中高", "高", "极高"}

# 第三方 SDK 签名库
# 每个条目包含 SDK 名称、类别、风险提示、描述和匹配关键词
# 通过在 Manifest 内容和解压文件列表中匹配 patterns 来识别集成的 SDK
SDK_SIGNATURES = [
    {
        "name": "百度统计",
        "category": "analytics",
        "risk_hint": "中",
        "description": "埋点统计和行为分析 SDK",
        "patterns": ("baidumobad_stat_id", "com.baidu.mobad", "baidu.mobstat", "baidu_tj_"),
    },
    {
        "name": "今日头条穿山甲",
        "category": "ad",
        "risk_hint": "中高",
        "description": "广告投放与归因 SDK",
        "patterns": ("openadsdk", "tt_pangolin", "bytedance.sdk.openadsdk"),
    },
    {
        "name": "华为厂商推送",
        "category": "push",
        "risk_hint": "低",
        "description": "华为 HMS Push 推送服务",
        "patterns": ("com.huawei.hms", "agconnect", "change_badge", "pushagent"),
    },
    {
        "name": "VIVO 厂商推送",
        "category": "push",
        "risk_hint": "低",
        "description": "vivo Push 推送服务",
        "patterns": ("com.vivo.push", "vivo.push", "badge_icon"),
    },
    {
        "name": "小米厂商推送",
        "category": "push",
        "risk_hint": "低",
        "description": "小米 MiPush 推送服务",
        "patterns": ("mipush", "xiaomi.push", "mipush_receive"),
    },
    {
        "name": "OPPO/HeyTap 推送",
        "category": "push",
        "risk_hint": "低",
        "description": "OPPO/HeyTap 推送服务",
        "patterns": ("heytap", "coloros.mcs", "oppo", "mcs_message"),
    },
    {
        "name": "荣耀厂商推送",
        "category": "push",
        "risk_hint": "低",
        "description": "荣耀 Push 推送服务",
        "patterns": ("hihonor.push", "honor.push"),
    },
    {
        "name": "微信开放平台",
        "category": "social",
        "risk_hint": "中",
        "description": "微信分享、登录或支付集成",
        "patterns": ("wxapi", "wechat", "com.tencent.mm"),
    },
    {
        "name": "微博开放平台",
        "category": "social",
        "risk_hint": "中",
        "description": "微博分享或登录集成",
        "patterns": ("weibo.sdk", "sina.weibo"),
    },
]

# 开发框架签名库
# 用于识别 APK 中使用的跨平台框架和底层组件，帮助理解应用的技术栈
FRAMEWORK_SIGNATURES = [
    {
        "name": "React Native",
        "description": "跨平台 JavaScript 渲染框架",
        "patterns": ("reactnativejni", "assets/index.android.bundle", "com/facebook/react"),
    },
    {
        "name": "Fresco",
        "description": "Facebook 图片渲染框架",
        "patterns": ("imagepipeline", "drawee", "native-imagetranscoder"),
    },
    {
        "name": "MMKV",
        "description": "腾讯高性能键值存储组件",
        "patterns": ("libmmkv", "com/tencent/mmkv"),
    },
    {
        "name": "Yoga",
        "description": "Facebook 跨平台布局引擎",
        "patterns": ("libyoga", "com/facebook/yoga"),
    },
    {
        "name": "WebP",
        "description": "WebP 图片编解码组件",
        "patterns": ("libwebp", "static-webp"),
    },
]

# 加固方案签名库
# 通过检测 APK 中的特征文件/库来判断应用是否使用了代码加固/混淆保护
REINFORCEMENT_SIGNATURES = [
    {"name": "360 Jiagu", "patterns": ("libjiagu", "jiagu_data.bin")},
    {"name": "爱加密", "patterns": ("ijiami", "libexecmain", "libexec.so")},
    {"name": "梆梆加固", "patterns": ("bangcle", "libsecmain", "libDexHelper")},
    {"name": "娜迦加固", "patterns": ("libnqshield", "nqshield")},
    {"name": "通付盾/阿里聚安全", "patterns": ("libsgmain", "sgsecuritybody")},
    {"name": "SecNeo", "patterns": ("secneo", "libDexHelper-x86")},
]


def ordered_unique(values: Iterable[str]) -> List[str]:
    """对字符串序列去重并保持原有顺序。

    用于去除 Manifest 解析中可能出现的重复条目（如重复声明的 Activity、权限等），
    同时保持首次出现的顺序。

    参数：
        values: 字符串迭代器

    返回：
        去重后的有序列表
    """
    seen = set()
    result: List[str] = []
    for value in values:
        # 过滤空字符串，只保留首次出现的非空值
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def safe_android_attr(element: Any, attr_name: str, default: str = "") -> str:
    """安全地获取 XML 元素的 android 命名空间属性。

    从 XML 元素中提取指定名称的 android 属性，自动添加 Android 命名空间前缀，
    并对结果做去空格处理。若属性不存在则返回默认值。

    参数：
        element: XML 元素对象
        attr_name: 属性名称（不含命名空间前缀，如 "name"、"value" 等）
        default: 属性缺失时的默认返回值

    返回：
        属性的字符串值（已去除首尾空白）
    """
    return str(element.get(f"{ANDROID_NS}{attr_name}", default) or default).strip()


class APKAnalyzer:
    """APK 静态分析器。

    负责从 APK 中提取 Manifest、组件、权限、queries、第三方 SDK、框架和加固特征，
    并将结构化结果输出为 JSON，供后续风险评分和 Web 展示模块使用。

    分析流程分为两个阶段：
    1. 解析阶段（parse_manifest）：加载 APK 并解析 AndroidManifest.xml
    2. 分析阶段（analyze_permissions / get_analysis_result）：基于解析结果进行权限分类和特征检测
    """

    def __init__(self, apk_path: str, output_dir: str = "output"):
        """初始化分析器。

        参数：
            apk_path: APK 文件的绝对或相对路径
            output_dir: 结果输出目录（当前未直接使用，由外部调用者控制）
        """
        self.apk_path = str(apk_path)
        self.output_dir = output_dir

        # androguard 的 APK 对象，在 parse_manifest 中初始化
        self.apk: Optional[APK] = None
        # 解析后的 AndroidManifest.xml 根元素
        self.manifest_xml = None
        # 加载权限知识库（CSV 文件），用于权限风险分类
        self.knowledge_base = PermissionKnowledgeBase.from_csv(
            PROJECT_ROOT / "docs" / "apk系统权限与风险.csv"
        )

        # 应用基本信息
        self.package_name = ""
        self.app_name = ""
        self.version_name = ""
        self.version_code = ""
        self.min_sdk = ""
        self.target_sdk = ""
        # 权限列表（三类来源的合并结果）
        self.permissions: List[str] = []
        self.requested_permissions: List[str] = []
        self.declared_permissions: List[str] = []
        self.implied_permissions: List[str] = []
        # 四大组件列表
        self.activities: List[str] = []
        self.services: List[str] = []
        self.receivers: List[str] = []
        self.providers: List[str] = []
        # 硬件/软件特性和库依赖
        self.features: List[str] = []
        self.libraries: List[str] = []
        # 应用元数据（meta-data）
        self.application_metadata: List[Dict[str, str]] = []
        # ContentProvider 的 authorities
        self.provider_authorities: List[str] = []
        # Android 11+ queries 声明
        self.queries: Dict[str, Any] = {"packages": [], "providers": [], "intents": []}
        # 第三方 SDK、框架和加固检测结果
        self.third_party_sdks: List[Dict[str, Any]] = []
        self.app_frameworks: List[Dict[str, Any]] = []
        self.analysis_flags: Dict[str, Any] = {}

        # ZIP 内文件列表（用于签名匹配的搜索范围）
        self._zip_entries: List[str] = []
        # 权限详情缓存（androguard 解析的原始数据）
        self._requested_permission_details: Dict[str, Any] = {}
        self._aosp_permission_details: Dict[str, Any] = {}
        self._declared_permission_details: Dict[str, Any] = {}

    def _load_apk(self) -> APK:
        """使用 androguard 加载 APK 文件。

        返回：
            解析后的 androguard APK 对象
        """
        return APK(self.apk_path)

    def _resolve_component_name(self, raw_name: str) -> str:
        """将清单文件中的相对组件名转换为完整限定名。

        Android Manifest 中组件名可使用相对形式：
        - ".SubActivity" → "com.example.app.SubActivity"
        - 无包名的简短名称 → "com.example.app.SimpleName"

        参数：
            raw_name: Manifest 中声明的原始组件名称

        返回：
            补全包名后的完整组件名
        """
        name = str(raw_name or "").strip()
        if not name:
            return ""
        # 以 "." 开头的是相对类名，需要拼上包名
        if name.startswith("."):
            return f"{self.package_name}{name}"
        # 不含 "." 的也是相对类名（常见于简单组件名）
        if "." not in name and self.package_name:
            return f"{self.package_name}.{name}"
        return name

    def _load_zip_entries(self) -> List[str]:
        """获取 APK（ZIP 格式）内的全部文件路径列表。

        返回：
            ZIP 内文件名列表，加载失败则返回空列表
        """
        try:
            with zipfile.ZipFile(self.apk_path, "r") as apk_file:
                return apk_file.namelist()
        except Exception:
            return []

    def _get_manifest_haystack(self) -> List[str]:
        """将所有 Manifest 相关数据汇集成一个搜索"草垛"。

        将权限名、组件名、特性、库、ZIP 条目、meta-data、queries 声明等
        所有文本信息合并为小写字符串列表，用于 SDK/框架/加固的签名匹配。

        返回：
            所有可搜索字符串的小写列表（去重前）
        """
        raw_values: List[str] = []
        raw_values.extend(self.permissions)
        raw_values.extend(self.activities)
        raw_values.extend(self.services)
        raw_values.extend(self.receivers)
        raw_values.extend(self.providers)
        raw_values.extend(self.features)
        raw_values.extend(self.libraries)
        raw_values.extend(self.provider_authorities)
        raw_values.extend(self._zip_entries)
        raw_values.extend(item.get("name", "") for item in self.application_metadata)
        raw_values.extend(item.get("value", "") for item in self.application_metadata)
        # 将 queries 中的 intent actions、categories 等也纳入搜索范围
        for intent in self.queries.get("intents", []):
            raw_values.extend(intent.get("actions", []))
            raw_values.extend(intent.get("categories", []))
            raw_values.extend(intent.get("schemes", []))
            raw_values.extend(intent.get("authorities", []))
        raw_values.extend(self.queries.get("packages", []))
        raw_values.extend(self.queries.get("providers", []))
        # 统一转为小写以支持大小写不敏感的匹配
        return [value.lower() for value in raw_values if value]

    def _extract_queries(self) -> Dict[str, Any]:
        """从 Manifest 中提取 Android 11+ 的 <queries> 声明。

        <queries> 声明了应用希望与其他应用进行交互的包名、Provider 和 Intent 过滤条件。
        自 Android 11 起，未在 queries 中声明的应用将在包可见性过滤中被隐藏。

        返回：
            包含 packages、providers、intents 三个列表的字典
        """
        if self.manifest_xml is None:
            return {"packages": [], "providers": [], "intents": []}

        packages: List[str] = []
        providers: List[str] = []
        intents: List[Dict[str, Any]] = []

        for query_element in self.manifest_xml.findall("queries"):
            # 提取 <package android:name="com.example.app" />
            for package_element in query_element.findall("package"):
                packages.append(safe_android_attr(package_element, "name"))

            # 提取 <provider android:authorities="com.example.provider" />
            for provider_element in query_element.findall("provider"):
                providers.append(safe_android_attr(provider_element, "authorities"))

            # 提取 <intent> 内的 action、category、data(scheme/host) 信息
            for intent_element in query_element.findall("intent"):
                actions = [safe_android_attr(node, "name") for node in intent_element.findall("action")]
                categories = [safe_android_attr(node, "name") for node in intent_element.findall("category")]
                schemes = [safe_android_attr(node, "scheme") for node in intent_element.findall("data")]
                authorities = [safe_android_attr(node, "host") for node in intent_element.findall("data")]
                intents.append(
                    {
                        "actions": ordered_unique(actions),
                        "categories": ordered_unique(categories),
                        "schemes": ordered_unique(schemes),
                        "authorities": ordered_unique(authorities),
                    }
                )

        return {
            "packages": ordered_unique(packages),
            "providers": ordered_unique(providers),
            "intents": intents,
        }

    def _extract_application_metadata(self) -> List[Dict[str, str]]:
        """提取 <application> 标签下声明的 meta-data 配置。

        常用于存放第三方 SDK 的初始化参数（如 AppID、渠道号等），
        是分析第三方服务集成的重要信息来源。

        返回：
            meta-data 字典列表，每个包含 name、value、resource 三个字段
        """
        if self.manifest_xml is None:
            return []

        app_element = self.manifest_xml.find("application")
        if app_element is None:
            return []

        metadata: List[Dict[str, str]] = []
        for node in app_element.findall("meta-data"):
            metadata.append(
                {
                    "name": safe_android_attr(node, "name"),
                    "value": safe_android_attr(node, "value"),
                    "resource": safe_android_attr(node, "resource"),
                }
            )
        return metadata

    def _extract_provider_authorities(self) -> List[str]:
        """提取 ContentProvider 的 authorities 属性列表。

        authorities 是 ContentProvider 的唯一标识，格式通常为包名.类名。
        分析 authorities 有助于了解应用对外提供的数据接口。

        返回：
            去重后的 authorities 列表
        """
        if self.manifest_xml is None:
            return []

        app_element = self.manifest_xml.find("application")
        if app_element is None:
            return []

        authorities = []
        for provider in app_element.findall("provider"):
            authorities.append(safe_android_attr(provider, "authorities"))
        return ordered_unique(authorities)

    def _normalize_implied_permissions(self, raw_permissions: Iterable[Any]) -> List[str]:
        """规范化 androguard 返回的隐含权限列表。

        androguard 的 get_uses_implied_permission_list() 可能返回多层嵌套结构，
        本方法将其展平为纯字符串列表。

        参数：
            raw_permissions: androguard 返回的原始隐含权限数据

        返回：
            规范化后的去重权限名列表
        """
        normalized: List[str] = []
        for item in raw_permissions or []:
            # 处理列表/元组嵌套：取第一个元素
            if isinstance(item, (list, tuple)):
                if item:
                    normalized.append(str(item[0]))
            elif item:
                normalized.append(str(item))
        return ordered_unique(normalized)

    def _detect_signatures(self, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """基于签名库在 Manifest 数据中进行模式匹配。

        对 haystack 中的每一项，逐一与签名库中每个签名的 patterns 做子串匹配，
        若任意 pattern 命中则视为检测到对应 SDK/框架/加固方案。

        参数：
            signatures: 签名条目列表，每项至少包含 name 和 patterns

        返回：
            检测到的签名条目列表，每项附带命中的证据（最多 5 条）
        """
        haystack = self._get_manifest_haystack()
        detections: List[Dict[str, Any]] = []

        for signature in signatures:
            evidences: List[str] = []
            for pattern in signature["patterns"]:
                # 在 haystack 中逐一搜索，找到一个匹配即可
                for entry in haystack:
                    if pattern in entry:
                        evidences.append(entry)
                        break
            if evidences:
                detection = {
                    "name": signature["name"],
                    "description": signature.get("description", ""),
                    "evidence": ordered_unique(evidences)[:5],
                }
                if "category" in signature:
                    detection["category"] = signature["category"]
                if "risk_hint" in signature:
                    detection["risk_hint"] = signature["risk_hint"]
                detections.append(detection)

        return detections

    def _detect_obfuscation(self) -> bool:
        """通过组件名称特征检测 APK 是否经过混淆处理。

        检测策略：统计所有组件名称分段中长度 ≤ 2 的短片段占比。
        如果短片段占比 ≥ 42%，判定为疑似混淆（混淆器通常生成 a、b、ab 等短类名）。

        返回：
            True 表示疑似经过混淆处理
        """
        # 收集所有组件名的分段（按 "." 分割）
        component_names = self.activities + self.services + self.receivers + self.providers
        segments: List[str] = []
        for name in component_names:
            for segment in name.split("."):
                segment = segment.strip()
                if segment:
                    segments.append(segment)
        if not segments:
            return False
        # 计算短分段（≤ 2 字符）占比
        short_segments = sum(1 for segment in segments if len(segment) <= 2)
        return (short_segments / len(segments)) >= 0.42

    def _collect_analysis_flags(self) -> Dict[str, Any]:
        """收集 APK 的结构特征标志。

        检测以下特征：
        - 多 DEX：是否存在 classes2.dex、classes3.dex 等（超出 64K 方法数限制）
        - Native 代码：是否包含 lib/ 下的 .so 文件
        - 混淆检测：调用 _detect_obfuscation
        - 加固检测：调用 _detect_signatures(REINFORCEMENT_SIGNATURES)
        - 查询面大小：queries 中声明的包、Provider、Intent 总数

        返回：
            包含各类分析标志的字典
        """
        # 检查是否存在第二个及以上的 DEX 文件（非 classes.dex）
        multi_dex = any(Path(name).name.startswith("classes") and name.endswith(".dex") and name != "classes.dex" for name in self._zip_entries)
        # 检查 lib/ 目录下是否有 .so 原生库文件
        uses_native_code = any(name.startswith("lib/") and name.endswith(".so") for name in self._zip_entries)
        reinforcement = self._detect_signatures(REINFORCEMENT_SIGNATURES)
        return {
            "multi_dex": multi_dex,
            "uses_native_code": uses_native_code,
            "suspected_obfuscation": self._detect_obfuscation(),
            "suspected_reinforcement": reinforcement,
            "query_surface_count": len(self.queries.get("packages", []))
            + len(self.queries.get("providers", []))
            + len(self.queries.get("intents", [])),
        }

    def _parse_manifest_by_zip_fallback(self) -> None:
        """降级解析方案：通过直接读取 ZIP 中的二进制 Manifest 来解析。

        当 androguard 的主解析流程失败时（如遇到非标准 APK 或不兼容的 Manifest），
        本方法使用 AXMLPrinter 将二进制 AndroidManifest.xml 转换为文本 XML，再使用
        ElementTree 进行手动解析。相比 androguard 的完整解析，降级方案不包含
        隐含权限和权限详情数据。

        异常：
            ValueError: 当 Manifest 文件格式无效时抛出
        """
        # 直接从 ZIP 中读取二进制 AndroidManifest.xml
        with zipfile.ZipFile(self.apk_path, "r") as apk_file:
            manifest_bytes = apk_file.read("AndroidManifest.xml")

        # 使用 AXMLPrinter 将二进制 XML 转换为可读文本
        axml = AXMLPrinter(manifest_bytes)
        if not axml.is_valid():
            raise ValueError("AndroidManifest.xml is invalid binary XML")

        manifest_payload = axml.get_xml()
        if isinstance(manifest_payload, bytes):
            manifest_text = manifest_payload.decode("utf-8", errors="ignore")
        else:
            manifest_text = str(manifest_payload)

        # 解析 XML 文本为 ElementTree 结构
        self.manifest_xml = ET.fromstring(manifest_text)
        self.package_name = str(self.manifest_xml.get("package", "") or "").strip()
        self.version_name = safe_android_attr(self.manifest_xml, "versionName")
        self.version_code = safe_android_attr(self.manifest_xml, "versionCode")

        # 提取 uses-sdk 中的最低和目标 SDK 版本
        uses_sdk = self.manifest_xml.find("uses-sdk")
        if uses_sdk is not None:
            self.min_sdk = safe_android_attr(uses_sdk, "minSdkVersion")
            self.target_sdk = safe_android_attr(uses_sdk, "targetSdkVersion")
        else:
            self.min_sdk = ""
            self.target_sdk = ""

        # 提取所有使用权限声明（包括普通权限和 SDK 23/Android M 权限）
        self.requested_permissions = ordered_unique(
            [
                safe_android_attr(node, "name")
                for tag in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m")
                for node in self.manifest_xml.findall(tag)
                if safe_android_attr(node, "name")
            ]
        )
        # 提取自定义权限声明
        self.declared_permissions = ordered_unique(
            [
                safe_android_attr(node, "name")
                for node in self.manifest_xml.findall("permission")
                if safe_android_attr(node, "name")
            ]
        )
        # 降级方案不支持隐含权限的提取
        self.implied_permissions = []
        self.permissions = ordered_unique(
            self.requested_permissions + self.declared_permissions + self.implied_permissions
        )

        # 提取应用名称：优先使用 label 属性，若以 "@" 开头（引用资源）则回退为包名
        app_element = self.manifest_xml.find("application")
        app_label = safe_android_attr(app_element, "label") if app_element is not None else ""
        self.app_name = app_label if app_label and not app_label.startswith("@") else self.package_name

        # 提取四大组件列表
        if app_element is None:
            self.activities = []
            self.services = []
            self.receivers = []
            self.providers = []
            self.libraries = []
        else:
            # 提取 Activity 列表，将相对名称补全为完整限定名
            self.activities = ordered_unique(
                [
                    self._resolve_component_name(safe_android_attr(node, "name"))
                    for node in app_element.findall("activity")
                    if safe_android_attr(node, "name")
                ]
            )
            # 提取 Service 列表
            self.services = ordered_unique(
                [
                    self._resolve_component_name(safe_android_attr(node, "name"))
                    for node in app_element.findall("service")
                    if safe_android_attr(node, "name")
                ]
            )
            # 提取 BroadcastReceiver 列表
            self.receivers = ordered_unique(
                [
                    self._resolve_component_name(safe_android_attr(node, "name"))
                    for node in app_element.findall("receiver")
                    if safe_android_attr(node, "name")
                ]
            )
            # 提取 ContentProvider 列表
            self.providers = ordered_unique(
                [
                    self._resolve_component_name(safe_android_attr(node, "name"))
                    for node in app_element.findall("provider")
                    if safe_android_attr(node, "name")
                ]
            )
            # 提取 uses-library 和 uses-native-library 声明的库依赖
            self.libraries = ordered_unique(
                [
                    safe_android_attr(node, "name")
                    for tag in ("uses-library", "uses-native-library")
                    for node in app_element.findall(tag)
                    if safe_android_attr(node, "name")
                ]
            )

        # 提取 uses-feature 声明（硬件/软件特性需求）
        self.features = ordered_unique(
            [
                safe_android_attr(node, "name") or safe_android_attr(node, "glEsVersion")
                for node in self.manifest_xml.findall("uses-feature")
                if safe_android_attr(node, "name") or safe_android_attr(node, "glEsVersion")
            ]
        )

        # 降级方案中权限详情不可用
        self._requested_permission_details = {}
        self._aosp_permission_details = {}
        self._declared_permission_details = {}

    def _finalize_manifest_state(self) -> None:
        """在 Manifest 基础信息解析完成后，调用各子分析方法完善结果。

        包括：meta-data 提取、Provider authorities 提取、queries 解析、
        ZIP 文件列表加载、SDK/框架/加固签名检测、分析标志收集。
        本方法在 parse_manifest 和 _parse_manifest_by_zip_fallback 两个流程中
        均会被调用，确保降级方案也能获得一致的结构化输出。
        """
        self.application_metadata = self._extract_application_metadata()
        self.provider_authorities = self._extract_provider_authorities()
        self.queries = self._extract_queries()
        self._zip_entries = self._load_zip_entries()

        self.third_party_sdks = self._detect_signatures(SDK_SIGNATURES)
        self.app_frameworks = self._detect_signatures(FRAMEWORK_SIGNATURES)
        self.analysis_flags = self._collect_analysis_flags()

    def parse_manifest(self) -> bool:
        """解析 APK 的 AndroidManifest.xml 与基础元数据。

        首先尝试使用 androguard 的完整解析流程，若失败则回退到 ZIP 降级解析。
        解析成功后会调用 _finalize_manifest_state 完成签名检测等后续分析。

        返回：
            True 表示解析成功（主解析或降级解析任一成功），False 表示全部失败
        """
        try:
            # 抑制 androguard 运行时的标准输出/错误输出，减少日志干扰
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.apk = self._load_apk()
                self.manifest_xml = self.apk.get_android_manifest_xml()

                # 使用 androguard API 提取基本应用信息
                self.package_name = self.apk.get_package()
                self.app_name = str(self.apk.get_app_name() or "")
                self.version_name = str(self.apk.get_androidversion_name() or "")
                self.version_code = str(self.apk.get_androidversion_code() or "")
                self.min_sdk = str(self.apk.get_min_sdk_version() or "")
                self.target_sdk = str(self.apk.get_target_sdk_version() or "")

                # 提取三类权限：请求权限、自定义权限、隐含权限
                self.requested_permissions = ordered_unique(self.apk.get_permissions() or [])
                self.declared_permissions = ordered_unique(self.apk.get_declared_permissions() or [])
                self.implied_permissions = self._normalize_implied_permissions(
                    self.apk.get_uses_implied_permission_list() or []
                )
                self.permissions = ordered_unique(
                    self.requested_permissions + self.declared_permissions + self.implied_permissions
                )

                # 提取四大组件和特性
                self.activities = ordered_unique(self.apk.get_activities() or [])
                self.services = ordered_unique(self.apk.get_services() or [])
                self.receivers = ordered_unique(self.apk.get_receivers() or [])
                self.providers = ordered_unique(self.apk.get_providers() or [])
                self.features = ordered_unique(self.apk.get_features() or [])
                self.libraries = ordered_unique(self.apk.get_libraries() or [])

                # 缓存权限详情数据，供后续分类使用
                self._requested_permission_details = self.apk.get_details_permissions() or {}
                self._aosp_permission_details = self.apk.get_requested_aosp_permissions_details() or {}
                self._declared_permission_details = self.apk.get_declared_permissions_details() or {}

            # 完成后续的签名检测和分析标志收集
            self._finalize_manifest_state()
            return True
        except Exception as primary_error:
            print(f"主解析失败，尝试降级解析: {self.apk_path} -> {primary_error}")
            try:
                self.apk = None
                self._parse_manifest_by_zip_fallback()
                self._finalize_manifest_state()
                print(f"降级解析成功: {self.apk_path}")
                return True
            except Exception as fallback_error:
                print(f"解析 APK 失败: {self.apk_path} -> {fallback_error}")
                return False

    def _resolve_permission_payload(
        self, permission_name: str, source: str
    ) -> Tuple[str, str, str]:
        """根据权限来源解析权限的标签、描述和保护级别。

        不同来源的权限数据格式不同，本方法统一处理三种来源：
        - declared_permission：应用自定义权限（数据结构为扁平字典）
        - requested_permission：通过 AOSP 详情或请求详情获取保护级别
        - implied_permission：通过请求详情获取

        参数：
            permission_name: 权限全名
            source: 权限来源类型

        返回：
            (label, description, raw_protection_level) 三元组
        """
        label = ""
        description = ""
        raw_protection = ""

        if source == "declared_permission":
            # 自定义权限：直接从 declared_permission_details 字典中取
            detail = self._declared_permission_details.get(permission_name, {})
            label = str(detail.get("label", "") or "")
            description = str(detail.get("description", "") or "")
            raw_protection = str(detail.get("protectionLevel", "") or "")
        else:
            # 先尝试从 AOSP 权限详情中查找
            detail = self._aosp_permission_details.get(permission_name)
            if isinstance(detail, dict):
                label = str(detail.get("label", "") or "")
                description = str(detail.get("description", "") or "")
                raw_protection = str(detail.get("protectionLevel", "") or "")
            elif permission_name in self._requested_permission_details:
                # AOSP 详情不可用时，回退到请求权限的原始数据（列表/元组格式）
                raw = self._requested_permission_details.get(permission_name, [])
                if isinstance(raw, (list, tuple)) and raw:
                    raw_protection = str(raw[0] or "")
                    if len(raw) > 1:
                        label = str(raw[1] or "")
                    if len(raw) > 2:
                        description = str(raw[2] or "")

        return label, description, raw_protection

    def _build_permission_detail(self, permission_name: str, source: str) -> Dict[str, Any]:
        """构造单条权限的完整结构化分析结果。

        结合权限知识库的分类信息和 androguard 的原始数据，为每条权限生成包含
        风险等级、隐私属性、保护级别、判定依据等字段的详细结果。

        参数：
            permission_name: 权限全名
            source: 权限来源类型

        返回：
            权限详细信息的字典
        """
        # 第一步：解析权限的标签、描述和保护级别原始数据
        label, description, raw_protection = self._resolve_permission_payload(permission_name, source)
        # 第二步：通过知识库获取权限的分类信息（风险等级、隐私属性等）
        catalog_entry = self.knowledge_base.classify(
            permission_name,
            source=source,
            label=label,
            description=description,
            raw_protection_level=raw_protection,
        )
        # 第三步：规范化风险等级和保护级别
        main_risk_level = normalize_risk_level(catalog_entry.get("风险等级"))
        protection_level = normalize_protection_level(raw_protection)

        # 若未解析到保护级别，使用知识库中的值作为补充
        if protection_level == "未知":
            protection_level = catalog_entry.get("Android保护级别", "未知")

        # 判断隐私相关性和风险标签
        privacy_attribute = catalog_entry.get("隐私属性", "非隐私")
        is_privacy_related = privacy_attribute != "非隐私"
        is_sensitive = main_risk_level in HIGH_RISK_LEVELS or privacy_attribute in {"强隐私", "中隐私"}
        is_dangerous = protection_level == "危险权限"

        return {
            "name": permission_name,
            "display_name": catalog_entry.get("权限中文名", ""),
            "description": catalog_entry.get("权限说明", ""),
            "risk_level": main_risk_level,
            "main_risk_level": main_risk_level,
            "android_protection_level": protection_level,
            "privacy_attribute": privacy_attribute,
            "risk_dimension": catalog_entry.get("风险维度", ""),
            "judgement_basis": catalog_entry.get("判定依据", ""),
            "notes": catalog_entry.get("备注", ""),
            "source": source,
            "is_dangerous": is_dangerous,
            "is_sensitive": is_sensitive,
            "is_privacy_related": is_privacy_related,
            # 非 android.permission. 开头的视为自定义权限
            "is_custom": not permission_name.startswith("android.permission."),
        }

    def analyze_permissions(self) -> Dict[str, Any]:
        """对所有权限进行风险分析和分类。

        遍历三类权限来源（请求权限、自定义权限、隐含权限），为每条权限生成
        详细的结构化信息，然后按风险等级、敏感度等维度进行汇总分类。

        返回：
            包含权限概览、分类统计、详细列表的综合分析结果字典
        """
        permission_details: List[Dict[str, Any]] = []
        seen_entries = set()

        # 定义权限来源与对应列表的映射，按优先级排列
        permission_sources = [
            ("requested_permission", self.requested_permissions),
            ("declared_permission", self.declared_permissions),
            ("implied_permission", self.implied_permissions),
        ]

        for source, permissions in permission_sources:
            for permission_name in permissions:
                # 去重：同一权限名+来源组合只处理一次
                entry_key = (source, permission_name)
                if entry_key in seen_entries:
                    continue
                seen_entries.add(entry_key)
                permission_details.append(self._build_permission_detail(permission_name, source))

        # 按风险等级分类
        risk_levels = {level: [] for level in RISK_LEVELS}
        dangerous_permissions: List[str] = []
        high_risk_permissions: List[str] = []
        sensitive_permissions: List[str] = []
        privacy_related_permissions: List[str] = []

        for detail in permission_details:
            risk_levels[detail["main_risk_level"]].append(detail["name"])
            if detail["is_dangerous"]:
                dangerous_permissions.append(detail["name"])
            if detail["main_risk_level"] in HIGH_RISK_LEVELS:
                high_risk_permissions.append(detail["name"])
            if detail["is_sensitive"]:
                sensitive_permissions.append(detail["name"])
            if detail["is_privacy_related"]:
                privacy_related_permissions.append(detail["name"])

        # 将权限详情分为敏感与非敏感两组，便于前端分类展示
        sensitive_permission_details = [item for item in permission_details if item["is_sensitive"]]
        other_permission_details = [item for item in permission_details if not item["is_sensitive"]]

        # 对各等级权限名去重
        risk_levels = {level: ordered_unique(values) for level, values in risk_levels.items()}

        return {
            "all_permissions": ordered_unique(self.permissions),
            "requested_permissions": list(self.requested_permissions),
            "declared_permissions": list(self.declared_permissions),
            "implied_permissions": list(self.implied_permissions),
            "dangerous_permissions": ordered_unique(dangerous_permissions),
            "high_risk_permissions": ordered_unique(high_risk_permissions),
            "sensitive_permissions": ordered_unique(sensitive_permissions),
            "privacy_related_permissions": ordered_unique(privacy_related_permissions),
            "other_permissions": ordered_unique(
                [item["name"] for item in permission_details if item["name"] not in sensitive_permissions]
            ),
            "risk_levels": risk_levels,
            "permission_details": permission_details,
            "sensitive_permission_details": sensitive_permission_details,
            "other_permission_details": other_permission_details,
            "permission_source_counts": {
                "requested_permission": len(self.requested_permissions),
                "declared_permission": len(self.declared_permissions),
                "implied_permission": len(self.implied_permissions),
            },
        }

    def get_analysis_result(self) -> Dict[str, Any]:
        """获取完整的 APK 分析结果。

        汇总 Manifest 解析数据和权限分析结果，生成供前端展示和 JSON 导出的
        完整结构化字典。

        返回：
            包含所有分析维度的综合结果字典
        """
        # 触发权限分析，获取详细分类结果
        permission_analysis = self.analyze_permissions()
        total_permission_entries = len(permission_analysis.get("permission_details", []))
        return {
            "package_name": self.package_name,
            "app_name": self.app_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "permissions": self.permissions,
            "requested_permissions": self.requested_permissions,
            "declared_permissions": self.declared_permissions,
            "implied_permissions": self.implied_permissions,
            "activities": self.activities,
            "services": self.services,
            "receivers": self.receivers,
            "providers": self.providers,
            "features": self.features,
            "libraries": self.libraries,
            "queries": self.queries,
            "application_metadata": self.application_metadata,
            "provider_authorities": self.provider_authorities,
            "third_party_sdks": self.third_party_sdks,
            "app_frameworks": self.app_frameworks,
            "analysis_flags": self.analysis_flags,
            "total_permissions": total_permission_entries,
            "permission_analysis": permission_analysis,
        }

    def save_result(self, output_file: str) -> None:
        """将分析结果保存为 JSON 文件。

        参数：
            output_file: 输出 JSON 文件路径
        """
        result = self.get_analysis_result()
        with open(output_file, "w", encoding="utf-8") as output_handle:
            json.dump(result, output_handle, ensure_ascii=False, indent=2)


class APKBatchAnalyzer:
    """APK 批量分析器。

    对指定目录下的所有 APK 文件进行批量静态分析，为每个 APK 生成独立的
    分析 JSON 文件，并汇总生成批量分析摘要。
    支持通过白名单（include_apks）过滤需要分析的文件。
    """

    def __init__(self, samples_dir: str, results_dir: str = "results", include_apks: Optional[List[str]] = None):
        """初始化批量分析器。

        参数：
            samples_dir: 存放 APK 样本的目录路径
            results_dir: 分析结果输出目录
            include_apks: 可选的文件名白名单，仅分析列表中指定的 APK 文件
        """
        self.samples_dir = samples_dir
        self.results_dir = results_dir
        self.include_apks = {item.strip() for item in (include_apks or []) if item.strip()}
        os.makedirs(results_dir, exist_ok=True)

    def analyze_all(self) -> List[Dict[str, Any]]:
        """对 samples_dir 下所有 APK 文件执行批量分析。

        遍历目录下所有 .apk 文件（若设置了白名单则过滤），逐一使用 APKAnalyzer
        进行解析和分析，保存结果并汇总。

        返回：
            所有成功分析的 APK 结果字典列表
        """
        results: List[Dict[str, Any]] = []
        # 获取目录下所有 .apk 文件，按名称排序
        apk_files = sorted(file for file in os.listdir(self.samples_dir) if file.lower().endswith(".apk"))
        # 若配置了白名单，只保留白名单中的文件
        if self.include_apks:
            apk_files = [file for file in apk_files if file in self.include_apks]

        print(f"发现 {len(apk_files)} 个 APK 样本")
        for apk_file in apk_files:
            apk_path = os.path.join(self.samples_dir, apk_file)
            print(f"正在分析: {apk_file}")

            # 为每个 APK 创建独立的分析器实例
            analyzer = APKAnalyzer(apk_path, self.results_dir)
            if not analyzer.parse_manifest():
                print(f"分析失败: {apk_file}")
                continue

            result = analyzer.get_analysis_result()
            result["apk_file"] = apk_file
            result_file = os.path.join(self.results_dir, f"{apk_file}_analysis.json")
            analyzer.save_result(result_file)
            results.append(result)

        # 保存批量分析摘要
        self.save_summary(results)
        return results

    def save_summary(self, results: List[Dict[str, Any]]) -> None:
        """保存批量分析摘要为 JSON 文件。

        参数：
            results: 所有 APK 的分析结果列表
        """
        summary = {
            "total_analyzed": len(results),
            "total_permission_entries": sum(item.get("total_permissions", 0) for item in results),
            "results": results,
        }

        summary_file = os.path.join(self.results_dir, "batch_analysis_summary.json")
        with open(summary_file, "w", encoding="utf-8") as output_handle:
            json.dump(summary, output_handle, ensure_ascii=False, indent=2)


# 命令行入口：直接运行本文件时，对 samples 目录下的所有 APK 执行批量分析
if __name__ == "__main__":
    batch_analyzer = APKBatchAnalyzer(str(PROJECT_ROOT / "samples"), str(PROJECT_ROOT / "results"))
    batch_analyzer.analyze_all()
