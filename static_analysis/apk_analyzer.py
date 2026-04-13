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


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SITE_PACKAGES = PROJECT_ROOT / ".venv" / "Lib" / "site-packages"
if str(SITE_PACKAGES) not in sys.path and SITE_PACKAGES.exists():
    sys.path.append(str(SITE_PACKAGES))


try:
    from loguru import logger as loguru_logger

    loguru_logger.remove()
    loguru_logger.add(sys.stderr, level="ERROR")
except Exception:
    loguru_logger = None

logging.basicConfig(level=logging.ERROR)
for logger_name in list(logging.Logger.manager.loggerDict):
    if "androguard" in logger_name.lower():
        logging.getLogger(logger_name).setLevel(logging.ERROR)

from androguard.core.apk import APK  # noqa: E402
from androguard.core.axml import AXMLPrinter  # noqa: E402

from static_analysis.permission_knowledge import (  # noqa: E402
    PermissionKnowledgeBase,
    normalize_protection_level,
    normalize_risk_level,
)


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
RISK_LEVELS = ("低", "中", "中高", "高", "极高")
HIGH_RISK_LEVELS = {"中高", "高", "极高"}

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

REINFORCEMENT_SIGNATURES = [
    {"name": "360 Jiagu", "patterns": ("libjiagu", "jiagu_data.bin")},
    {"name": "爱加密", "patterns": ("ijiami", "libexecmain", "libexec.so")},
    {"name": "梆梆加固", "patterns": ("bangcle", "libsecmain", "libDexHelper")},
    {"name": "娜迦加固", "patterns": ("libnqshield", "nqshield")},
    {"name": "通付盾/阿里聚安全", "patterns": ("libsgmain", "sgsecuritybody")},
    {"name": "SecNeo", "patterns": ("secneo", "libDexHelper-x86")},
]


def ordered_unique(values: Iterable[str]) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def safe_android_attr(element: Any, attr_name: str, default: str = "") -> str:
    return str(element.get(f"{ANDROID_NS}{attr_name}", default) or default).strip()


class APKAnalyzer:
    def __init__(self, apk_path: str, output_dir: str = "output"):
        self.apk_path = str(apk_path)
        self.output_dir = output_dir

        self.apk: Optional[APK] = None
        self.manifest_xml = None
        self.knowledge_base = PermissionKnowledgeBase.from_csv(
            PROJECT_ROOT / "docs" / "apk系统权限与风险.csv"
        )

        self.package_name = ""
        self.app_name = ""
        self.version_name = ""
        self.version_code = ""
        self.min_sdk = ""
        self.target_sdk = ""
        self.permissions: List[str] = []
        self.requested_permissions: List[str] = []
        self.declared_permissions: List[str] = []
        self.implied_permissions: List[str] = []
        self.activities: List[str] = []
        self.services: List[str] = []
        self.receivers: List[str] = []
        self.providers: List[str] = []
        self.features: List[str] = []
        self.libraries: List[str] = []
        self.application_metadata: List[Dict[str, str]] = []
        self.provider_authorities: List[str] = []
        self.queries: Dict[str, Any] = {"packages": [], "providers": [], "intents": []}
        self.third_party_sdks: List[Dict[str, Any]] = []
        self.app_frameworks: List[Dict[str, Any]] = []
        self.analysis_flags: Dict[str, Any] = {}

        self._zip_entries: List[str] = []
        self._requested_permission_details: Dict[str, Any] = {}
        self._aosp_permission_details: Dict[str, Any] = {}
        self._declared_permission_details: Dict[str, Any] = {}

    def _load_apk(self) -> APK:
        return APK(self.apk_path)

    def _resolve_component_name(self, raw_name: str) -> str:
        name = str(raw_name or "").strip()
        if not name:
            return ""
        if name.startswith("."):
            return f"{self.package_name}{name}"
        if "." not in name and self.package_name:
            return f"{self.package_name}.{name}"
        return name

    def _load_zip_entries(self) -> List[str]:
        try:
            with zipfile.ZipFile(self.apk_path, "r") as apk_file:
                return apk_file.namelist()
        except Exception:
            return []

    def _get_manifest_haystack(self) -> List[str]:
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
        for intent in self.queries.get("intents", []):
            raw_values.extend(intent.get("actions", []))
            raw_values.extend(intent.get("categories", []))
            raw_values.extend(intent.get("schemes", []))
            raw_values.extend(intent.get("authorities", []))
        raw_values.extend(self.queries.get("packages", []))
        raw_values.extend(self.queries.get("providers", []))
        return [value.lower() for value in raw_values if value]

    def _extract_queries(self) -> Dict[str, Any]:
        if self.manifest_xml is None:
            return {"packages": [], "providers": [], "intents": []}

        packages: List[str] = []
        providers: List[str] = []
        intents: List[Dict[str, Any]] = []

        for query_element in self.manifest_xml.findall("queries"):
            for package_element in query_element.findall("package"):
                packages.append(safe_android_attr(package_element, "name"))

            for provider_element in query_element.findall("provider"):
                providers.append(safe_android_attr(provider_element, "authorities"))

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
        normalized: List[str] = []
        for item in raw_permissions or []:
            if isinstance(item, (list, tuple)):
                if item:
                    normalized.append(str(item[0]))
            elif item:
                normalized.append(str(item))
        return ordered_unique(normalized)

    def _detect_signatures(self, signatures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        haystack = self._get_manifest_haystack()
        detections: List[Dict[str, Any]] = []

        for signature in signatures:
            evidences: List[str] = []
            for pattern in signature["patterns"]:
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
        component_names = self.activities + self.services + self.receivers + self.providers
        segments: List[str] = []
        for name in component_names:
            for segment in name.split("."):
                segment = segment.strip()
                if segment:
                    segments.append(segment)
        if not segments:
            return False
        short_segments = sum(1 for segment in segments if len(segment) <= 2)
        return (short_segments / len(segments)) >= 0.42

    def _collect_analysis_flags(self) -> Dict[str, Any]:
        multi_dex = any(Path(name).name.startswith("classes") and name.endswith(".dex") and name != "classes.dex" for name in self._zip_entries)
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
        with zipfile.ZipFile(self.apk_path, "r") as apk_file:
            manifest_bytes = apk_file.read("AndroidManifest.xml")

        axml = AXMLPrinter(manifest_bytes)
        if not axml.is_valid():
            raise ValueError("AndroidManifest.xml is invalid binary XML")

        manifest_payload = axml.get_xml()
        if isinstance(manifest_payload, bytes):
            manifest_text = manifest_payload.decode("utf-8", errors="ignore")
        else:
            manifest_text = str(manifest_payload)

        self.manifest_xml = ET.fromstring(manifest_text)
        self.package_name = str(self.manifest_xml.get("package", "") or "").strip()
        self.version_name = safe_android_attr(self.manifest_xml, "versionName")
        self.version_code = safe_android_attr(self.manifest_xml, "versionCode")

        uses_sdk = self.manifest_xml.find("uses-sdk")
        if uses_sdk is not None:
            self.min_sdk = safe_android_attr(uses_sdk, "minSdkVersion")
            self.target_sdk = safe_android_attr(uses_sdk, "targetSdkVersion")
        else:
            self.min_sdk = ""
            self.target_sdk = ""

        self.requested_permissions = ordered_unique(
            [
                safe_android_attr(node, "name")
                for tag in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m")
                for node in self.manifest_xml.findall(tag)
                if safe_android_attr(node, "name")
            ]
        )
        self.declared_permissions = ordered_unique(
            [
                safe_android_attr(node, "name")
                for node in self.manifest_xml.findall("permission")
                if safe_android_attr(node, "name")
            ]
        )
        self.implied_permissions = []
        self.permissions = ordered_unique(
            self.requested_permissions + self.declared_permissions + self.implied_permissions
        )

        app_element = self.manifest_xml.find("application")
        app_label = safe_android_attr(app_element, "label") if app_element is not None else ""
        self.app_name = app_label if app_label and not app_label.startswith("@") else self.package_name

        if app_element is None:
            self.activities = []
            self.services = []
            self.receivers = []
            self.providers = []
            self.libraries = []
        else:
            self.activities = ordered_unique(
                [
                    self._resolve_component_name(safe_android_attr(node, "name"))
                    for node in app_element.findall("activity")
                    if safe_android_attr(node, "name")
                ]
            )
            self.services = ordered_unique(
                [
                    self._resolve_component_name(safe_android_attr(node, "name"))
                    for node in app_element.findall("service")
                    if safe_android_attr(node, "name")
                ]
            )
            self.receivers = ordered_unique(
                [
                    self._resolve_component_name(safe_android_attr(node, "name"))
                    for node in app_element.findall("receiver")
                    if safe_android_attr(node, "name")
                ]
            )
            self.providers = ordered_unique(
                [
                    self._resolve_component_name(safe_android_attr(node, "name"))
                    for node in app_element.findall("provider")
                    if safe_android_attr(node, "name")
                ]
            )
            self.libraries = ordered_unique(
                [
                    safe_android_attr(node, "name")
                    for tag in ("uses-library", "uses-native-library")
                    for node in app_element.findall(tag)
                    if safe_android_attr(node, "name")
                ]
            )

        self.features = ordered_unique(
            [
                safe_android_attr(node, "name") or safe_android_attr(node, "glEsVersion")
                for node in self.manifest_xml.findall("uses-feature")
                if safe_android_attr(node, "name") or safe_android_attr(node, "glEsVersion")
            ]
        )

        self._requested_permission_details = {}
        self._aosp_permission_details = {}
        self._declared_permission_details = {}

    def _finalize_manifest_state(self) -> None:
        self.application_metadata = self._extract_application_metadata()
        self.provider_authorities = self._extract_provider_authorities()
        self.queries = self._extract_queries()
        self._zip_entries = self._load_zip_entries()

        self.third_party_sdks = self._detect_signatures(SDK_SIGNATURES)
        self.app_frameworks = self._detect_signatures(FRAMEWORK_SIGNATURES)
        self.analysis_flags = self._collect_analysis_flags()

    def parse_manifest(self) -> bool:
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.apk = self._load_apk()
                self.manifest_xml = self.apk.get_android_manifest_xml()

                self.package_name = self.apk.get_package()
                self.app_name = str(self.apk.get_app_name() or "")
                self.version_name = str(self.apk.get_androidversion_name() or "")
                self.version_code = str(self.apk.get_androidversion_code() or "")
                self.min_sdk = str(self.apk.get_min_sdk_version() or "")
                self.target_sdk = str(self.apk.get_target_sdk_version() or "")

                self.requested_permissions = ordered_unique(self.apk.get_permissions() or [])
                self.declared_permissions = ordered_unique(self.apk.get_declared_permissions() or [])
                self.implied_permissions = self._normalize_implied_permissions(
                    self.apk.get_uses_implied_permission_list() or []
                )
                self.permissions = ordered_unique(
                    self.requested_permissions + self.declared_permissions + self.implied_permissions
                )

                self.activities = ordered_unique(self.apk.get_activities() or [])
                self.services = ordered_unique(self.apk.get_services() or [])
                self.receivers = ordered_unique(self.apk.get_receivers() or [])
                self.providers = ordered_unique(self.apk.get_providers() or [])
                self.features = ordered_unique(self.apk.get_features() or [])
                self.libraries = ordered_unique(self.apk.get_libraries() or [])

                self._requested_permission_details = self.apk.get_details_permissions() or {}
                self._aosp_permission_details = self.apk.get_requested_aosp_permissions_details() or {}
                self._declared_permission_details = self.apk.get_declared_permissions_details() or {}

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
        label = ""
        description = ""
        raw_protection = ""

        if source == "declared_permission":
            detail = self._declared_permission_details.get(permission_name, {})
            label = str(detail.get("label", "") or "")
            description = str(detail.get("description", "") or "")
            raw_protection = str(detail.get("protectionLevel", "") or "")
        else:
            detail = self._aosp_permission_details.get(permission_name)
            if isinstance(detail, dict):
                label = str(detail.get("label", "") or "")
                description = str(detail.get("description", "") or "")
                raw_protection = str(detail.get("protectionLevel", "") or "")
            elif permission_name in self._requested_permission_details:
                raw = self._requested_permission_details.get(permission_name, [])
                if isinstance(raw, (list, tuple)) and raw:
                    raw_protection = str(raw[0] or "")
                    if len(raw) > 1:
                        label = str(raw[1] or "")
                    if len(raw) > 2:
                        description = str(raw[2] or "")

        return label, description, raw_protection

    def _build_permission_detail(self, permission_name: str, source: str) -> Dict[str, Any]:
        label, description, raw_protection = self._resolve_permission_payload(permission_name, source)
        catalog_entry = self.knowledge_base.classify(
            permission_name,
            source=source,
            label=label,
            description=description,
            raw_protection_level=raw_protection,
        )
        main_risk_level = normalize_risk_level(catalog_entry.get("风险等级"))
        protection_level = normalize_protection_level(raw_protection)

        if protection_level == "未知":
            protection_level = catalog_entry.get("Android保护级别", "未知")

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
            "is_custom": not permission_name.startswith("android.permission."),
        }

    def analyze_permissions(self) -> Dict[str, Any]:
        permission_details: List[Dict[str, Any]] = []
        seen_entries = set()

        permission_sources = [
            ("requested_permission", self.requested_permissions),
            ("declared_permission", self.declared_permissions),
            ("implied_permission", self.implied_permissions),
        ]

        for source, permissions in permission_sources:
            for permission_name in permissions:
                entry_key = (source, permission_name)
                if entry_key in seen_entries:
                    continue
                seen_entries.add(entry_key)
                permission_details.append(self._build_permission_detail(permission_name, source))

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

        sensitive_permission_details = [item for item in permission_details if item["is_sensitive"]]
        other_permission_details = [item for item in permission_details if not item["is_sensitive"]]

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
        result = self.get_analysis_result()
        with open(output_file, "w", encoding="utf-8") as output_handle:
            json.dump(result, output_handle, ensure_ascii=False, indent=2)


class APKBatchAnalyzer:
    def __init__(self, samples_dir: str, results_dir: str = "results"):
        self.samples_dir = samples_dir
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)

    def analyze_all(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        apk_files = sorted(file for file in os.listdir(self.samples_dir) if file.lower().endswith(".apk"))

        print(f"发现 {len(apk_files)} 个 APK 样本")
        for apk_file in apk_files:
            apk_path = os.path.join(self.samples_dir, apk_file)
            print(f"正在分析: {apk_file}")

            analyzer = APKAnalyzer(apk_path, self.results_dir)
            if not analyzer.parse_manifest():
                print(f"分析失败: {apk_file}")
                continue

            result = analyzer.get_analysis_result()
            result["apk_file"] = apk_file
            result_file = os.path.join(self.results_dir, f"{apk_file}_analysis.json")
            analyzer.save_result(result_file)
            results.append(result)

        self.save_summary(results)
        return results

    def save_summary(self, results: List[Dict[str, Any]]) -> None:
        summary = {
            "total_analyzed": len(results),
            "total_permission_entries": sum(item.get("total_permissions", 0) for item in results),
            "results": results,
        }

        summary_file = os.path.join(self.results_dir, "batch_analysis_summary.json")
        with open(summary_file, "w", encoding="utf-8") as output_handle:
            json.dump(summary, output_handle, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    batch_analyzer = APKBatchAnalyzer(str(PROJECT_ROOT / "samples"), str(PROJECT_ROOT / "results"))
    batch_analyzer.analyze_all()
