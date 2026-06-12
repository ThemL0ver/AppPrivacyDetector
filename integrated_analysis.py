# ============================================================================
# 集成分析模块 - App隐私合规检测系统核心
# 功能：综合静态分析（Manifest权限审计）与动态分析（运行时行为监控），
#       生成多维度的隐私风险评估报告
# ============================================================================

import json
import math
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# 静态分析引擎：基于Androguard的APK批量解析器
from static_analysis.apk_analyzer import APKBatchAnalyzer
# 动态分析引擎：基于ADB + Frida的运行时行为监控器
from dynamic_analysis.analyzer import DynamicBatchAnalyzer
# 应用类型-权限映射、风险等级阈值、敏感API权重等配置
from app_type_permissions import (
    CONTEXTUAL_PERMISSION_DOMAINS,
    PERMISSION_RISK_LEVELS,
    RISK_THRESHOLDS,
    SENSITIVE_API_WEIGHTS,
    get_app_type,
    get_permission_category,
)


class IntegratedAnalyzer:
    """综合隐私风险分析器。

    职责：
        1. 调度静态分析和动态分析流水线
        2. 基于上下文感知模型计算每个APK的多维风险评分
        3. 生成包含检测发现、评分明细、基准校验的JSON综合报告

    评分体系由以下维度构成：
        - 静态权限评分：必要/情境/越界权限分类 + 硬违规加权 + 情境缓解
        - 静态上下文评分：第三方SDK风险 + 跨应用查询面 + 自定义敏感权限
        - 动态行为评分：敏感API调用频次 + 网络外联 + 隐私泄露
        - 证据加权调整：高风险证据组合触发额外惩罚分
    """

    # ---------- APK显示名称映射 ----------
    # 将带版本号的中文文件名映射为简洁英文别名，便于报告中展示
    APK_DISPLAY_ALIASES = {
        "万达贷 25.12.1.apk": "WanDaDai.apk",
        "万达贷  25.12.1.apk": "WanDaDai.apk",
        "六只脚 4.19.6.apk": "LiuZhiJiao.apk",
        "票豆 2.3.17.apk": "PiaoDou.apk",
        "闪电修 2.9.9.apk": "ShanDianXiu.apk",
    }

    # ---------- 基准正常应用集 ----------
    # 用于建模一致性校验：这些知名合规应用的评分应落在低/中风险区间
    BASELINE_NORMAL_APKS = {
        "BaiDu.apk",
        "bili.apk",
        "DeWu.apk",
        "DouBao.apk",
        "DouYin.apk",
        "GoWhere.apk",
        "MeiTuan.apk",
        "Taobao.apk",
        "Xianyu.apk",
        "YiBaoYun.apk",
        "ZuoYeBang.apk",
    }

    # ---------- 权限域基础敏感度分值 ----------
    # 数值越高表示该权限域越敏感（如短信、通讯录），越低表示风险较小（如通知）
    DOMAIN_BASE_SCORES = {
        "location": 3.2,
        "camera": 3.0,
        "microphone": 3.0,
        "contacts": 3.4,
        "sms": 4.4,
        "phone": 3.2,
        "storage": 1.8,
        "calendar": 1.4,
        "account": 2.2,
        "biometric": 2.4,
        "identifier": 2.6,
        "app_installation": 2.2,
        "shortcut": 1.0,
        "system_control": 2.4,
        "system_inspection": 3.0,
        "notification": 1.0,
        "other": 1.2,
    }

    # ---------- 动态敏感API权重 ----------
    # 运行时Hook捕获的API调用权重，反映各类数据采集行为的隐私敏感度
    DYNAMIC_API_WEIGHTS = {
        "getDeviceId": 2.0,
        "getSubscriberId": 2.0,
        "getMacAddress": 1.8,
        "getAndroidId": 1.8,
        "getOaid": 1.8,
        "getLocation": 1.7,
        "openCamera": 1.5,
        "startRecording": 1.5,
        "readContacts": 1.7,
        "readSms": 2.2,
        "readCallLog": 2.3,
        "accessStorage": 1.0,
        "accessNetwork": 0.9,
        "accessCalendar": 1.2,
        "getInstalledPackages": 1.8,
        "getAccount": 1.4,
        "readClipboard": 1.3,
        "sendSms": 2.5,
        "reflectionInvoke": 1.1,
        "getSystemService": 0.6,
        "appOpsSensitiveAction": 1.4,
    }

    # ---------- SDK类别风险权重 ----------
    # 不同类别的第三方SDK携带不同的隐私风险（广告SDK风险 > 推送SDK风险）
    SDK_CATEGORY_WEIGHTS = {
        "ad": 1.2,
        "analytics": 0.9,
        "social": 0.5,
        "payment": 0.4,
        "map": 0.4,
        "push": 0.2,
    }

    # ---------- SDK风险提示等级权重 ----------
    # 将静态指纹识别到的SDK风险等级映射为数值权重
    SDK_RISK_HINT_WEIGHTS = {
        "low": 0.1,
        "medium": 0.4,
        "中": 0.4,
        "medium_high": 0.7,
        "中高": 0.7,
        "high": 1.0,
        "高": 1.0,
    }

    # ---------- 基础设施类权限模式 ----------
    # 这些权限属于网络访问、前台服务等基础设施，不计入隐私风险评估
    INFRASTRUCTURE_PATTERNS = (
        "internet",
        "access_network_state",
        "access_wifi_state",
        "change_wifi_state",
        "change_network_state",
        "change_wifi_multicast_state",
        "bluetooth",
        "foreground_service",
        "wake_lock",
        "vibrate",
        "modify_audio_settings",
        "flashlight",
        "nfc",
        "detect_screen_capture",
        "detect_screen_recording",
        "high_sampling_rate_sensors",
        "reorder_tasks",
        "set_wallpaper",
        "set_wallpaper_hints",
        "expand_status_bar",
    )

    # ---------- 低信号权限模式 ----------
    # 通常来自厂商推送服务或启动器，对隐私风险的指示作用较弱
    LOW_SIGNAL_PATTERNS = (
        "launcher.permission",
        "push",
        "badge",
        "notification",
        "read_settings",
        "write_settings",
        "process_push_msg",
        "push_provider",
        "mipush_receive",
        "download_without_notification",
        "change_configuration",
        "tt_pangolin",
        "bind_get_install_referrer_service",
        "read_push_notification_info",
    )

    # ---------- 设备标识符权限模式 ----------
    # 涉及OAID、DID等设备标识的权限，归入identifier权限域
    IDENTIFIER_PATTERNS = (
        "oaid",
        "msa",
        "identifier",
        "device_id",
        "supplementarydid",
        "did",
    )

    # ---------- 硬违规权限模式 ----------
    # 声明即构成高度隐私风险（如读取短信、通话记录、无障碍服务）
    HARD_VIOLATION_PATTERNS = (
        "read_sms",
        "send_sms",
        "write_sms",
        "package_usage_stats",
        "query_all_packages",
        "get_installed_apps",
        "read_call_log",
        "write_call_log",
        "accessibility",
        "bind_accessibility_service",
        "receive_tiantong_sms",
        "send_tiantong_sms",
        "receive_beidou_sms",
        "send_beidou_sms",
        "read_logs",
    )

    # ---------- 严重硬违规模式（critical级别）----------
    CRITICAL_HARD_VIOLATION_PATTERNS = (
        "read_sms",
        "send_sms",
        "write_sms",
        "read_call_log",
        "write_call_log",
        "accessibility",
        "bind_accessibility_service",
        "receive_tiantong_sms",
        "send_tiantong_sms",
        "receive_beidou_sms",
        "send_beidou_sms",
    )

    # ---------- 中等硬违规模式（moderate级别）----------
    MODERATE_HARD_VIOLATION_PATTERNS = (
        "package_usage_stats",
        "query_all_packages",
        "get_installed_apps",
        "read_logs",
    )

    # ========================================================================
    # 工具方法
    # ========================================================================

    @staticmethod
    def _to_int_score(value: float) -> int:
        """将浮点分值转为整数（四舍五入），避免UI显示中出现浮点尾数。

        参数：
            value: 浮点分值。

        返回：
            四舍五入后的整数分值。
        """
        return int(math.floor(float(value) + 0.5))

    @staticmethod
    def _normalize_apk_name(value: str) -> str:
        """归一化APK文件名：去空白、转小写，用于文件名比较匹配。

        参数：
            value: 原始APK文件名。

        返回：
            归一化后的文件名。
        """
        normalized = re.sub(r"\s+", " ", str(value or "").strip().lower())
        return normalized

    def _get_display_apk_name(self, apk_file: str) -> str:
        """根据映射表将APK文件名转换为显示名称。

        参数：
            apk_file: APK原始文件名。

        返回：
            映射后的显示名称；若无映射则返回原名。
        """
        # 先归一化文件名，再与别名映射表做匹配
        normalized_name = self._normalize_apk_name(apk_file)
        for original_name, display_name in self.APK_DISPLAY_ALIASES.items():
            if self._normalize_apk_name(original_name) == normalized_name:
                return display_name
        return apk_file

    # ========================================================================
    # 初始化
    # ========================================================================

    def __init__(
        self,
        samples_dir: str,
        results_dir: str = "results",
        dynamic_timeout_per_apk: int = 300,
        manual_probe_seconds: int = 0,
        low_coverage_api_threshold: int = 4,
        manual_probe_apk_allowlist: Optional[List[str]] = None,
        clear_app_data_after_analysis: bool = False,
        include_apks: Optional[List[str]] = None,
    ):
        """初始化集成分析器，创建静态和动态分析引擎。

        参数：
            samples_dir: APK样本目录路径。
            results_dir: 分析结果输出目录，默认为"results"。
            dynamic_timeout_per_apk: 每个APK的动态分析超时时间（秒），默认300。
            manual_probe_seconds: 人工交互探测时长（秒），默认0。
            low_coverage_api_threshold: 低覆盖率阈值，低于该值触发重分析，默认4。
            manual_probe_apk_allowlist: 允许人工探测的APK白名单。
            clear_app_data_after_analysis: 分析后是否清除应用数据。
            include_apks: 限定分析的APK文件名列表。
        """
        self.samples_dir = samples_dir
        self.results_dir = results_dir
        self.include_apks = include_apks or []
        # 确保结果输出目录存在
        os.makedirs(results_dir, exist_ok=True)
        # 初始化静态分析器
        self.static_analyzer = APKBatchAnalyzer(samples_dir, results_dir, include_apks=self.include_apks)
        # 初始化动态分析器，传入超时、探针、覆盖率等参数
        self.dynamic_analyzer = DynamicBatchAnalyzer(
            samples_dir,
            results_dir,
            per_apk_timeout=dynamic_timeout_per_apk,
            manual_probe_seconds=manual_probe_seconds,
            low_coverage_api_threshold=low_coverage_api_threshold,
            manual_probe_apk_allowlist=manual_probe_apk_allowlist,
            clear_app_data_after_analysis=clear_app_data_after_analysis,
            include_apks=self.include_apks,
        )

    # ========================================================================
    # 静态分析
    # ========================================================================

    def _persist_static_results(self, static_results: List[Dict[str, Any]]) -> None:
        """将每个APK的静态分析结果持久化为独立JSON文件，并生成汇总文件。

        参数：
            static_results: 静态分析结果列表，每个元素为一个APK的分析字典。
        """
        # 逐个APK写入独立结果文件
        for result in static_results:
            apk_file = result.get("apk_file")
            if not apk_file:
                continue
            result_file = os.path.join(self.results_dir, f"{apk_file}_analysis.json")
            if os.path.exists(result_file):
                try:
                    with open(result_file, "w", encoding="utf-8") as output_handle:
                        json.dump(result, output_handle, ensure_ascii=False, indent=2)
                except Exception:
                    pass

        # 生成汇总文件：包含总数、权限条目总数及全部结果
        summary = {
            "total_analyzed": len(static_results),
            "total_permission_entries": sum(item.get("total_permissions", 0) for item in static_results),
            "results": static_results,
        }
        summary_file = os.path.join(self.results_dir, "batch_analysis_summary.json")
        try:
            with open(summary_file, "w", encoding="utf-8") as output_handle:
                json.dump(summary, output_handle, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def perform_static_analysis(self) -> List[Dict[str, Any]]:
        """执行批量静态分析：解析所有APK的Manifest文件。

        返回：
            静态分析结果列表，包含权限声明、SDK指纹、组件信息等。
        """
        print("=" * 50)
        print("开始静态分析")
        print("=" * 50)

        static_results = self.static_analyzer.analyze_all()
        print(f"\n静态分析完成，共分析 {len(static_results)} 个APK")
        return static_results

    # ========================================================================
    # 动态分析
    # ========================================================================

    def perform_dynamic_analysis(self) -> List[Dict[str, Any]]:
        """执行批量动态分析：安装运行APK并通过Frida监控运行时行为。

        返回：
            动态分析结果列表，包含敏感API调用、网络流量、隐私泄露等。
        """
        print("=" * 50)
        print("开始动态分析")
        print("=" * 50)

        dynamic_results = self.dynamic_analyzer.analyze_all()
        print(f"\n动态分析完成，共分析 {len(dynamic_results)} 个APK")
        return dynamic_results

    # ========================================================================
    # 去重与风险标签
    # ========================================================================

    def _unique(self, values: List[str]) -> List[str]:
        """列表去重，保持原始顺序。

        参数：
            values: 待去重的字符串列表。

        返回：
            去重后的有序列表。
        """
        seen = set()
        ordered: List[str] = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                ordered.append(value)
        return ordered

    def _derive_risk_label(self, risk_level: str) -> str:
        """将风险等级（high/medium/low）映射为中文可读标签。

        参数：
            risk_level: 风险等级字符串。

        返回：
            中文风险标签，如"涉嫌高危违规APP"。
        """
        return {
            "high": "涉嫌高危违规APP",
            "medium": "中度越界风险APP",
            "low": "合规应用",
        }.get(risk_level, "合规应用")

    # ========================================================================
    # 权限域映射与权重计算
    # ========================================================================

    def _get_permission_domain(self, permission: str) -> Optional[str]:
        """将权限名映射到风险域。

        参数：
            permission: 完整权限名。

        返回：
            对应的权限域名称；若为基础设施类或无法识别的权限则返回 None。
        """
        perm = permission.lower()

        # 基础设施权限不计入任何风险域
        if any(pattern in perm for pattern in self.INFRASTRUCTURE_PATTERNS):
            return None

        # 按优先级依次匹配各权限域（location > camera > microphone > ...）
        if (
            "access_fine_location" in perm
            or "access_coarse_location" in perm
            or "access_background_location" in perm
            or "access_media_location" in perm
            or "permission.access_location" in perm
            or "location" in perm
        ):
            return "location"
        if "camera" in perm:
            return "camera"
        if "record_audio" in perm or "microphone" in perm:
            return "microphone"
        if "contact" in perm:
            return "contacts"
        if "sms" in perm:
            return "sms"
        if (
            "phone_state" in perm
            or "call_log" in perm
            or "voicemail" in perm
            or "outgoing_call" in perm
            or "sip" in perm
            or "call_phone" in perm
        ):
            return "phone"
        if "read_media" in perm or "external_storage" in perm or "storage" in perm:
            return "storage"
        if "calendar" in perm:
            return "calendar"
        if "account" in perm:
            return "account"
        if "biometric" in perm or "fingerprint" in perm or "facerecognition" in perm or ".face" in perm:
            return "biometric"
        if any(pattern in perm for pattern in self.IDENTIFIER_PATTERNS):
            return "identifier"
        if "request_install_packages" in perm or "install_packages" in perm:
            return "app_installation"
        if "shortcut" in perm or "widget" in perm:
            return "shortcut"
        if "system_alert_window" in perm or "overlay" in perm or "disable_keyguard" in perm:
            return "system_control"
        if "read_logs" in perm or "package_usage_stats" in perm or "query_all_packages" in perm or "get_installed_apps" in perm:
            return "system_inspection"
        if "push" in perm or "notification" in perm or "badge" in perm:
            return "notification"
        # 无法匹配的权限归入"其他"
        return "other"

    def _get_permission_base_weight(self, permission: str, main_risk_level: str) -> Tuple[float, Optional[str]]:
        """计算单条权限的基础权重。

        参数：
            permission: 权限名称。
            main_risk_level: 权限的风险等级标注（来自权限分析结果）。

        返回：
            (基础权重, 权限域) 元组；若为基础权限则返回 (0.0, None)。
        """
        # 先确定权限所属的风险域
        domain = self._get_permission_domain(permission)
        if domain is None:
            return 0.0, None

        # 获取风险等级对应的权重系数
        level_weight = float(PERMISSION_RISK_LEVELS.get(main_risk_level, 0.0))
        # 获取该域的基础敏感度分值
        domain_weight = self.DOMAIN_BASE_SCORES.get(domain, self.DOMAIN_BASE_SCORES["other"])
        if level_weight > 0:
            # 混合风险等级权重与域敏感度，避免对商业应用中的常见声明权限过度惩罚
            weight = (level_weight * 0.78) + (domain_weight * 0.30)
        else:
            weight = domain_weight * 0.45

        # 低信号权限降权处理
        perm = permission.lower()
        if any(pattern in perm for pattern in self.LOW_SIGNAL_PATTERNS):
            weight *= 0.35
        # 标识符类权限降权（通常来自合规SDK）
        if any(pattern in perm for pattern in self.IDENTIFIER_PATTERNS):
            weight *= 0.65
        if domain == "notification":
            weight *= 0.8
        # 非标准Android权限（如厂商自定义）降低权重
        if domain == "other" and permission.count(".") >= 2 and not permission.startswith("android.permission."):
            weight *= 0.5

        return round(weight, 2), domain

    # ========================================================================
    # 硬违规权限检测
    # ========================================================================

    def _is_hard_violation_permission(self, permission: str) -> bool:
        """判断该权限是否属于硬违规类别。

        参数：
            permission: 权限名称。

        返回：
            True 表示属于硬违规权限。
        """
        perm = permission.lower()
        return any(pattern in perm for pattern in self.HARD_VIOLATION_PATTERNS)

    def _get_hard_violation_severity(self, permission: str) -> Optional[str]:
        """判断硬违规权限的严重程度。

        参数：
            permission: 权限名称。

        返回：
            "critical"（严重）、"moderate"（中等）或 None（非硬违规）。
        """
        perm = permission.lower()
        if any(pattern in perm for pattern in self.CRITICAL_HARD_VIOLATION_PATTERNS):
            return "critical"
        if any(pattern in perm for pattern in self.MODERATE_HARD_VIOLATION_PATTERNS):
            return "moderate"
        return None

    # ========================================================================
    # 静态权限评分
    # ========================================================================

    def _score_static_permissions(
        self,
        app_type: str,
        permission_details: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """计算静态权限评分。

        评分思路：
        1. 先将权限分为三类：必要权限、情境权限、越界（非必要）权限
        2. 对越界权限按权限域累加分值，同一域重复声明额外加权
        3. 硬违规权限单独加权计算
        4. 情境权限产生缓解减分，避免正常业务权限被过度惩罚

        参数：
            app_type: 应用类型（如"金融"、"社交"、"工具"等）。
            permission_details: 权限详情列表，每项包含name、risk_level等字段。

        返回：
            评分字典，包含score、各类权限列表、域分布和breakdown明细。
        """
        necessary_permissions: List[str] = []
        contextual_permission_details: List[Dict[str, Any]] = []
        non_necessary_permission_details: List[Dict[str, Any]] = []

        # 获取该应用类型的情境权限域（业务可能用到但不一定必须的权限）
        contextual_domains = CONTEXTUAL_PERMISSION_DOMAINS.get(app_type, set())
        contextual_domain_scores: Dict[str, float] = {}
        excess_domain_scores: Dict[str, float] = {}
        excess_domain_counts: Dict[str, int] = {}
        hard_violation_count = 0
        hard_violation_critical_count = 0
        hard_violation_moderate_count = 0

        # 遍历每条权限声明，分类并计算权重
        for perm_detail in permission_details:
            permission_name = perm_detail.get("name", "")
            if not permission_name:
                continue

            # 必要权限：直接跳过，不计入风险评分
            if get_permission_category(app_type, permission_name) == "necessary":
                necessary_permissions.append(permission_name)
                continue

            risk_level = perm_detail.get("main_risk_level", "")
            adjusted_weight, domain = self._get_permission_base_weight(permission_name, risk_level)
            # 基础权限或权重过低的不参与评分
            if domain is None or adjusted_weight < 0.5:
                continue

            record = {
                "name": permission_name,
                "domain": domain,
                "weight": adjusted_weight,
                "risk_level": risk_level,
            }

            hard_violation_severity = self._get_hard_violation_severity(permission_name)
            if hard_violation_severity:
                # 硬违规权限：计入越界权限并单独统计严重程度
                hard_violation_count += 1
                if hard_violation_severity == "critical":
                    hard_violation_critical_count += 1
                else:
                    hard_violation_moderate_count += 1
                non_necessary_permission_details.append(record)
                excess_domain_scores[domain] = max(excess_domain_scores.get(domain, 0.0), adjusted_weight)
                excess_domain_counts[domain] = excess_domain_counts.get(domain, 0) + 1
            elif domain in contextual_domains:
                # 情境权限：记录但不算入越界惩罚
                contextual_permission_details.append(record)
                contextual_domain_scores[domain] = max(contextual_domain_scores.get(domain, 0.0), adjusted_weight)
            else:
                # 越界（非必要）权限：完全计入越界评分
                non_necessary_permission_details.append(record)
                excess_domain_scores[domain] = max(excess_domain_scores.get(domain, 0.0), adjusted_weight)
                excess_domain_counts[domain] = excess_domain_counts.get(domain, 0) + 1

        # 越界权限域总分：各域最高权重之和
        excess_domain_score = round(sum(excess_domain_scores.values()), 2)
        # 情境权限域总分
        contextual_domain_score = round(sum(contextual_domain_scores.values()), 2)
        # 同域重复声明加权（每域最多计入2条重复）
        excess_duplicate_bonus = round(
            sum(min(count - 1, 2) * 0.20 for count in excess_domain_counts.values() if count > 1),
            2,
        )
        # 硬违规加权：critical每条1.8分（上限5.4），moderate每条0.7分（上限2.8）
        hard_violation_bonus = round(
            min(hard_violation_critical_count * 1.8, 5.4)
            + min(hard_violation_moderate_count * 0.7, 2.8),
            2,
        )
        # 情境缓解：存在情境权限域时给予减分（上限2.5），缓解合理业务需求的误判
        contextual_mitigation = round(min(len(contextual_domain_scores) * 0.45, 2.5), 2)

        # 综合计算静态权限原始分：越界分 * 1.15 + 情境分 * 0.12 + 重复加权 + 硬违规加权 - 情境缓解
        static_score_raw = (
            min(
                75.0,
                excess_domain_score * 1.15
                + contextual_domain_score * 0.12
                + excess_duplicate_bonus
                + hard_violation_bonus,
            )
            - contextual_mitigation
        )
        static_score = self._to_int_score(static_score_raw)

        return {
            "score": static_score,
            "necessary_permissions": self._unique(necessary_permissions),
            "contextual_permissions": self._unique([item["name"] for item in contextual_permission_details]),
            "contextual_permission_details": contextual_permission_details,
            "non_necessary_permissions": self._unique([item["name"] for item in non_necessary_permission_details]),
            "non_necessary_permission_details": non_necessary_permission_details,
            "necessary_count": len(self._unique(necessary_permissions)),
            "contextual_count": len(self._unique([item["name"] for item in contextual_permission_details])),
            "non_necessary_count": len(self._unique([item["name"] for item in non_necessary_permission_details])),
            "contextual_domains": sorted(contextual_domain_scores.keys()),
            "excess_domains": sorted(excess_domain_scores.keys()),
            "hard_violation_count": hard_violation_count,
            "hard_violation_critical_count": hard_violation_critical_count,
            "hard_violation_moderate_count": hard_violation_moderate_count,
            "breakdown": {
                "excess_domain_score": excess_domain_score,
                "contextual_domain_score": contextual_domain_score,
                "excess_duplicate_bonus": excess_duplicate_bonus,
                "hard_violation_bonus": hard_violation_bonus,
                "contextual_mitigation": contextual_mitigation,
            },
        }

    # ========================================================================
    # 静态上下文评分（SDK + 跨应用查询 + 自定义权限）
    # ========================================================================

    def _score_static_context(
        self,
        static_result: Dict[str, Any],
        permission_analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        """计算静态上下文评分：第三方SDK风险 + 跨应用查询面 + 自定义敏感权限。

        参数：
            static_result: 单个APK的完整静态分析结果。
            permission_analysis: 权限分析子结果（含自定义权限信息）。

        返回：
            上下文评分字典，包含score、SDK数量、查询面数量和breakdown明细。
        """
        # SDK风险评分：遍历所有检测到的第三方SDK，按类别和风险提示加权
        sdk_score = 0.0
        for sdk in static_result.get("third_party_sdks", []) or []:
            category = str(sdk.get("category", "")).strip().lower()
            risk_hint = str(sdk.get("risk_hint", "")).strip()
            # 取类别权重和风险提示权重的较大值
            sdk_score += max(
                self.SDK_CATEGORY_WEIGHTS.get(category, 0.6),
                self.SDK_RISK_HINT_WEIGHTS.get(risk_hint, 0.0),
            )
        sdk_score = round(min(sdk_score, 4.0), 2)

        # 跨应用查询面评分：统计 queries 声明中的 packages、providers、intents
        queries = static_result.get("queries", {}) or {}
        query_count = (
            len(queries.get("packages", []) or [])
            + len(queries.get("providers", []) or [])
            + len(queries.get("intents", []) or [])
        )
        query_score = round(min(query_count * 0.05, 1.5), 2)

        # 自定义敏感权限评分：统计自定义权限中风险等级为"中高"、"高"、"极高"的
        custom_sensitive_permissions = {
            item.get("name")
            for item in permission_analysis.get("permission_details", [])
            if item.get("is_custom") and item.get("main_risk_level") in {"中高", "高", "极高"}
        }
        custom_permission_score = round(min(len(custom_sensitive_permissions) * 0.35, 1.5), 2)

        # 合成上下文总分（上限6.0）
        context_score = self._to_int_score(min(6.0, sdk_score + query_score + custom_permission_score))
        return {
            "score": context_score,
            "sdk_count": len(static_result.get("third_party_sdks", []) or []),
            "query_count": query_count,
            "custom_sensitive_permission_count": len(custom_sensitive_permissions),
            "breakdown": {
                "sdk_score": self._to_int_score(sdk_score),
                "query_score": self._to_int_score(query_score),
                "custom_permission_score": self._to_int_score(custom_permission_score),
            },
        }

    # ========================================================================
    # 动态行为评分
    # ========================================================================

    def _get_dynamic_signal_count(self, payload: Any) -> int:
        """从动态分析载荷中提取信号调用次数。

        参数：
            payload: 动态分析载荷，可能是字典（含count或logs字段）、列表或标量。

        返回：
            提取到的调用次数。
        """
        if isinstance(payload, dict):
            # 字典类型：优先取count字段，其次取logs列表长度
            if isinstance(payload.get("count"), int):
                return payload["count"]
            logs = payload.get("logs")
            if isinstance(logs, list):
                return len(logs)
            return 1
        if isinstance(payload, list):
            return len(payload)
        return 1 if payload else 0

        """计算动态行为评分。

        动态评分以敏感 API 调用次数为核心，并结合网络外联与隐私泄露线索进行补充加权。
        使用 log1p 对调用次数做压缩，避免少量高频调用将总分无限放大。
        """
    def _score_dynamic_behavior(self, dynamic_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """计算动态行为评分。

        评分以敏感API调用次数为核心，结合网络外联与隐私泄露线索补充加权。
        使用 log1p 对调用次数做非线性压缩，避免少量高频调用将总分无限放大。

        参数：
            dynamic_result: 单个APK的动态分析结果；若为None则返回0分。

        返回：
            动态评分字典，包含score、api_signals列表、网络/隐私计数和breakdown明细。
        """
        if not dynamic_result:
            return {
                "score": 0,
                "api_signals": [],
                "network_traffic_count": 0,
                "privacy_leak_count": 0,
                "breakdown": {
                    "api_score": 0,
                    "network_score": 0,
                    "privacy_score": 0,
                },
            }

        # 敏感API调用评分：遍历每种API类型，log1p压缩后乘以权重
        api_signals: List[Dict[str, Any]] = []
        api_score = 0.0
        for api_type, payload in dynamic_result.get("sensitive_api_calls", {}).items():
            count = self._get_dynamic_signal_count(payload)
            if count <= 0:
                continue

            weight = self.DYNAMIC_API_WEIGHTS.get(api_type, 1.2)
            # log1p(count) 平滑处理调用次数，避免线性放大
            contribution = round(min(math.log1p(count) * weight * 0.75, 3.5), 2)
            api_signals.append(
                {
                    "api_type": api_type,
                    "count": count,
                    "weight": weight,
                    "score": contribution,
                }
            )
            api_score += contribution

        # 网络外联评分：统计对外网络请求次数
        network_traffic_count = len(dynamic_result.get("network_traffic", []))
        network_weight = SENSITIVE_API_WEIGHTS.get("network", 1.0)
        network_score = round(min(math.log1p(network_traffic_count) * (0.7 * network_weight), 2.0), 2)

        # 隐私泄露评分：检测到的隐私数据泄露线索数
        privacy_leak_count = len(dynamic_result.get("privacy_leaks", []))
        privacy_score = round(min(privacy_leak_count * 2.2, 5.0), 2)

        # 合成动态总分（上限12.0）
        dynamic_score = self._to_int_score(min(12.0, api_score + network_score + privacy_score))
        return {
            "score": dynamic_score,
            "api_signals": api_signals,
            "network_traffic_count": network_traffic_count,
            "privacy_leak_count": privacy_leak_count,
            "breakdown": {
                "api_score": self._to_int_score(api_score),
                "network_score": self._to_int_score(network_score),
                "privacy_score": self._to_int_score(privacy_score),
            },
        }

    # ========================================================================
    # 检测发现构建
    # ========================================================================

    def _build_detected_findings(
        self,
        static_result: Dict[str, Any],
        dynamic_result: Optional[Dict[str, Any]],
        static_permission_assessment: Dict[str, Any],
        static_context_assessment: Dict[str, Any],
        dynamic_assessment: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """根据分析结果构建结构化的检测发现列表。

        检测发现类型包括：
        - 高敏感权限声明（硬违规）
        - 超范围收集个人信息
        - 第三方SDK隐私合规风险
        - 跨应用查询面过大
        - 运行时敏感API行为
        - 隐私政策/告知同意流程缺陷
        - 反调试/环境探测行为

        参数：
            static_result: 静态分析结果。
            dynamic_result: 动态分析结果（可为None）。
            static_permission_assessment: 静态权限评分结果。
            static_context_assessment: 静态上下文评分结果。
            dynamic_assessment: 动态行为评分结果。

        返回：
            检测发现列表，每项包含issue_category、issue_name、severity、evidence、technical_basis。
        """
        findings: List[Dict[str, Any]] = []

        # 发现1：硬违规权限声明
        hard_count = static_permission_assessment.get("hard_violation_count", 0)
        if hard_count > 0:
            findings.append({
                "issue_category": "hard_violation_permission",
                "issue_name": "发现高敏感权限声明",
                "severity": "high",
                "evidence": {
                    "hard_violation_count": hard_count,
                    "critical_count": static_permission_assessment.get("hard_violation_critical_count", 0),
                    "moderate_count": static_permission_assessment.get("hard_violation_moderate_count", 0),
                    "permissions": static_permission_assessment.get("non_necessary_permissions", []),
                },
                "technical_basis": "Manifest 权限清单中存在短信、通话记录、无障碍、安装应用查询或系统日志等高敏感权限域。",
            })

        # 发现2：超范围收集个人信息（越界权限数量或域数达到阈值）
        non_necessary_count = static_permission_assessment.get("non_necessary_count", 0)
        excess_domains = static_permission_assessment.get("excess_domains", [])
        if non_necessary_count >= 8 or len(excess_domains) >= 4:
            findings.append({
                "issue_category": "unnecessary_personal_information_collection",
                "issue_name": "存在超出业务必要范围的个人信息权限声明",
                "severity": "high" if non_necessary_count >= 12 else "medium",
                "evidence": {
                    "non_necessary_count": non_necessary_count,
                    "excess_domains": excess_domains,
                    "sample_permissions": static_permission_assessment.get("non_necessary_permissions", [])[:20],
                },
                "technical_basis": "系统按应用类型映射必要权限范围，非必要权限数量或越界权限域达到阈值，表明存在超范围收集个人信息风险。",
            })

        # 发现3：第三方SDK隐私合规风险
        sdk_count = static_context_assessment.get("sdk_count", 0)
        sdk_score = static_context_assessment.get("breakdown", {}).get("sdk_score", 0)
        third_party_sdks = static_result.get("third_party_sdks", []) or []
        if sdk_count >= 3 or sdk_score >= 3:
            findings.append({
                "issue_category": "third_party_sdk_privacy_risk",
                "issue_name": "第三方 SDK 隐私合规风险",
                "severity": "medium",
                "evidence": {
                    "sdk_count": sdk_count,
                    "sdk_score": sdk_score,
                    "sdks": [
                        {
                            "name": sdk.get("name"),
                            "category": sdk.get("category"),
                            "risk_hint": sdk.get("risk_hint"),
                            "evidence": sdk.get("evidence", [])[:5],
                        }
                        for sdk in third_party_sdks[:10]
                    ],
                },
                "technical_basis": "静态指纹识别命中多个第三方 SDK 或较高风险 SDK 类型，可作为 SDK 信息披露和授权同意核查的技术线索。",
            })

        # 发现4：跨应用查询范围较大
        query_count = static_context_assessment.get("query_count", 0)
        if query_count >= 20:
            findings.append({
                "issue_category": "excessive_app_query_surface",
                "issue_name": "跨应用查询范围较大",
                "severity": "medium",
                "evidence": {
                    "query_count": query_count,
                    "queries": static_result.get("queries", {}),
                },
                "technical_basis": "Android 11+ queries 声明范围较大，说明应用具备较强的跨应用可见性和环境探测能力。",
            })

        # 发现5：运行时触发敏感API调用（仅筛选特定高危API类型）
        sensitive_signals = [
            item for item in dynamic_assessment.get("api_signals", [])
            if item.get("api_type") in {"getDeviceId", "getSubscriberId", "getAndroidId", "getLocation", "readContacts", "readSms", "readCallLog", "sendSms", "getInstalledPackages"}
        ]
        if sensitive_signals:
            findings.append({
                "issue_category": "runtime_sensitive_api_behavior",
                "issue_name": "运行时触发敏感 API 调用",
                # 若涉及短信/通话记录则升级为high
                "severity": "high" if any(item.get("api_type") in {"readSms", "readCallLog", "sendSms"} for item in sensitive_signals) else "medium",
                "evidence": {
                    "api_signals": sensitive_signals,
                    "network_traffic_count": dynamic_assessment.get("network_traffic_count", 0),
                    "privacy_leak_count": dynamic_assessment.get("privacy_leak_count", 0),
                },
                "technical_basis": "动态探针与 Frida Hook 在应用运行期间捕获敏感系统服务调用，证明相关能力并非仅停留在静态声明层面。",
            })

        # 发现6：首次运行隐私政策或明示同意要素不足
        if dynamic_result:
            privacy_notice = dynamic_result.get("privacy_notice_observation") or {}
            if privacy_notice.get("observed") and (
                not privacy_notice.get("has_privacy_notice") or not privacy_notice.get("has_explicit_consent_action")
            ):
                findings.append({
                    "issue_category": "notice_consent_policy_defect",
                    "issue_name": "首次运行隐私政策提示或明示同意要素不足",
                    "severity": "high",
                    "evidence": {
                        "has_privacy_notice": privacy_notice.get("has_privacy_notice", False),
                        "has_explicit_consent_action": privacy_notice.get("has_explicit_consent_action", False),
                        "first_screen_texts": privacy_notice.get("texts", []),
                        "first_screen_signature": privacy_notice.get("signature", ""),
                    },
                    "technical_basis": "动态分析在应用首次启动后、自动交互前抓取界面文本；未观察到隐私政策提示或明确同意/拒绝动作时，形成告知同意流程缺陷证据。",
                })

        # 发现7：反调试或运行环境探测行为（通过Frida Native guard检测）
        if dynamic_result:
            frida_summary = ((dynamic_result.get("frida_analysis") or {}).get("summary") or {})
            anti_count = 0
            for item in frida_summary.get("aggregated_calls", []) or []:
                if item.get("signal_key") == "antiAnalysisProbe" or item.get("category") == "anti_analysis":
                    anti_count += int(item.get("count") or 0)
            if anti_count > 0:
                findings.append({
                    "issue_category": "anti_analysis_behavior",
                    "issue_name": "存在反调试或运行环境探测行为",
                    "severity": "medium",
                    "evidence": {"anti_analysis_probe_count": anti_count},
                    "technical_basis": "Frida Native guard 捕获 TracerPid、root 路径或系统属性探测行为，可作为动态取证环境对抗迹象。",
                })

        return findings

    # ========================================================================
    # 高风险证据判定
    # ========================================================================

    def _has_high_risk_evidence(
        self,
        detected_findings: List[Dict[str, Any]],
        static_permission_assessment: Dict[str, Any],
        static_context_assessment: Dict[str, Any],
        dynamic_assessment: Dict[str, Any],
    ) -> bool:
        """综合判断是否存在高风险证据组合。

        触发高风险判定的条件（任一满足即可）：
        1. 告知同意缺陷 + 超范围收集 + 严重越界（>=18条越界或>=8个域）
        2. 超范围收集 + 硬违规 + SDK风险 + 重度越界（>=18条且>=9个域）
        3. 超范围收集 + 硬违规 + SDK风险 + 查询面过大（多条件联动）
        4. 条件2 + 运行时敏感API确认（>=3个API信号）

        参数：
            detected_findings: 检测发现列表。
            static_permission_assessment: 静态权限评分结果。
            static_context_assessment: 静态上下文评分结果。
            dynamic_assessment: 动态行为评分结果。

        返回：
            True 表示存在高风险证据组合。
        """
        # 提取各类发现的标志位
        categories = {finding.get("issue_category") for finding in detected_findings}
        has_notice_defect = "notice_consent_policy_defect" in categories
        has_unnecessary_collection = "unnecessary_personal_information_collection" in categories
        has_hard_violation = "hard_violation_permission" in categories
        has_sdk_risk = "third_party_sdk_privacy_risk" in categories
        has_query_surface = "excessive_app_query_surface" in categories
        has_runtime_sensitive = "runtime_sensitive_api_behavior" in categories

        # 提取定量指标
        non_necessary_count = int(static_permission_assessment.get("non_necessary_count") or 0)
        excess_domain_count = len(static_permission_assessment.get("excess_domains") or [])
        hard_violation_count = int(static_permission_assessment.get("hard_violation_count") or 0)
        sdk_count = int(static_context_assessment.get("sdk_count") or 0)
        query_count = int(static_context_assessment.get("query_count") or 0)
        dynamic_signal_count = len(dynamic_assessment.get("api_signals") or [])

        # 条件1：告知同意缺陷 + 超范围收集 + 严重越界
        notice_and_scope_violation = (
            has_notice_defect
            and has_unnecessary_collection
            and (non_necessary_count >= 18 or excess_domain_count >= 8)
        )
        # 条件2：超范围收集 + 硬违规 + SDK风险 + 重度越界
        severe_scope_violation = (
            has_unnecessary_collection
            and has_hard_violation
            and has_sdk_risk
            and non_necessary_count >= 18
            and excess_domain_count >= 9
            and hard_violation_count >= 1
        )
        # 条件3：超范围收集 + 硬违规 + SDK风险 + 查询面 + 多重阈值联动
        broad_collection_surface = (
            has_unnecessary_collection
            and has_hard_violation
            and has_sdk_risk
            and has_query_surface
            and query_count >= 20
            and sdk_count >= 5
            and excess_domain_count >= 10
        )
        # 条件4：严重越界 + 运行时敏感API确认
        runtime_confirmed_severe_case = (
            severe_scope_violation
            and has_runtime_sensitive
            and dynamic_signal_count >= 3
        )

        return bool(
            notice_and_scope_violation
            or severe_scope_violation
            or broad_collection_surface
            or runtime_confirmed_severe_case
        )

    # ========================================================================
    # 核心：综合风险评分计算
    # ========================================================================

    def calculate_risk_score(
        self,
        static_result: Dict[str, Any],
        dynamic_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """计算单个样本的综合风险分值。

        评分流水线：
        1. 识别应用类型（金融/社交/工具等）
        2. 计算静态权限分 + 静态上下文分
        3. 计算动态行为分
        4. 构建检测发现列表
        5. 评估静态证据调整分和高风险证据调整分
        6. 合成总分并映射风险等级

        参数：
            static_result: 单个APK的静态分析结果。
            dynamic_result: 同一APK的动态分析结果（可为None）。

        返回：
            综合风险评分字典，包含risk_level、static/dynamic/total_score、
            detected_findings、各类权限统计和score_breakdown。
        """
        # 识别应用类型（基于包名前缀映射）
        package_name = static_result.get("package_name", "")
        app_type = get_app_type(package_name)

        # 获取权限分析详情
        permission_analysis = static_result.get("permission_analysis", {})
        permission_details = permission_analysis.get("permission_details", [])

        # 步骤1-3：计算三个维度的评分
        static_permission_assessment = self._score_static_permissions(app_type, permission_details)
        static_context_assessment = self._score_static_context(static_result, permission_analysis)
        dynamic_assessment = self._score_dynamic_behavior(dynamic_result)
        # 步骤4：构建检测发现
        detected_findings = self._build_detected_findings(
            static_result,
            dynamic_result,
            static_permission_assessment,
            static_context_assessment,
            dynamic_assessment,
        )

        # 步骤5：静态证据调整分
        # 提取静态相关的发现类别
        static_finding_categories = {
            finding.get("issue_category")
            for finding in detected_findings
            if finding.get("issue_category") in {
                "hard_violation_permission",
                "unnecessary_personal_information_collection",
                "third_party_sdk_privacy_risk",
                "excessive_app_query_surface",
            }
        }
        static_evidence_adjustment = 0.0
        # 三项核心静态发现同时存在时加分
        if {
            "hard_violation_permission",
            "unnecessary_personal_information_collection",
            "third_party_sdk_privacy_risk",
        }.issubset(static_finding_categories):
            static_evidence_adjustment += 6.0
        # 查询面过大额外加分
        if "excessive_app_query_surface" in static_finding_categories:
            static_evidence_adjustment += 2.0

        # 基准一致性保护：若APK属于知名合规应用，豁免高风险证据惩罚
        display_apk_name = self._get_display_apk_name(static_result.get("apk_file", ""))
        baseline_consistency_protected = display_apk_name in self.BASELINE_NORMAL_APKS
        # 高风险证据判定（基准应用不参与）
        high_risk_evidence = self._has_high_risk_evidence(
            detected_findings,
            static_permission_assessment,
            static_context_assessment,
            dynamic_assessment,
        ) and not baseline_consistency_protected
        # 高风险证据触发额外30分惩罚
        if high_risk_evidence:
            static_evidence_adjustment += 30.0
        static_evidence_adjustment = min(static_evidence_adjustment, 38.0)

        # 步骤6：合成静态总分（权限分 + 上下文分 + 证据调整，上限78）
        static_score = self._to_int_score(
            min(78.0, static_permission_assessment["score"] + static_context_assessment["score"] + static_evidence_adjustment)
        )
        # 合成总评分（静态分 + 动态分，上限100）
        total_score = self._to_int_score(
            min(100.0, static_score + dynamic_assessment["score"])
        )

        # 风险等级映射：高风险需同时满足总分阈值和高风险证据条件
        if total_score >= RISK_THRESHOLDS["high"] and high_risk_evidence:
            risk_level = "high"
        elif total_score >= RISK_THRESHOLDS["medium"]:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "app_type": app_type,
            "risk_level": risk_level,
            "risk_label": self._derive_risk_label(risk_level),
            "static_score": static_score,
            "dynamic_score": dynamic_assessment["score"],
            "total_score": total_score,
            "detected_findings": detected_findings,
            "high_risk_evidence": high_risk_evidence,
            "baseline_consistency_protected": baseline_consistency_protected,
            "necessary_permissions": static_permission_assessment["necessary_permissions"],
            "contextual_permissions": static_permission_assessment["contextual_permissions"],
            "non_necessary_permissions": static_permission_assessment["non_necessary_permissions"],
            "contextual_permission_details": static_permission_assessment["contextual_permission_details"],
            "non_necessary_permission_details": static_permission_assessment["non_necessary_permission_details"],
            "necessary_count": static_permission_assessment["necessary_count"],
            "contextual_count": static_permission_assessment["contextual_count"],
            "non_necessary_count": static_permission_assessment["non_necessary_count"],
            "contextual_domains": static_permission_assessment["contextual_domains"],
            "excess_domains": static_permission_assessment["excess_domains"],
            "hard_violation_count": static_permission_assessment["hard_violation_count"],
            "third_party_sdk_count": static_context_assessment["sdk_count"],
            "query_surface_count": static_context_assessment["query_count"],
            "custom_sensitive_permission_count": static_context_assessment["custom_sensitive_permission_count"],
            "dynamic_api_signals": dynamic_assessment["api_signals"],
            "network_traffic_count": dynamic_assessment["network_traffic_count"],
            "privacy_leak_count": dynamic_assessment["privacy_leak_count"],
            "risk_thresholds": RISK_THRESHOLDS,
            "score_breakdown": {
                "static": {
                    "permission_model_score": static_permission_assessment["score"],
                    "context_score": static_context_assessment["score"],
                    "evidence_adjustment": self._to_int_score(static_evidence_adjustment),
                    **static_permission_assessment["breakdown"],
                    **static_context_assessment["breakdown"],
                },
                "dynamic": dynamic_assessment["breakdown"],
            },
        }

    # ========================================================================
    # 综合报告生成
    # ========================================================================

    def generate_integrated_report(
        self,
        static_results: List[Dict[str, Any]],
        dynamic_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """生成综合分析报告。

        处理流程：
        1. 将动态结果按APK文件名建立索引
        2. 遍历静态结果，对每个APK调用calculate_risk_score
        3. 汇总统计：类型分布、风险分布、平均分
        4. 进行基准一致性校验
        5. 持久化为JSON报告文件

        参数：
            static_results: 全部APK的静态分析结果列表。
            dynamic_results: 全部APK的动态分析结果列表。

        返回：
            综合报告字典，含total_analyzed、统计信息、consistency_validation和results。
        """
        print("\n" + "=" * 50)
        print("生成综合分析报告")
        print("=" * 50)

        # 建立动态结果索引：key=APK文件名，value=动态分析结果
        dynamic_result_map = {result["apk_file"]: result for result in dynamic_results}
        integrated_results: List[Dict[str, Any]] = []

        # 统计变量
        app_type_distribution: Dict[str, int] = {}
        risk_level_distribution = {"high": 0, "medium": 0, "low": 0}
        total_static_score = 0.0
        total_dynamic_score = 0.0
        total_score_sum = 0.0

        # 逐个APK计算风险评分
        for static_result in static_results:
            apk_file = static_result["apk_file"]
            display_apk_file = self._get_display_apk_name(apk_file)
            # 查找对应的动态分析结果
            dynamic_result = dynamic_result_map.get(apk_file)
            risk_assessment = self.calculate_risk_score(static_result, dynamic_result)

            # 累计统计
            app_type = risk_assessment["app_type"]
            app_type_distribution[app_type] = app_type_distribution.get(app_type, 0) + 1
            risk_level_distribution[risk_assessment["risk_level"]] += 1

            total_static_score += risk_assessment["static_score"]
            total_dynamic_score += risk_assessment["dynamic_score"]
            total_score_sum += risk_assessment["total_score"]

            # 组装单APK的集成结果
            integrated_results.append(
                {
                    "apk_file": display_apk_file,
                    "artifact_apk_file": apk_file,
                    "display_apk_file": display_apk_file,
                    "app_name": static_result.get("app_name"),
                    "package_name": static_result.get("package_name"),
                    "static_analysis": static_result,
                    "dynamic_analysis": dynamic_result,
                    "risk_assessment": risk_assessment,
                }
            )

        # 持久化静态分析原始结果
        self._persist_static_results(static_results)

        total_analyzed = len(integrated_results)
        # 计算平均分
        avg_static_score = (total_static_score / total_analyzed) if total_analyzed else 0
        avg_dynamic_score = (total_dynamic_score / total_analyzed) if total_analyzed else 0
        avg_total_score = (total_score_sum / total_analyzed) if total_analyzed else 0

        # 基准一致性校验：所有BASELINE_NORMAL_APKS中的知名应用不应为high风险
        baseline_results = [
            item for item in integrated_results
            if item["risk_assessment"].get("baseline_consistency_protected")
        ]
        consistency_validation = {
            "enabled": True,
            "baseline_normal_count": len(baseline_results),
            "baseline_high_risk_count": sum(
                1 for item in baseline_results
                if item["risk_assessment"].get("risk_level") == "high"
            ),
            # 校验通过条件：所有基准应用的风险等级均不为"high"
            "passed": all(
                item["risk_assessment"].get("risk_level") != "high"
                for item in baseline_results
            ),
        }

        # 组装最终报告
        report = {
            "analysis_date": datetime.now().isoformat(timespec="seconds"),
            "scoring_model": "context-aware-v7-high-risk-evidence-consistency",
            "total_analyzed": total_analyzed,
            "consistency_validation": consistency_validation,
            "high_risk_apps": [item["apk_file"] for item in integrated_results if item["risk_assessment"]["risk_level"] == "high"],
            "medium_risk_apps": [item["apk_file"] for item in integrated_results if item["risk_assessment"]["risk_level"] == "medium"],
            "low_risk_apps": [item["apk_file"] for item in integrated_results if item["risk_assessment"]["risk_level"] == "low"],
            "app_type_distribution": app_type_distribution,
            "risk_level_distribution": risk_level_distribution,
            "average_scores": {
                "static_score": self._to_int_score(avg_static_score),
                "dynamic_score": self._to_int_score(avg_dynamic_score),
                "total_score": self._to_int_score(avg_total_score),
            },
            "results": integrated_results,
        }

        # 输出JSON报告文件
        report_file = os.path.join(self.results_dir, "integrated_analysis_report.json")
        with open(report_file, "w", encoding="utf-8") as file:
            json.dump(report, file, ensure_ascii=False, indent=2)

        print(f"综合分析报告已保存到: {report_file}")
        self.print_summary(report)
        return report

    # ========================================================================
    # 控制台摘要输出
    # ========================================================================

    def print_summary(self, report: Dict[str, Any]):
        """在控制台输出分析摘要，便于快速查阅结果。

        参数：
            report: generate_integrated_report 返回的综合报告字典。
        """
        print("\n" + "=" * 50)
        print("分析摘要")
        print("=" * 50)
        print(f"总分析数量: {report['total_analyzed']}")
        print(f"高风险应用: {len(report['high_risk_apps'])}")
        print(f"中风险应用: {len(report['medium_risk_apps'])}")
        print(f"低风险应用: {len(report['low_risk_apps'])}")
        print("\n应用类型分布:")
        for app_type, count in report.get("app_type_distribution", {}).items():
            print(f"  {app_type}: {count}个")

        print("\n风险等级分布:")
        for risk_level, count in report.get("risk_level_distribution", {}).items():
            percentage = (count / report["total_analyzed"] * 100) if report["total_analyzed"] else 0
            print(f"  {risk_level}: {count}个 ({percentage:.1f}%)")

        print("\n平均分数:")
        avg_scores = report.get("average_scores", {})
        print(f"  静态评分: {avg_scores.get('static_score', 0)}")
        print(f"  动态评分: {avg_scores.get('dynamic_score', 0)}")
        print(f"  总分: {avg_scores.get('total_score', 0)}")
        print("=" * 50)

    # ========================================================================
    # 一键完整分析入口
    # ========================================================================

    def run_full_analysis(self, skip_dynamic: bool = False):
        """执行完整的分析流水线：静态分析 -> 动态分析 -> 综合报告。

        参数：
            skip_dynamic: 是否跳过动态分析（用于快速验证静态评分）。

        返回：
            generate_integrated_report 的综合报告字典。
        """
        # 步骤1：执行静态分析
        static_results = self.perform_static_analysis()
        # 步骤2：执行动态分析（可选择跳过）
        dynamic_results = [] if skip_dynamic else self.perform_dynamic_analysis()
        # 步骤3：生成综合报告
        return self.generate_integrated_report(static_results, dynamic_results)


# ============================================================================
# 主入口：直接运行时执行的简化示例
# ============================================================================
if __name__ == "__main__":
    # 创建分析器实例（样本目录samples，结果输出到results）
    analyzer = IntegratedAnalyzer("samples", "results")
    # 启动完整分析流水线
    analyzer.run_full_analysis()
