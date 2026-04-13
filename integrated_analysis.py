import json
import math
import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from static_analysis.apk_analyzer import APKBatchAnalyzer
from dynamic_analysis.analyzer import DynamicBatchAnalyzer
from app_type_permissions import (
    CONTEXTUAL_PERMISSION_DOMAINS,
    PERMISSION_RISK_LEVELS,
    RISK_THRESHOLDS,
    SENSITIVE_API_WEIGHTS,
    get_app_type,
    get_permission_category,
)


class IntegratedAnalyzer:
    DOMAIN_BASE_SCORES = {
        "location": 4.0,
        "camera": 4.0,
        "microphone": 4.0,
        "contacts": 4.2,
        "sms": 5.0,
        "phone": 4.0,
        "storage": 2.6,
        "calendar": 2.0,
        "account": 3.0,
        "biometric": 3.0,
        "identifier": 3.2,
        "app_installation": 3.0,
        "shortcut": 1.0,
        "system_control": 3.2,
        "system_inspection": 4.8,
        "notification": 1.0,
        "other": 1.2,
    }

    DYNAMIC_API_WEIGHTS = {
        "getDeviceId": 2.4,
        "getSubscriberId": 2.4,
        "getMacAddress": 2.1,
        "getAndroidId": 2.2,
        "getOaid": 2.2,
        "getLocation": 2.0,
        "openCamera": 1.8,
        "startRecording": 1.8,
        "readContacts": 2.0,
        "readSms": 2.5,
        "readCallLog": 2.6,
        "accessStorage": 1.3,
        "accessNetwork": 1.1,
        "accessCalendar": 1.6,
        "getInstalledPackages": 2.1,
        "getAccount": 1.7,
        "readClipboard": 1.5,
        "sendSms": 2.8,
        "reflectionInvoke": 1.4,
        "getSystemService": 0.8,
        "appOpsSensitiveAction": 1.7,
    }

    SDK_CATEGORY_WEIGHTS = {
        "ad": 2.2,
        "analytics": 1.6,
        "social": 1.0,
        "payment": 0.8,
        "map": 0.8,
        "push": 0.3,
    }

    SDK_RISK_HINT_WEIGHTS = {
        "low": 0.2,
        "medium": 0.8,
        "中": 0.8,
        "medium_high": 1.2,
        "中高": 1.2,
        "high": 1.6,
        "高": 1.6,
    }

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

    IDENTIFIER_PATTERNS = (
        "oaid",
        "msa",
        "identifier",
        "device_id",
        "supplementarydid",
        "did",
    )

    HARD_VIOLATION_PATTERNS = (
        "read_sms",
        "send_sms",
        "write_sms",
        "read_logs",
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
    )

    @staticmethod
    def _to_int_score(value: float) -> int:
        # Use half-up style for positive scores to avoid long float tails in UI.
        return int(math.floor(float(value) + 0.5))

    def __init__(
        self,
        samples_dir: str,
        results_dir: str = "results",
        dynamic_timeout_per_apk: int = 300,
    ):
        self.samples_dir = samples_dir
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)

        self.static_analyzer = APKBatchAnalyzer(samples_dir, results_dir)
        self.dynamic_analyzer = DynamicBatchAnalyzer(
            samples_dir,
            results_dir,
            per_apk_timeout=dynamic_timeout_per_apk,
        )

    def perform_static_analysis(self) -> List[Dict[str, Any]]:
        print("=" * 50)
        print("开始静态分析")
        print("=" * 50)

        static_results = self.static_analyzer.analyze_all()
        print(f"\n静态分析完成，共分析 {len(static_results)} 个APK")
        return static_results

    def perform_dynamic_analysis(self) -> List[Dict[str, Any]]:
        print("=" * 50)
        print("开始动态分析")
        print("=" * 50)

        dynamic_results = self.dynamic_analyzer.analyze_all()
        print(f"\n动态分析完成，共分析 {len(dynamic_results)} 个APK")
        return dynamic_results

    def _unique(self, values: List[str]) -> List[str]:
        seen = set()
        ordered: List[str] = []
        for value in values:
            if value and value not in seen:
                seen.add(value)
                ordered.append(value)
        return ordered

    def _derive_risk_label(self, risk_level: str) -> str:
        return {
            "high": "涉嫌高危违规APP",
            "medium": "中度越界风险APP",
            "low": "合规应用",
        }.get(risk_level, "合规应用")

    def _get_permission_domain(self, permission: str) -> Optional[str]:
        perm = permission.lower()

        if any(pattern in perm for pattern in self.INFRASTRUCTURE_PATTERNS):
            return None

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
        return "other"

    def _get_permission_base_weight(self, permission: str, main_risk_level: str) -> Tuple[float, Optional[str]]:
        domain = self._get_permission_domain(permission)
        if domain is None:
            return 0.0, None

        level_weight = float(PERMISSION_RISK_LEVELS.get(main_risk_level, 0.0))
        domain_weight = self.DOMAIN_BASE_SCORES.get(domain, self.DOMAIN_BASE_SCORES["other"])
        weight = max(level_weight, domain_weight)

        perm = permission.lower()
        if any(pattern in perm for pattern in self.LOW_SIGNAL_PATTERNS):
            weight *= 0.35
        if any(pattern in perm for pattern in self.IDENTIFIER_PATTERNS):
            weight *= 0.65
        if domain == "notification":
            weight *= 0.8
        if domain == "other" and permission.count(".") >= 2 and not permission.startswith("android.permission."):
            weight *= 0.5

        return round(weight, 2), domain

    def _is_hard_violation_permission(self, permission: str) -> bool:
        perm = permission.lower()
        return any(pattern in perm for pattern in self.HARD_VIOLATION_PATTERNS)

    def _score_static_permissions(
        self,
        app_type: str,
        permission_details: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        necessary_permissions: List[str] = []
        contextual_permission_details: List[Dict[str, Any]] = []
        non_necessary_permission_details: List[Dict[str, Any]] = []

        contextual_domains = CONTEXTUAL_PERMISSION_DOMAINS.get(app_type, set())
        contextual_domain_scores: Dict[str, float] = {}
        excess_domain_scores: Dict[str, float] = {}
        excess_domain_counts: Dict[str, int] = {}
        hard_violation_count = 0

        for perm_detail in permission_details:
            permission_name = perm_detail.get("name", "")
            if not permission_name:
                continue

            if get_permission_category(app_type, permission_name) == "necessary":
                necessary_permissions.append(permission_name)
                continue

            risk_level = perm_detail.get("main_risk_level", "")
            adjusted_weight, domain = self._get_permission_base_weight(permission_name, risk_level)
            if domain is None or adjusted_weight < 0.5:
                continue

            record = {
                "name": permission_name,
                "domain": domain,
                "weight": adjusted_weight,
                "risk_level": risk_level,
            }

            if self._is_hard_violation_permission(permission_name):
                hard_violation_count += 1
                non_necessary_permission_details.append(record)
                excess_domain_scores[domain] = max(excess_domain_scores.get(domain, 0.0), adjusted_weight)
                excess_domain_counts[domain] = excess_domain_counts.get(domain, 0) + 1
            elif domain in contextual_domains:
                contextual_permission_details.append(record)
                contextual_domain_scores[domain] = max(contextual_domain_scores.get(domain, 0.0), adjusted_weight)
            else:
                non_necessary_permission_details.append(record)
                excess_domain_scores[domain] = max(excess_domain_scores.get(domain, 0.0), adjusted_weight)
                excess_domain_counts[domain] = excess_domain_counts.get(domain, 0) + 1

        excess_domain_score = round(sum(excess_domain_scores.values()), 2)
        contextual_domain_score = round(sum(contextual_domain_scores.values()), 2)
        excess_duplicate_bonus = round(
            sum(min(count - 1, 2) * 0.35 for count in excess_domain_counts.values() if count > 1),
            2,
        )
        hard_violation_bonus = round(min(hard_violation_count * 2.5, 10.0), 2)

        static_score_raw = (
            min(
                85.0,
                excess_domain_score * 1.5
                + contextual_domain_score * 0.18
                + excess_duplicate_bonus
                + hard_violation_bonus,
            )
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
            "breakdown": {
                "excess_domain_score": excess_domain_score,
                "contextual_domain_score": contextual_domain_score,
                "excess_duplicate_bonus": excess_duplicate_bonus,
                "hard_violation_bonus": hard_violation_bonus,
            },
        }

    def _score_static_context(
        self,
        static_result: Dict[str, Any],
        permission_analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        sdk_score = 0.0
        for sdk in static_result.get("third_party_sdks", []) or []:
            category = str(sdk.get("category", "")).strip().lower()
            risk_hint = str(sdk.get("risk_hint", "")).strip()
            sdk_score += max(
                self.SDK_CATEGORY_WEIGHTS.get(category, 0.6),
                self.SDK_RISK_HINT_WEIGHTS.get(risk_hint, 0.0),
            )
        sdk_score = round(min(sdk_score, 6.0), 2)

        queries = static_result.get("queries", {}) or {}
        query_count = (
            len(queries.get("packages", []) or [])
            + len(queries.get("providers", []) or [])
            + len(queries.get("intents", []) or [])
        )
        query_score = round(min(query_count * 0.4, 3.0), 2)

        custom_sensitive_permissions = {
            item.get("name")
            for item in permission_analysis.get("permission_details", [])
            if item.get("is_custom") and item.get("main_risk_level") in {"中高", "高", "极高"}
        }
        custom_permission_score = round(min(len(custom_sensitive_permissions) * 0.7, 3.0), 2)

        context_score = self._to_int_score(min(10.0, sdk_score + query_score + custom_permission_score))
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

    def _get_dynamic_signal_count(self, payload: Any) -> int:
        if isinstance(payload, dict):
            if isinstance(payload.get("count"), int):
                return payload["count"]
            logs = payload.get("logs")
            if isinstance(logs, list):
                return len(logs)
            return 1
        if isinstance(payload, list):
            return len(payload)
        return 1 if payload else 0

    def _score_dynamic_behavior(self, dynamic_result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
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

        api_signals: List[Dict[str, Any]] = []
        api_score = 0.0
        for api_type, payload in dynamic_result.get("sensitive_api_calls", {}).items():
            count = self._get_dynamic_signal_count(payload)
            if count <= 0:
                continue

            weight = self.DYNAMIC_API_WEIGHTS.get(api_type, 1.4)
            contribution = round(min(math.log1p(count) * weight, 4.5), 2)
            api_signals.append(
                {
                    "api_type": api_type,
                    "count": count,
                    "weight": weight,
                    "score": contribution,
                }
            )
            api_score += contribution

        network_traffic_count = len(dynamic_result.get("network_traffic", []))
        network_weight = SENSITIVE_API_WEIGHTS.get("network", 1.0)
        network_score = round(min(math.log1p(network_traffic_count) * (0.85 * network_weight), 2.8), 2)

        privacy_leak_count = len(dynamic_result.get("privacy_leaks", []))
        privacy_score = round(min(privacy_leak_count * 2.5, 6.0), 2)

        dynamic_score = self._to_int_score(min(15.0, api_score + network_score + privacy_score))
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

    def calculate_risk_score(
        self,
        static_result: Dict[str, Any],
        dynamic_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        package_name = static_result.get("package_name", "")
        app_type = get_app_type(package_name)

        permission_analysis = static_result.get("permission_analysis", {})
        permission_details = permission_analysis.get("permission_details", [])

        static_permission_assessment = self._score_static_permissions(app_type, permission_details)
        static_context_assessment = self._score_static_context(static_result, permission_analysis)
        dynamic_assessment = self._score_dynamic_behavior(dynamic_result)

        static_score = self._to_int_score(
            min(85.0, static_permission_assessment["score"] + static_context_assessment["score"])
        )
        total_score = self._to_int_score(min(100.0, static_score + dynamic_assessment["score"]))

        if total_score >= RISK_THRESHOLDS["high"]:
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
                    **static_permission_assessment["breakdown"],
                    **static_context_assessment["breakdown"],
                },
                "dynamic": dynamic_assessment["breakdown"],
            },
        }

    def generate_integrated_report(
        self,
        static_results: List[Dict[str, Any]],
        dynamic_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        print("\n" + "=" * 50)
        print("生成综合分析报告")
        print("=" * 50)

        dynamic_result_map = {result["apk_file"]: result for result in dynamic_results}
        integrated_results: List[Dict[str, Any]] = []

        app_type_distribution: Dict[str, int] = {}
        risk_level_distribution = {"high": 0, "medium": 0, "low": 0}
        total_static_score = 0.0
        total_dynamic_score = 0.0

        for static_result in static_results:
            apk_file = static_result["apk_file"]
            dynamic_result = dynamic_result_map.get(apk_file)
            risk_assessment = self.calculate_risk_score(static_result, dynamic_result)

            app_type = risk_assessment["app_type"]
            app_type_distribution[app_type] = app_type_distribution.get(app_type, 0) + 1
            risk_level_distribution[risk_assessment["risk_level"]] += 1

            total_static_score += risk_assessment["static_score"]
            total_dynamic_score += risk_assessment["dynamic_score"]

            integrated_results.append(
                {
                    "apk_file": apk_file,
                    "package_name": static_result.get("package_name"),
                    "static_analysis": static_result,
                    "dynamic_analysis": dynamic_result,
                    "risk_assessment": risk_assessment,
                }
            )

        total_analyzed = len(integrated_results)
        avg_static_score = (total_static_score / total_analyzed) if total_analyzed else 0
        avg_dynamic_score = (total_dynamic_score / total_analyzed) if total_analyzed else 0
        avg_total_score = ((total_static_score + total_dynamic_score) / total_analyzed) if total_analyzed else 0

        report = {
            "analysis_date": datetime.now().isoformat(timespec="seconds"),
            "scoring_model": "context-aware-v3",
            "total_analyzed": total_analyzed,
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

        report_file = os.path.join(self.results_dir, "integrated_analysis_report.json")
        with open(report_file, "w", encoding="utf-8") as file:
            json.dump(report, file, ensure_ascii=False, indent=2)

        print(f"综合分析报告已保存到: {report_file}")
        self.print_summary(report)
        return report

    def print_summary(self, report: Dict[str, Any]):
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

    def run_full_analysis(self, skip_dynamic: bool = False):
        static_results = self.perform_static_analysis()
        dynamic_results = [] if skip_dynamic else self.perform_dynamic_analysis()
        return self.generate_integrated_report(static_results, dynamic_results)


if __name__ == "__main__":
    analyzer = IntegratedAnalyzer("samples", "results")
    analyzer.run_full_analysis()
