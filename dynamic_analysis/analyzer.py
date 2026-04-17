import json
import multiprocessing
import os
import re
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

from tqdm import tqdm

try:
    from dynamic_engine.frida_analyzer import EnhancedDynamicAnalyzer

    frida_available = True
except ImportError:
    print("warning: Frida module is unavailable, dynamic Frida analysis will be skipped")
    frida_available = False


class DynamicAnalyzer:
    SAFE_ACTION_KEYWORDS = (
        "允许",
        "始终允许",
        "仅在使用中",
        "仅在使用期间",
        "同意",
        "确定",
        "确认",
        "继续",
        "进入",
        "开始",
        "去开启",
        "去设置",
    )

    DISMISS_ACTION_KEYWORDS = (
        "跳过",
        "关闭",
        "我知道了",
        "知道了",
        "以后再说",
        "稍后",
        "暂不",
        "下次再说",
        "稍后再说",
        "稍后处理",
        "下次",
    )

    NEGATIVE_ACTION_KEYWORDS = (
        "拒绝",
        "不允许",
        "不同意",
        "禁止",
        "取消",
        "拒不",
        "暂不授权",
        "不再",
    )

    PERMISSION_ALLOW_RESOURCE_HINTS = (
        "permission_allow_always_button",
        "permission_allow_foreground_only_button",
        "permission_allow_one_time_button",
        "permission_allow_button",
        "permission_allow_selected_button",
        "permission_allow_all_button",
        "grant_dialog_button_allow",
        "button1",
    )

    PERMISSION_DENY_RESOURCE_HINTS = (
        "permission_deny_and_dont_ask_again_button",
        "permission_deny_button",
        "permission_no_upgrade_button",
        "permission_no_upgrade_and_dont_ask_again_button",
        "grant_dialog_button_deny",
        "button2",
    )

    LOGIN_GATE_KEYWORDS = (
        "登录",
        "立即登录",
        "手机号登录",
        "微信登录",
        "qq登录",
        "验证码",
        "密码",
        "账号",
        "一键登录",
        "授权登录",
        "登录后",
        "注册",
    )

    LOADING_KEYWORDS = (
        "加载",
        "启动中",
        "请稍候",
        "正在打开",
        "初始化",
        "loading",
        "splash",
        "opening",
    )

    SYSTEM_DIALOG_PACKAGES = (
        "android",
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
        "com.android.packageinstaller",
        "com.android.systemui",
    )

    BLOCKED_INTERACTION_KEYWORDS = (
        "下载",
        "安装",
        "更新",
        "立即下载",
        "立即安装",
        "应用市场",
        "游戏中心",
        "download",
        "install",
        "update",
        "market",
        "store",
        "gamecenter",
        "launcher",
    )

    CLEANUP_PROTECTED_PACKAGES = (
        "android",
        "com.android.systemui",
        "com.android.settings",
        "com.android.shell",
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        "com.android.inputmethod.latin",
        "com.google.android.inputmethod.latin",
        "com.android.documentsui",
        "com.bignox.launcher",
        "com.android.launcher",
        "com.android.launcher3",
        "com.google.android.apps.nexuslauncher",
    )

    CLEANUP_PROTECTED_PREFIXES = (
        "com.android.",
        "com.google.android.",
        "android.",
        "com.qualcomm.",
        "com.mediatek.",
        "com.bignox.",
        "com.nox.",
    )

    def __init__(
        self,
        apk_path: str,
        output_dir: str = "output",
        manual_probe_seconds: int = 0,
        low_coverage_api_threshold: int = 4,
        analysis_timeout_budget_seconds: int = 0,
    ):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.package_name = self._extract_package_name_from_apk()
        self.main_activity = self._extract_main_activity_from_apk()
        self.adb_path = self._find_adb()
        self.sensitive_apis = self._load_sensitive_apis()
        self.monitoring_logs: List[str] = []
        self.manual_probe_seconds = max(0, int(manual_probe_seconds))
        self.low_coverage_api_threshold = max(1, int(low_coverage_api_threshold))
        self.analysis_timeout_budget_seconds = max(0, int(analysis_timeout_budget_seconds))
        self.analysis_started_at = 0.0
        self.analysis_deadline: Optional[float] = None
        self.frida_analyzer = EnhancedDynamicAnalyzer(apk_path, output_dir) if frida_available else None
        self.device_id: Optional[str] = None
        self.app_pid: Optional[str] = None
        self.app_pids: List[str] = []
        self.last_launch_error: Optional[str] = None
        if self.frida_analyzer and self.package_name:
            self.frida_analyzer.set_package_name(self.package_name)

    def _activate_analysis_budget(self) -> None:
        self.analysis_started_at = time.time()
        if self.analysis_timeout_budget_seconds > 0:
            self.analysis_deadline = self.analysis_started_at + self.analysis_timeout_budget_seconds
        else:
            self.analysis_deadline = None

    def _remaining_analysis_budget(self) -> Optional[float]:
        if self.analysis_deadline is None:
            return None
        return max(0.0, self.analysis_deadline - time.time())

    def _has_analysis_budget(self, minimum_seconds: int = 1, reserve_seconds: int = 0) -> bool:
        remaining = self._remaining_analysis_budget()
        if remaining is None:
            return True
        return remaining > max(0, int(minimum_seconds) + int(reserve_seconds))

    def _step_budget(
        self,
        requested_seconds: int,
        minimum_seconds: int = 0,
        reserve_seconds: int = 0,
    ) -> int:
        requested = max(0, int(requested_seconds))
        minimum = max(0, int(minimum_seconds))
        reserve = max(0, int(reserve_seconds))
        remaining = self._remaining_analysis_budget()
        if remaining is None:
            return requested
        allowed = max(0, int(remaining) - reserve)
        if allowed <= 0:
            return 0
        if minimum and allowed < minimum:
            return 0
        if requested <= 0:
            return allowed
        return max(minimum if minimum else 0, min(requested, allowed))

    def _find_adb(self) -> str:
        adb_paths = [
            r"E:\Nox\bin\nox_adb.exe",
            r"C:\Program Files (x86)\Nox\bin\adb.exe",
            "adb",
        ]
        for path in adb_paths:
            try:
                subprocess.run([path, "version"], capture_output=True, check=True, timeout=5)
                print(f"found adb: {path}")
                return path
            except Exception:
                continue
        print("warning: adb was not found, using fallback name `adb`")
        return "adb"

    def _find_aapt(self) -> Optional[str]:
        android_home = os.environ.get("ANDROID_HOME")
        if android_home:
            build_tools = os.path.join(android_home, "build-tools")
            if os.path.exists(build_tools):
                for version in sorted(os.listdir(build_tools), reverse=True):
                    aapt_path = os.path.join(build_tools, version, "aapt.exe")
                    if os.path.exists(aapt_path):
                        return aapt_path
        for path in [r"E:\Nox\bin\nox_aapt.exe", "aapt"]:
            try:
                subprocess.run([path, "version"], capture_output=True, timeout=5)
                return path
            except Exception:
                continue
        return None

    def _extract_package_name_from_apk(self) -> Optional[str]:
        aapt = self._find_aapt()
        if not aapt:
            print("warning: aapt was not found, trying androguard fallback")
        else:
            try:
                result = subprocess.run(
                    [aapt, "dump", "badging", self.apk_path],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=20,
                )
                if result.returncode == 0:
                    match = re.search(r"package: name='([^']+)'", result.stdout)
                    if match:
                        return match.group(1)
            except Exception as error:
                print(f"extract package name by aapt failed: {error}")
        try:
            from androguard.core.apk import APK

            apk = APK(self.apk_path)
            package_name = apk.get_package()
            if package_name:
                print(f"package extracted by androguard: {package_name}")
                return package_name
        except Exception as error:
            print(f"extract package name by androguard failed: {error}")
        return None

    def _extract_main_activity_from_apk(self) -> Optional[str]:
        aapt = self._find_aapt()
        if aapt:
            try:
                result = subprocess.run(
                    [aapt, "dump", "badging", self.apk_path],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=20,
                )
                if result.returncode == 0:
                    match = re.search(r"launchable-activity: name='([^']+)'", result.stdout)
                    if match:
                        return str(match.group(1)).strip()
            except Exception as error:
                print(f"extract main activity by aapt failed: {error}")

        try:
            from androguard.core.apk import APK

            apk = APK(self.apk_path)
            main_activity = apk.get_main_activity()
            if main_activity:
                return str(main_activity).strip()
        except Exception as error:
            print(f"extract main activity by androguard failed: {error}")
        return None

    def _build_launch_component(self) -> Optional[str]:
        if not self.package_name or not self.main_activity:
            return None
        activity_name = str(self.main_activity).strip()
        if not activity_name:
            return None
        if activity_name.startswith("."):
            return f"{self.package_name}/{activity_name}"
        if "." not in activity_name:
            return f"{self.package_name}/.{activity_name}"
        return f"{self.package_name}/{activity_name}"

    def _load_sensitive_apis(self) -> Dict[str, str]:
        return {
            "getDeviceId": "device identifier",
            "getSubscriberId": "subscriber identifier",
            "getMacAddress": "mac address",
            "getAndroidId": "android id",
            "getOaid": "oaid or vendor identifier",
            "getLocation": "location",
            "openCamera": "camera access",
            "startRecording": "audio recording",
            "readContacts": "read contacts",
            "readSms": "read sms",
            "readCallLog": "read call log",
            "accessStorage": "storage access",
            "accessNetwork": "network access",
            "accessCalendar": "calendar access",
            "getInstalledPackages": "installed app list",
            "getAccount": "account info",
            "readClipboard": "clipboard access",
            "sendSms": "send sms",
            "reflectionInvoke": "reflection invoke",
            "getSystemService": "system service request",
            "appOpsSensitiveAction": "AppOps sensitive action",
            "permissionCheck": "permission check",
            "permissionRequest": "permission request",
            "webViewNavigation": "WebView navigation",
            "cookieAccess": "WebView cookie access",
            "antiAnalysisProbe": "anti-analysis or root-detection probe",
        }

    def _run_adb_command(self, command: List[str], timeout: int = 15, quiet: bool = False) -> Optional[str]:
        full_command = [self.adb_path] + command
        try:
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                if not quiet:
                    print(f"adb command timed out: {' '.join(full_command)}")
                return None
            if process.returncode != 0:
                message = (stderr or stdout or "").strip()
                if message and not quiet:
                    print(f"adb command failed: {message}")
                return None
            return (stdout or "").strip()
        except Exception as error:
            if not quiet:
                print(f"adb execution failed: {error}")
            return None

    def _check_command_exists(self, command: str) -> bool:
        try:
            subprocess.run([command, "--version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def check_device_connected(self) -> bool:
        output = self._run_adb_command(["devices"])
        if not output:
            return False
        lines = output.splitlines()[1:]
        for line in lines:
            if "\tdevice" in line:
                self.device_id = line.split("\t")[0].strip()
                print(f"connected device: {self.device_id}")
                return True
        return False

    def _start_frida_server(self) -> None:
        frida_server = "/data/local/tmp/frida-server-17.7.3-android-x86_64"
        setup_commands = [
            ["shell", "pkill frida-server || true"],
            ["shell", f"chmod 755 {frida_server}"],
            ["forward", "tcp:27042", "tcp:27042"],
            ["forward", "tcp:27043", "tcp:27043"],
            ["shell", f"{frida_server} >/dev/null 2>&1 &"],
        ]
        for command in setup_commands:
            self._run_adb_command(command, timeout=10)
        time.sleep(2)

    def _check_device_with_retry(self) -> bool:
        if self.check_device_connected():
            self._start_frida_server()
            return True

        self._run_adb_command(["kill-server"])
        time.sleep(1)
        self._run_adb_command(["start-server"], timeout=30)
        time.sleep(2)
        self._run_adb_command(["connect", "127.0.0.1:62025"], timeout=15)
        time.sleep(2)

        for _ in range(3):
            if self.check_device_connected():
                self._start_frida_server()
                return True
            time.sleep(2)
        print("unable to connect emulator device")
        return False

    def install_apk(self, timeout: int = 180) -> bool:
        print(f"installing apk: {self.apk_path}")
        try:
            result = subprocess.run(
                [self.adb_path, "install", "-r", "-t", "-g", self.apk_path],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            if result.returncode == 0 or "INSTALL_FAILED_ALREADY_EXISTS" in (result.stderr or ""):
                return True
            print(f"apk install failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            print("apk install timed out")
        except Exception as error:
            print(f"apk install error: {error}")
        return False

    def _refresh_app_pid(self) -> Optional[str]:
        if not self.package_name:
            self.app_pid = None
            self.app_pids = []
            return None
        output = self._run_adb_command(["shell", "pidof", self.package_name], timeout=10, quiet=True)
        if not output:
            self.app_pid = None
            self.app_pids = []
            self._sync_frida_preferred_pids()
            return None
        self.app_pids = [item.strip() for item in str(output).split() if str(item).strip()]
        self.app_pid = self.app_pids[0] if self.app_pids else None
        self._sync_frida_preferred_pids()
        return self.app_pid

    def _get_preferred_app_pids(self) -> List[int]:
        self._refresh_app_pid()
        preferred: List[int] = []
        seen = set()
        for pid_text in self.app_pids:
            try:
                pid = int(pid_text)
            except (TypeError, ValueError):
                continue
            if pid <= 0 or pid in seen:
                continue
            seen.add(pid)
            preferred.append(pid)
        return preferred

    def _sync_frida_preferred_pids(self) -> None:
        if not self.frida_analyzer:
            return
        preferred_pids: List[int] = []
        seen = set()
        for pid_text in self.app_pids:
            try:
                pid = int(pid_text)
            except (TypeError, ValueError):
                continue
            if pid <= 0 or pid in seen:
                continue
            seen.add(pid)
            preferred_pids.append(pid)
        self.frida_analyzer.set_preferred_pids(preferred_pids)

    def _is_app_running(self) -> bool:
        return self._refresh_app_pid() is not None

    def _force_stop_app(self) -> bool:
        if not self.package_name:
            return False
        self._run_adb_command(["shell", "am", "force-stop", self.package_name], timeout=15, quiet=True)
        self.app_pid = None
        self.app_pids = []
        self._sync_frida_preferred_pids()
        time.sleep(2)
        return True

    @staticmethod
    def _extract_package_names_from_text(text: str) -> List[str]:
        package_names = set()
        normalized_text = str(text or "")
        patterns = [
            r"\b([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+){1,})/",
            r"\bA=([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+){1,})\b",
            r"\bpackageName=([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+){1,})\b",
            r"\bpackage:([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+){1,})\b",
        ]
        for pattern in patterns:
            for match in re.findall(pattern, normalized_text):
                package_name = str(match or "").strip()
                if package_name:
                    package_names.add(package_name)
        return sorted(package_names)

    def _list_user_installed_packages(self) -> List[str]:
        output = self._run_adb_command(["shell", "pm", "list", "packages", "-3"], timeout=30, quiet=True) or ""
        package_names = []
        for line in output.splitlines():
            stripped = str(line or "").strip()
            if not stripped.startswith("package:"):
                continue
            package_name = stripped.split("package:", 1)[1].strip()
            if package_name:
                package_names.append(package_name)
        return self._merge_unique_text(package_names)

    def _collect_home_packages(self) -> List[str]:
        home_packages = set(self.CLEANUP_PROTECTED_PACKAGES)
        resolve_commands = [
            ["shell", "cmd", "package", "resolve-activity", "--brief", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME"],
            ["shell", "pm", "resolve-activity", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME"],
        ]
        for command in resolve_commands:
            output = self._run_adb_command(command, timeout=20, quiet=True) or ""
            for package_name in self._extract_package_names_from_text(output):
                home_packages.add(package_name)

        for package_name in self._list_user_installed_packages():
            lowered = package_name.lower()
            if "launcher" in lowered or lowered.endswith(".home") or ".home." in lowered:
                home_packages.add(package_name)

        foreground_package = self._get_foreground_package()
        if foreground_package:
            lowered = foreground_package.lower()
            if "launcher" in lowered or lowered.endswith(".home") or ".home." in lowered:
                home_packages.add(foreground_package)

        return sorted(home_packages)

    def _is_home_surface_package(self, package_name: Optional[str]) -> bool:
        normalized = str(package_name or "").strip().lower()
        if not normalized:
            return True
        home_packages = {str(item).strip().lower() for item in self._collect_home_packages()}
        if normalized in home_packages:
            return True
        if normalized in {str(item).strip().lower() for item in self.SYSTEM_DIALOG_PACKAGES}:
            return True
        return "launcher" in normalized or normalized.endswith(".home") or ".home." in normalized

    def _build_cleanup_protected_packages(self) -> set:
        protected_packages = set(self.SYSTEM_DIALOG_PACKAGES)
        protected_packages.update(self.CLEANUP_PROTECTED_PACKAGES)
        protected_packages.update(self._collect_home_packages())
        return {str(item).strip() for item in protected_packages if str(item).strip()}

    def _is_protected_cleanup_package(
        self,
        package_name: Optional[str],
        protected_packages: Optional[set] = None,
        allow_target: bool = False,
    ) -> bool:
        normalized = str(package_name or "").strip()
        if not normalized:
            return True

        target_package = str(self.package_name or "").strip()
        if allow_target and target_package and normalized == target_package:
            return False

        protected = {str(item).strip().lower() for item in (protected_packages or self._build_cleanup_protected_packages())}
        lowered = normalized.lower()
        if lowered in protected:
            return True
        return any(lowered.startswith(prefix) for prefix in self.CLEANUP_PROTECTED_PREFIXES)

    def _force_stop_package(
        self,
        package_name: Optional[str],
        protected_packages: Optional[set] = None,
        allow_target: bool = False,
        quiet: bool = True,
    ) -> bool:
        normalized = str(package_name or "").strip()
        if not normalized:
            return False
        if self._is_protected_cleanup_package(
            normalized,
            protected_packages=protected_packages,
            allow_target=allow_target,
        ):
            return False
        self._run_adb_command(["shell", "am", "force-stop", normalized], timeout=15, quiet=quiet)
        if self.package_name and normalized == self.package_name:
            self.app_pid = None
        time.sleep(0.4)
        return True

    def _clear_package_data(self, package_name: Optional[str], quiet: bool = True) -> bool:
        normalized = str(package_name or "").strip()
        if not normalized:
            return False
        output = self._run_adb_command(["shell", "pm", "clear", normalized], timeout=45, quiet=quiet)
        if output is None:
            return False
        return "success" in output.lower()

    def _collect_background_candidate_packages(self) -> List[str]:
        protected_packages = self._build_cleanup_protected_packages()
        package_names = set()
        dump_commands = [
            ["shell", "dumpsys", "activity", "recents"],
            ["shell", "dumpsys", "activity", "activities"],
            ["shell", "dumpsys", "window", "windows"],
        ]
        for command in dump_commands:
            output = self._run_adb_command(command, timeout=25, quiet=True) or ""
            package_names.update(self._extract_package_names_from_text(output))

        foreground_package = self._get_foreground_package()
        if foreground_package:
            package_names.add(foreground_package)

        target_package = str(self.package_name or "").strip()
        cleaned = []
        for package_name in sorted(package_names):
            if not package_name or package_name == target_package:
                continue
            if self._is_protected_cleanup_package(package_name, protected_packages=protected_packages):
                continue
            cleaned.append(package_name)
        return self._merge_unique_text(cleaned)

    def _return_to_home_screen(self, retries: int = 3) -> bool:
        for _ in range(max(1, int(retries))):
            self._run_adb_command(["shell", "input", "keyevent", "3"], timeout=8, quiet=True)
            time.sleep(1)
            foreground_package = self._get_foreground_package()
            if self._is_home_surface_package(foreground_package):
                return True
        return False

    def reset_analysis_environment(
        self,
        clear_app_data: bool = False,
        cleanup_background_apps: bool = True,
        clear_logs: bool = True,
        cleanup_label: str = "",
    ) -> Dict[str, Any]:
        cleanup_summary: Dict[str, Any] = {
            "label": cleanup_label,
            "device_connected": False,
            "desktop_ready": False,
            "app_data_cleared": False,
            "force_stopped_packages": [],
            "background_packages_cleaned": [],
            "remaining_foreground_package": None,
            "errors": [],
        }

        if cleanup_label:
            print(f"[cleanup] {cleanup_label}")

        if not self._check_device_with_retry():
            cleanup_summary["errors"].append("device is not connected")
            return cleanup_summary

        cleanup_summary["device_connected"] = True
        protected_packages = self._build_cleanup_protected_packages()
        target_package = str(self.package_name or "").strip()

        self._return_to_home_screen(retries=2)

        if target_package and self._force_stop_package(
            target_package,
            protected_packages=protected_packages,
            allow_target=True,
            quiet=True,
        ):
            cleanup_summary["force_stopped_packages"].append(target_package)

        if cleanup_background_apps:
            self._run_adb_command(["shell", "am", "kill-all"], timeout=20, quiet=True)
            self._run_adb_command(["shell", "cmd", "activity", "kill-all"], timeout=20, quiet=True)
            for package_name in self._collect_background_candidate_packages():
                if self._force_stop_package(
                    package_name,
                    protected_packages=protected_packages,
                    allow_target=False,
                    quiet=True,
                ):
                    cleanup_summary["background_packages_cleaned"].append(package_name)

        if clear_app_data and target_package:
            cleanup_summary["app_data_cleared"] = self._clear_package_data(target_package, quiet=True)

        if clear_logs:
            self._run_adb_command(["logcat", "-c"], timeout=15, quiet=True)

        self._return_to_home_screen(retries=3)
        foreground_package = self._get_foreground_package()
        if foreground_package and not self._is_protected_cleanup_package(
            foreground_package,
            protected_packages=protected_packages,
            allow_target=False,
        ):
            if self._force_stop_package(
                foreground_package,
                protected_packages=protected_packages,
                allow_target=False,
                quiet=True,
            ):
                cleanup_summary["background_packages_cleaned"].append(foreground_package)
            self._return_to_home_screen(retries=2)

        cleanup_summary["force_stopped_packages"] = self._merge_unique_text(cleanup_summary["force_stopped_packages"])
        cleanup_summary["background_packages_cleaned"] = self._merge_unique_text(
            cleanup_summary["background_packages_cleaned"]
        )
        cleanup_summary["remaining_foreground_package"] = self._get_foreground_package()
        cleanup_summary["desktop_ready"] = self._return_to_home_screen(retries=2)
        self.app_pid = None
        time.sleep(1)
        return cleanup_summary

    def cleanup_runtime_state(
        self,
        clear_app_data: bool = False,
        cleanup_background_apps: bool = False,
        clear_logs: bool = False,
    ) -> None:
        self.reset_analysis_environment(
            clear_app_data=clear_app_data,
            cleanup_background_apps=cleanup_background_apps,
            clear_logs=clear_logs,
            cleanup_label="worker cleanup",
        )

    def _get_foreground_package(self) -> Optional[str]:
        window_dump = self._run_adb_command(["shell", "dumpsys", "window", "windows"], timeout=20, quiet=True) or ""
        patterns = [
            r"mCurrentFocus=Window\{[^\n]*\s([A-Za-z0-9._]+)/(?:[A-Za-z0-9.$_]+)\}",
            r"mFocusedApp=.*ActivityRecord\{[^\n]*\s([A-Za-z0-9._]+)/",
        ]
        for pattern in patterns:
            match = re.search(pattern, window_dump)
            if match:
                return str(match.group(1)).strip()

        activity_dump = self._run_adb_command(["shell", "dumpsys", "activity", "activities"], timeout=20, quiet=True) or ""
        for pattern in [
            r"topResumedActivity=.*? ([A-Za-z0-9._]+)/",
            r"mResumedActivity:.*? ([A-Za-z0-9._]+)/",
        ]:
            match = re.search(pattern, activity_dump)
            if match:
                return str(match.group(1)).strip()
        return None

    def _is_target_foreground(self) -> bool:
        if not self.package_name:
            return False
        return self._get_foreground_package() == self.package_name

    def _is_system_dialog_package(self, package_name: Optional[str]) -> bool:
        return str(package_name or "").strip() in self.SYSTEM_DIALOG_PACKAGES

    def _is_controlled_foreground(self, allow_system_dialogs: bool = False) -> bool:
        foreground_package = self._get_foreground_package()
        if not foreground_package:
            return False
        if self.package_name and foreground_package == self.package_name:
            return True
        return allow_system_dialogs and self._is_system_dialog_package(foreground_package)

    def _should_keep_ui_node(self, package_name: str, include_system_dialogs: bool = False) -> bool:
        normalized = str(package_name or "").strip()
        if not normalized:
            return True
        if self.package_name and normalized == self.package_name:
            return True
        return include_system_dialogs and self._is_system_dialog_package(normalized)

    def _parse_bounds(self, bounds_text: str) -> Optional[Dict[str, int]]:
        match = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", str(bounds_text or "").strip())
        if not match:
            return None
        left, top, right, bottom = [int(value) for value in match.groups()]
        if right <= left or bottom <= top:
            return None
        return {
            "left": left,
            "top": top,
            "right": right,
            "bottom": bottom,
            "center_x": int((left + right) / 2),
            "center_y": int((top + bottom) / 2),
            "width": right - left,
            "height": bottom - top,
        }

    def _get_screen_size(self) -> Dict[str, int]:
        output = self._run_adb_command(["shell", "wm", "size"], timeout=10, quiet=True) or ""
        matches = re.findall(r"(\d+)x(\d+)", output)
        if matches:
            width, height = matches[-1]
            return {"width": max(int(width), 480), "height": max(int(height), 800)}
        return {"width": 1080, "height": 1920}

    def _dump_ui_snapshot(self, include_system_dialogs: bool = False) -> Dict[str, Any]:
        target_path = "/sdcard/appprivacydetector_ui.xml"
        dump_output = self._run_adb_command(["shell", "uiautomator", "dump", target_path], timeout=20, quiet=True)
        if dump_output is None:
            return {"nodes": [], "clickable_nodes": [], "safe_action_nodes": [], "texts": [], "signature": ""}

        xml_text = self._run_adb_command(["shell", "cat", target_path], timeout=20, quiet=True) or ""
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return {"nodes": [], "clickable_nodes": [], "safe_action_nodes": [], "texts": [], "signature": ""}

        nodes: List[Dict[str, Any]] = []
        clickable_nodes: List[Dict[str, Any]] = []
        safe_action_nodes: List[Dict[str, Any]] = []
        texts: List[str] = []

        for element in root.iter("node"):
            package_name = str(element.attrib.get("package", "")).strip()
            if not self._should_keep_ui_node(package_name, include_system_dialogs=include_system_dialogs):
                continue

            bounds = self._parse_bounds(element.attrib.get("bounds", ""))
            if not bounds:
                continue

            text = str(element.attrib.get("text", "")).strip()
            content_desc = str(element.attrib.get("content-desc", "")).strip()
            resource_id = str(element.attrib.get("resource-id", "")).strip()
            class_name = str(element.attrib.get("class", "")).strip()
            clickable = str(element.attrib.get("clickable", "")).lower() == "true"
            enabled = str(element.attrib.get("enabled", "")).lower() == "true"
            scrollable = str(element.attrib.get("scrollable", "")).lower() == "true"

            normalized_text = " ".join(part for part in [text, content_desc, resource_id] if part).strip()
            node = {
                "package": package_name,
                "text": text,
                "content_desc": content_desc,
                "resource_id": resource_id,
                "class_name": class_name,
                "clickable": clickable,
                "enabled": enabled,
                "scrollable": scrollable,
                "bounds": bounds,
                "normalized_text": normalized_text,
                "is_system_dialog": self._is_system_dialog_package(package_name),
            }
            nodes.append(node)
            if normalized_text:
                texts.append(normalized_text)
            if clickable and enabled and bounds["width"] >= 24 and bounds["height"] >= 24:
                clickable_nodes.append(node)
                if not self._is_negative_action_node(node) and (
                    self._is_permission_allow_node(node)
                    or self._is_general_positive_action_node(node)
                    or self._is_dismiss_action_node(node)
                ):
                    safe_action_nodes.append(node)

        signature_parts = []
        for node in nodes[:12]:
            label = node["text"] or node["content_desc"] or node["resource_id"]
            if label:
                signature_parts.append(label)

        return {
            "nodes": nodes,
            "clickable_nodes": clickable_nodes,
            "safe_action_nodes": safe_action_nodes,
            "texts": texts[:30],
            "signature": "|".join(signature_parts[:8]),
        }

    def _has_loading_marker(self, snapshot: Dict[str, Any]) -> bool:
        texts = snapshot.get("texts", []) or []
        lowered_texts = " ".join(str(item) for item in texts).lower()
        return any(keyword in lowered_texts for keyword in self.LOADING_KEYWORDS)

    def _detect_login_gate(self, snapshot: Optional[Dict[str, Any]] = None) -> bool:
        snapshot = snapshot or self._dump_ui_snapshot()
        texts = snapshot.get("texts", []) or []
        merged = " ".join(str(item) for item in texts)
        lowered = merged.lower()
        return any(keyword in merged for keyword in self.LOGIN_GATE_KEYWORDS) or any(
            keyword in lowered for keyword in ["login", "sign in", "sign-in", "手机号", "password", "wechat", "qq"]
        )

    def _is_blocked_interaction_node(self, node: Dict[str, Any]) -> bool:
        normalized_text = str(node.get("normalized_text") or "").strip().lower()
        return any(keyword.lower() in normalized_text for keyword in self.BLOCKED_INTERACTION_KEYWORDS)

    def _is_interaction_candidate(self, node: Dict[str, Any], screen: Optional[Dict[str, int]] = None) -> bool:
        bounds = node.get("bounds") or {}
        screen = screen or self._get_screen_size()
        center_y = int(bounds.get("center_y", 0))
        center_x = int(bounds.get("center_x", 0))
        width = int(bounds.get("width", 0))
        height = int(bounds.get("height", 0))
        if node.get("is_system_dialog"):
            return False
        if self._is_blocked_interaction_node(node):
            return False
        if width < 32 or height < 32:
            return False
        if center_y <= int(screen["height"] * 0.18) or center_y >= int(screen["height"] * 0.84):
            return False
        if center_x <= int(screen["width"] * 0.08) or center_x >= int(screen["width"] * 0.92):
            return False
        return True

    @staticmethod
    def _normalized_node_text(node: Dict[str, Any]) -> str:
        return str(node.get("normalized_text") or "").strip()

    def _is_negative_action_node(self, node: Dict[str, Any]) -> bool:
        normalized_text = self._normalized_node_text(node)
        lowered_text = normalized_text.lower()
        resource_id = str(node.get("resource_id") or "").strip().lower()
        if any(hint in resource_id for hint in self.PERMISSION_DENY_RESOURCE_HINTS):
            return True
        if any(keyword in normalized_text for keyword in self.NEGATIVE_ACTION_KEYWORDS):
            return True
        return any(keyword in lowered_text for keyword in ["deny", "disagree", "forbid", "cancel", "decline"])

    def _is_dismiss_action_node(self, node: Dict[str, Any]) -> bool:
        normalized_text = self._normalized_node_text(node)
        lowered_text = normalized_text.lower()
        if any(keyword in normalized_text for keyword in self.DISMISS_ACTION_KEYWORDS):
            return True
        return any(keyword in lowered_text for keyword in ["skip", "close", "later", "not now", "got it"])

    def _is_permission_allow_node(self, node: Dict[str, Any]) -> bool:
        normalized_text = self._normalized_node_text(node)
        lowered_text = normalized_text.lower()
        resource_id = str(node.get("resource_id") or "").strip().lower()
        if any(hint in resource_id for hint in self.PERMISSION_ALLOW_RESOURCE_HINTS):
            return True
        if any(keyword in normalized_text for keyword in self.SAFE_ACTION_KEYWORDS):
            return True
        return any(
            keyword in lowered_text
            for keyword in [
                "allow",
                "grant",
                "agree",
                "confirm",
                "continue",
                "ok",
                "while using",
                "only this time",
                "one time",
                "always allow",
            ]
        )

    def _permission_allow_rank(self, node: Dict[str, Any]) -> int:
        normalized_text = self._normalized_node_text(node)
        lowered_text = normalized_text.lower()
        resource_id = str(node.get("resource_id") or "").strip().lower()
        rank_rules = [
            ("permission_allow_always_button", 0),
            ("始终允许", 0),
            ("总是允许", 0),
            ("always allow", 0),
            ("permission_allow_foreground_only_button", 1),
            ("仅在使用中", 1),
            ("仅在使用期间", 1),
            ("使用期间", 1),
            ("while using", 1),
            ("permission_allow_one_time_button", 2),
            ("仅此一次", 2),
            ("本次允许", 2),
            ("only this time", 2),
            ("one time", 2),
            ("permission_allow_button", 3),
            ("permission_allow_selected_button", 3),
            ("允许", 3),
            ("同意", 3),
            ("确认", 3),
            ("继续", 3),
            ("grant", 3),
            ("allow", 3),
        ]
        for pattern, rank in rank_rules:
            if pattern in resource_id or pattern in normalized_text or pattern in lowered_text:
                return rank
        return 10

    def _is_general_positive_action_node(self, node: Dict[str, Any]) -> bool:
        if self._is_negative_action_node(node) or self._is_dismiss_action_node(node):
            return False
        normalized_text = self._normalized_node_text(node)
        lowered_text = normalized_text.lower()
        resource_id = str(node.get("resource_id") or "").strip().lower()
        if any(keyword in normalized_text for keyword in self.SAFE_ACTION_KEYWORDS):
            return True
        if resource_id.endswith(":id/button1") or resource_id.endswith("/button1"):
            return True
        return any(keyword in lowered_text for keyword in ["allow", "agree", "confirm", "continue", "next", "enter", "open", "start", "grant"])

    def _select_safe_action_candidate(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        clickable_nodes = snapshot.get("clickable_nodes", []) or []
        if not clickable_nodes:
            return None

        system_dialog_nodes = [node for node in clickable_nodes if node.get("is_system_dialog")]
        target_nodes = system_dialog_nodes if system_dialog_nodes else clickable_nodes

        permission_allow_nodes = [
            node
            for node in target_nodes
            if self._is_permission_allow_node(node) and not self._is_negative_action_node(node)
        ]
        if permission_allow_nodes:
            return sorted(
                permission_allow_nodes,
                key=lambda node: (
                    0 if node.get("is_system_dialog") else 1,
                    self._permission_allow_rank(node),
                    -int((node.get("bounds") or {}).get("center_x", 0)),
                    -int((node.get("bounds") or {}).get("center_y", 0)),
                ),
            )[0]

        general_positive_nodes = [
            node
            for node in target_nodes
            if self._is_general_positive_action_node(node)
        ]
        if general_positive_nodes:
            return sorted(
                general_positive_nodes,
                key=lambda node: (
                    0 if node.get("is_system_dialog") else 1,
                    -int((node.get("bounds") or {}).get("center_x", 0)),
                    -int((node.get("bounds") or {}).get("center_y", 0)),
                ),
            )[0]

        if system_dialog_nodes:
            return None

        dismiss_nodes = [
            node
            for node in target_nodes
            if self._is_dismiss_action_node(node) and not self._is_negative_action_node(node)
        ]
        if dismiss_nodes:
            return sorted(
                dismiss_nodes,
                key=lambda node: (
                    -int((node.get("bounds") or {}).get("center_y", 0)),
                    -int((node.get("bounds") or {}).get("center_x", 0)),
                ),
            )[0]
        return None

    def _get_interaction_candidates(self, snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        screen = self._get_screen_size()
        return [
            node
            for node in (snapshot.get("clickable_nodes", []) or [])
            if self._is_interaction_candidate(node, screen=screen)
        ]

    def _tap_absolute(
        self,
        x: int,
        y: int,
        settle_seconds: float = 1.0,
        allow_system_dialogs: bool = False,
    ) -> bool:
        if not self._is_controlled_foreground(allow_system_dialogs=allow_system_dialogs):
            return False
        self._run_adb_command(["shell", "input", "tap", str(int(x)), str(int(y))], timeout=10, quiet=True)
        time.sleep(max(0.1, float(settle_seconds)))
        return self._is_controlled_foreground(allow_system_dialogs=allow_system_dialogs)

    def _tap_node(
        self,
        node: Dict[str, Any],
        settle_seconds: float = 1.0,
        allow_system_dialogs: bool = False,
    ) -> bool:
        bounds = node.get("bounds") or {}
        return self._tap_absolute(
            bounds.get("center_x", 0),
            bounds.get("center_y", 0),
            settle_seconds=settle_seconds,
            allow_system_dialogs=allow_system_dialogs,
        )

    def _handle_safe_actions(self, max_actions: int = 3) -> int:
        if not self._is_controlled_foreground(allow_system_dialogs=True):
            return 0
        handled = 0
        for _ in range(max(1, int(max_actions))):
            snapshot = self._dump_ui_snapshot(include_system_dialogs=True)
            candidate = self._select_safe_action_candidate(snapshot)
            if not candidate:
                break
            if not self._tap_node(candidate, settle_seconds=0.8, allow_system_dialogs=True):
                break
            handled += 1
        return handled

    @staticmethod
    def _node_action_key(node: Dict[str, Any]) -> str:
        bounds = node.get("bounds") or {}
        return "|".join(
            [
                str(node.get("resource_id") or ""),
                str(node.get("text") or ""),
                str(node.get("content_desc") or ""),
                str(bounds.get("center_x", 0)),
                str(bounds.get("center_y", 0)),
            ]
        )

    def _swipe_screen(
        self,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        duration_ms: int = 320,
    ) -> bool:
        if not self._is_target_foreground():
            return False
        self._run_adb_command(
            [
                "shell",
                "input",
                "swipe",
                str(int(start_x)),
                str(int(start_y)),
                str(int(end_x)),
                str(int(end_y)),
                str(max(120, int(duration_ms))),
            ],
            timeout=10,
            quiet=True,
        )
        time.sleep(0.9)
        return self._is_target_foreground()

    def _run_guided_interaction_loop(
        self,
        duration_seconds: int = 8,
        allow_monkey_fallback: bool = False,
        monkey_event_count: int = 10,
        monkey_throttle_ms: int = 150,
    ) -> int:
        if not self.package_name:
            return 0

        loop_seconds = max(2, int(duration_seconds))
        deadline = time.time() + loop_seconds
        screen = self._get_screen_size()
        seen_targets = set()
        actions = 0
        round_index = 0

        while time.time() < deadline:
            if not self._is_controlled_foreground(allow_system_dialogs=True):
                if not self.start_app(force_launch=False):
                    time.sleep(0.8)
                    continue

            actions += self._handle_safe_actions(max_actions=2)
            snapshot = self._dump_ui_snapshot(include_system_dialogs=True)

            if self._has_loading_marker(snapshot) and not self._get_interaction_candidates(snapshot):
                self._keep_app_foreground(dwell_seconds=min(2, max(1, int(deadline - time.time()))))
                round_index += 1
                continue

            tapped_this_round = 0
            candidates = sorted(
                self._get_interaction_candidates(snapshot),
                key=lambda node: (
                    -int((node.get("bounds") or {}).get("center_y", 0)),
                    abs(int((node.get("bounds") or {}).get("center_x", 0)) - int(screen["width"] * 0.5)),
                ),
            )
            for node in candidates:
                if time.time() >= deadline:
                    break
                action_key = self._node_action_key(node)
                if action_key in seen_targets:
                    continue
                if self._tap_node(node, settle_seconds=0.8):
                    seen_targets.add(action_key)
                    actions += 1
                    tapped_this_round += 1
                    actions += self._handle_safe_actions(max_actions=1)
                if tapped_this_round >= 3:
                    break

            if time.time() >= deadline:
                break

            if self._is_target_foreground():
                if round_index % 2 == 0:
                    if self._swipe_screen(
                        int(screen["width"] * 0.50),
                        int(screen["height"] * 0.78),
                        int(screen["width"] * 0.50),
                        int(screen["height"] * 0.34),
                        duration_ms=360,
                    ):
                        actions += 1
                else:
                    if self._swipe_screen(
                        int(screen["width"] * 0.78),
                        int(screen["height"] * 0.56),
                        int(screen["width"] * 0.22),
                        int(screen["height"] * 0.56),
                        duration_ms=280,
                    ):
                        actions += 1
                actions += self._handle_safe_actions(max_actions=1)

            if (
                tapped_this_round == 0
                and allow_monkey_fallback
                and self._is_target_foreground()
                and not self._should_avoid_aggressive_navigation()
                and time.time() + 3 < deadline
            ):
                if self.run_monkey_burst(
                    event_count=max(6, int(monkey_event_count)),
                    throttle_ms=max(120, int(monkey_throttle_ms)),
                ):
                    actions += 1
                    actions += self._handle_safe_actions(max_actions=1)

            round_index += 1

        return actions

    def _is_snapshot_ready(self, snapshot: Dict[str, Any]) -> bool:
        nodes = snapshot.get("nodes", []) or []
        texts = snapshot.get("texts", []) or []
        interactive_nodes = self._get_interaction_candidates(snapshot)
        if len(nodes) < 4:
            return False
        if self._has_loading_marker(snapshot) and not interactive_nodes:
            return False
        return bool(interactive_nodes) or len(texts) >= 3

    def _should_avoid_aggressive_navigation(self, snapshot: Optional[Dict[str, Any]] = None) -> bool:
        snapshot = snapshot or self._dump_ui_snapshot()
        return self._detect_login_gate(snapshot) or self._has_loading_marker(snapshot)

    def _keep_app_foreground(self, dwell_seconds: int = 6) -> bool:
        if not self.package_name:
            return False
        deadline = time.time() + max(1, int(dwell_seconds))
        while time.time() < deadline:
            if not self._is_controlled_foreground(allow_system_dialogs=True):
                if not self.start_app(force_launch=False):
                    time.sleep(1)
                    continue
            self._handle_safe_actions(max_actions=2)
            time.sleep(1)
        return self._is_app_running()

    def _wait_for_app_ready(self, max_wait_seconds: int = 45) -> bool:
        if not self.package_name:
            return False
        wait_budget = self._step_budget(max_wait_seconds, minimum_seconds=3)
        if wait_budget <= 0:
            return self._is_app_running()
        start_time = time.time()
        while time.time() - start_time < wait_budget:
            foreground_package = self._get_foreground_package()
            if self._is_system_dialog_package(foreground_package):
                self._handle_safe_actions(max_actions=2)
                time.sleep(1.2)
                continue
            if foreground_package == self.package_name:
                self._handle_safe_actions(max_actions=2)
                snapshot = self._dump_ui_snapshot()
                if self._is_snapshot_ready(snapshot):
                    return True
            elif self._is_app_running():
                time.sleep(2)
                continue
            time.sleep(1.5)
        return self._is_app_running()

    def _launch_via_explicit_activity(self) -> bool:
        component_name = self._build_launch_component()
        if not component_name:
            return False
        output = self._run_adb_command(
            ["shell", "am", "start", "-S", "-W", "-n", component_name],
            timeout=35,
            quiet=True,
        )
        return output is not None

    def _launch_via_monkey(self) -> bool:
        if not self.package_name:
            return False
        output = self._run_adb_command(
            ["shell", "monkey", "-p", self.package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            timeout=30,
            quiet=True,
        )
        return output is not None

    def start_app(self, force_launch: bool = True) -> bool:
        if not self.package_name:
            return False
        self.last_launch_error = None
        if not force_launch and self._is_target_foreground() and self._wait_for_app_ready(max_wait_seconds=12):
            return True
        if force_launch:
            self._force_stop_app()

        launch_plan = [
            (self._launch_via_explicit_activity, 24 if force_launch else 12),
            (self._launch_via_monkey, 30 if force_launch else 16),
        ]
        if not self.main_activity:
            launch_plan = [(self._launch_via_monkey, 30 if force_launch else 16)]

        for launch_func, wait_window in launch_plan:
            if not launch_func():
                continue
            time.sleep(2.5)
            wait_budget = self._step_budget(wait_window, minimum_seconds=6)
            if wait_budget > 0 and self._wait_for_app_ready(max_wait_seconds=wait_budget):
                self._refresh_app_pid()
                self._handle_safe_actions(max_actions=3)
                return True

        self.last_launch_error = "app launch did not stabilize"
        return self._is_app_running()

    def _perform_basic_interactions(self) -> None:
        if not self._is_target_foreground():
            return
        interaction_window = self._step_budget(8, minimum_seconds=3, reserve_seconds=36 if self.frida_analyzer else 12)
        if interaction_window <= 0:
            self._handle_safe_actions(max_actions=2)
            return
        self._run_guided_interaction_loop(
            duration_seconds=interaction_window,
            allow_monkey_fallback=True,
            monkey_event_count=8,
            monkey_throttle_ms=140,
        )

    def simulate_user_interactions(self) -> bool:
        if not self.start_app(force_launch=False):
            if not self.start_app(force_launch=True):
                return False
        self._handle_safe_actions(max_actions=3)
        self._perform_basic_interactions()
        if self._detect_login_gate():
            print("[dynamic] login gate detected, keep app on foreground for extended probing")
            dwell_seconds = self._step_budget(8, minimum_seconds=3, reserve_seconds=28 if self.frida_analyzer else 8)
            if dwell_seconds > 0:
                self._keep_app_foreground(dwell_seconds=dwell_seconds)
        self._handle_safe_actions(max_actions=2)
        return True

    def run_monkey_burst(self, event_count: int = 80, throttle_ms: int = 180) -> bool:
        if not self.package_name:
            return False
        if self._detect_login_gate():
            print("[dynamic] login gate detected, skip monkey burst")
            self._keep_app_foreground(dwell_seconds=5)
            return False
        print(f"run monkey burst for {event_count} events")
        timeout = max(55, int((event_count * throttle_ms) / 1000) + 28)
        command = [
            "shell",
            "monkey",
            "-p",
            self.package_name,
            "--ignore-crashes",
            "--ignore-native-crashes",
            "--ignore-timeouts",
            "--ignore-security-exceptions",
            "--pct-touch",
            "55",
            "--pct-motion",
            "18",
            "--pct-nav",
            "12",
            "--pct-majornav",
            "3",
            "--pct-appswitch",
            "0",
            "--pct-anyevent",
            "0",
            "--pct-syskeys",
            "0",
            "--throttle",
            str(throttle_ms),
            "-v",
            str(event_count),
        ]
        output = self._run_adb_command(command, timeout=timeout, quiet=True)
        return output is not None

    def _warm_up_app_process(self) -> None:
        if not self.start_app(force_launch=False):
            self.start_app(force_launch=True)
        self._refresh_app_pid()
        self._handle_safe_actions(max_actions=2)
        self._perform_basic_interactions()

    def exercise_app_under_frida(self) -> bool:
        self._warm_up_app_process()
        if self._should_avoid_aggressive_navigation():
            dwell_seconds = self._step_budget(8, minimum_seconds=3, reserve_seconds=16)
            if dwell_seconds > 0:
                self._keep_app_foreground(dwell_seconds=dwell_seconds)
        else:
            interaction_window = self._step_budget(12, minimum_seconds=4, reserve_seconds=14)
            if interaction_window > 0:
                self._run_guided_interaction_loop(
                    duration_seconds=interaction_window,
                    allow_monkey_fallback=True,
                    monkey_event_count=12,
                    monkey_throttle_ms=150,
                )
        self._warm_up_app_process()
        return True

    def _exercise_cold_start_under_frida(self) -> bool:
        if not self.start_app(force_launch=True):
            return False
        self._handle_safe_actions(max_actions=3)
        primary_window = self._step_budget(8, minimum_seconds=4, reserve_seconds=14)
        if primary_window > 0:
            self._run_guided_interaction_loop(
                duration_seconds=primary_window,
                allow_monkey_fallback=False,
            )
        if self._should_avoid_aggressive_navigation():
            dwell_seconds = self._step_budget(5, minimum_seconds=2, reserve_seconds=10)
            if dwell_seconds > 0:
                self._keep_app_foreground(dwell_seconds=dwell_seconds)
        else:
            secondary_window = self._step_budget(6, minimum_seconds=3, reserve_seconds=8)
            if secondary_window > 0:
                self._run_guided_interaction_loop(
                    duration_seconds=secondary_window,
                    allow_monkey_fallback=True,
                    monkey_event_count=8,
                    monkey_throttle_ms=160,
                )
        return True

    def _exercise_recovery_under_frida(self) -> bool:
        if not self.start_app(force_launch=True):
            return False
        self._handle_safe_actions(max_actions=3)
        if self._should_avoid_aggressive_navigation():
            dwell_seconds = self._step_budget(6, minimum_seconds=2, reserve_seconds=8)
            if dwell_seconds > 0:
                self._keep_app_foreground(dwell_seconds=dwell_seconds)
        else:
            recovery_window = self._step_budget(9, minimum_seconds=4, reserve_seconds=8)
            if recovery_window > 0:
                self._run_guided_interaction_loop(
                    duration_seconds=recovery_window,
                    allow_monkey_fallback=True,
                    monkey_event_count=10,
                    monkey_throttle_ms=150,
                )
        self._perform_basic_interactions()
        return True

    def _exercise_runtime_probe(self) -> bool:
        if not self.start_app(force_launch=False):
            return False
        self._handle_safe_actions(max_actions=2)
        primary_window = self._step_budget(8, minimum_seconds=4, reserve_seconds=12 if self.frida_analyzer else 4)
        if primary_window > 0:
            self._run_guided_interaction_loop(
                duration_seconds=primary_window,
                allow_monkey_fallback=True,
                monkey_event_count=8,
                monkey_throttle_ms=150,
            )
        if self._should_avoid_aggressive_navigation():
            dwell_seconds = self._step_budget(4, minimum_seconds=2, reserve_seconds=8)
            if dwell_seconds > 0:
                self._keep_app_foreground(dwell_seconds=dwell_seconds)
        else:
            secondary_window = self._step_budget(5, minimum_seconds=3, reserve_seconds=6)
            if secondary_window > 0:
                self._run_guided_interaction_loop(
                    duration_seconds=secondary_window,
                    allow_monkey_fallback=True,
                    monkey_event_count=6,
                    monkey_throttle_ms=140,
                )
        return True

    def monitor_sensitive_api_calls(
        self,
        duration: int = 60,
        exercise_callback: Optional[Any] = None,
    ) -> Dict[str, Dict[str, Any]]:
        print(f"monitoring logcat sensitive APIs for {duration}s")
        self._run_adb_command(["logcat", "-c"], quiet=True)
        detected_apis: Dict[str, Dict[str, Any]] = {}
        probe_thread: Optional[threading.Thread] = None
        patterns = {
            "getDeviceId": ["getdeviceid", "getimei", "imei", "meid", "getserial"],
            "getSubscriberId": ["getsubscriberid", "imsi", "simserial", "line1number"],
            "getMacAddress": ["getmacaddress", "bluetoothadapter.getaddress", "wifiinfo"],
            "getAndroidId": ["android_id", "settings$secure", "settings secure"],
            "getOaid": ["oaid", "aaid", "vaid", "udid", "idprovider", "deviceidservice"],
            "getLocation": ["locationmanager", "requestlocationupdates", "getlastknownlocation", "fusedlocation", "getcurrentlocation"],
            "openCamera": ["camera.open", "cameramanager", "opencamera", "imagecapture"],
            "startRecording": ["mediarecorder", "audiorecord", "startrecording", "speechrecognizer"],
            "readContacts": ["contactscontract", "content://com.android.contacts", "content://contacts"],
            "readSms": ["smsmanager", "content://sms", "content://mms"],
            "readCallLog": ["content://call_log", "calllog"],
            "accessStorage": ["externalstorage", "mediastore", "content://media", "openfileinput", "openfileoutput", "downloads"],
            "accessCalendar": ["calendarcontract", "content://com.android.calendar", "content://calendar"],
            "getInstalledPackages": ["getinstalledpackages", "getinstalledapplications", "queryintentactivities", "queryintentservices", "queryintentreceivers"],
            "getAccount": ["accountmanager", "getaccounts", "getaccountsbytype"],
            "readClipboard": ["clipboardmanager", "getprimaryclip", "setprimaryclip"],
            "sendSms": ["sendtextmessage", "sendmultiparttextmessage", "senddatamessage"],
        }
        noisy_patterns = ["runtimeinit$methodandargscaller.run", "system.err", "zygoteinit"]

        try:
            if exercise_callback is not None:
                probe_thread = threading.Thread(target=exercise_callback, daemon=True)
                probe_thread.start()
            with tqdm(total=duration, desc="monitor sensitive APIs", unit="s") as progress:
                for _ in range(max(1, int(duration))):
                    time.sleep(1)
                    progress.update(1)
        finally:
            if probe_thread is not None and probe_thread.is_alive():
                probe_thread.join(timeout=5)

        dump_command = ["logcat", "-d"]
        active_pid = self._refresh_app_pid()
        if active_pid:
            dump_command.extend(["--pid", str(active_pid)])
        log_dump = self._run_adb_command(dump_command, timeout=20, quiet=True) or ""

        for line in log_dump.splitlines():
            normalized_line = str(line or "").strip()
            lower_line = normalized_line.lower()
            if not normalized_line or any(pattern in lower_line for pattern in noisy_patterns):
                continue
            for api, api_patterns in patterns.items():
                if not any(pattern in lower_line for pattern in api_patterns):
                    continue
                entry = detected_apis.setdefault(
                    api,
                    {"description": self.sensitive_apis.get(api, api), "count": 0, "logs": []},
                )
                entry["count"] += 1
                if normalized_line not in entry["logs"] and len(entry["logs"]) < 20:
                    entry["logs"].append(normalized_line)
                self.monitoring_logs.append(normalized_line)
                break

        return detected_apis

    def _merge_sensitive_api_calls(
        self,
        base_data: Optional[Dict[str, Dict[str, Any]]],
        extra_data: Optional[Dict[str, Dict[str, Any]]],
    ) -> Dict[str, Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for source in [base_data or {}, extra_data or {}]:
            for api_key, payload in source.items():
                target = merged.setdefault(
                    api_key,
                    {"description": payload.get("description", self.sensitive_apis.get(api_key, api_key)), "count": 0, "logs": []},
                )
                target["count"] += int(payload.get("count", 0))
                for log_line in payload.get("logs", []):
                    if log_line not in target["logs"] and len(target["logs"]) < 30:
                        target["logs"].append(log_line)
        return merged

    def _extract_frida_sensitive_api_calls(self, frida_analysis: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        if not frida_analysis:
            return {}
        summary = frida_analysis.get("summary", {}) or {}
        aggregated_calls = summary.get("aggregated_calls", []) or []
        signal_counts = summary.get("signal_counts", {}) or {}
        extracted: Dict[str, Dict[str, Any]] = {}
        for item in aggregated_calls:
            signal_key = item.get("signal_key")
            if not signal_key:
                continue
            extracted[signal_key] = {
                "description": item.get("description", self.sensitive_apis.get(signal_key, signal_key)),
                "count": int(item.get("count", signal_counts.get(signal_key, 0))),
                "logs": item.get("sample_apis", [])[:10],
            }
        for signal_key, count in signal_counts.items():
            extracted.setdefault(
                signal_key,
                {"description": self.sensitive_apis.get(signal_key, signal_key), "count": int(count), "logs": []},
            )
        return extracted

    def get_network_traffic(self) -> List[str]:
        output = self._run_adb_command(["shell", "netstat", "-tunap"], timeout=20)
        if not output:
            return []
        connections = []
        for line in output.splitlines():
            if self.package_name and self.package_name in line:
                connections.append(line.strip())
        return connections

    def get_battery_usage(self) -> Optional[str]:
        return self._run_adb_command(["shell", "dumpsys", "battery"], timeout=20)

    def get_memory_usage(self) -> Optional[str]:
        if not self.package_name:
            return None
        return self._run_adb_command(["shell", "dumpsys", "meminfo", self.package_name], timeout=20)

    def get_cpu_usage(self) -> Optional[str]:
        pid = self.app_pid or (self._run_adb_command(["shell", "pidof", self.package_name], timeout=10) if self.package_name else None)
        if not pid:
            return None
        return self._run_adb_command(["shell", "top", "-n", "1", "-p", str(pid).split()[0]], timeout=20)

    def get_app_info(self) -> Optional[Dict[str, str]]:
        if not self.package_name:
            return None
        app_info: Dict[str, str] = {}
        package_info = self._run_adb_command(["shell", "dumpsys", "package", self.package_name], timeout=30)
        if package_info:
            app_info["package_info"] = package_info
        return app_info or None

    def get_app_permissions(self) -> Optional[List[str]]:
        if not self.package_name:
            return None
        output = self._run_adb_command(["shell", "dumpsys", "package", self.package_name], timeout=30)
        if not output:
            return None
        permissions = []
        capture = False
        for line in output.splitlines():
            stripped = line.strip()
            if stripped.startswith("requested permissions:"):
                capture = True
                continue
            if capture:
                if not stripped or stripped.endswith(":"):
                    break
                permissions.append(stripped)
        return permissions or None

    def _is_low_coverage_frida(self, frida_summary: Dict[str, Any]) -> bool:
        total_api_calls = int(frida_summary.get("total_api_calls") or 0)
        total_signals = int(frida_summary.get("total_hooked_signals") or 0)
        if total_api_calls < self.low_coverage_api_threshold:
            return True
        if total_signals < 2:
            return True
        return False

    def _manual_guided_probe(self) -> bool:
        probe_window = self._step_budget(self.manual_probe_seconds, minimum_seconds=0, reserve_seconds=2)
        if probe_window <= 0:
            return True

        print(
            f"[Frida][Manual] low coverage detected, manual interaction window: {probe_window}s"
        )
        print("[Frida][Manual] please grant permissions / login / navigate sensitive pages in emulator now")

        started_at = time.time()
        last_reported = -1
        while time.time() - started_at < probe_window:
            if not self._is_controlled_foreground(allow_system_dialogs=True):
                self.start_app(force_launch=False)
            self._handle_safe_actions(max_actions=2)
            snapshot = self._dump_ui_snapshot(include_system_dialogs=True)
            if self._detect_login_gate(snapshot):
                print("[Frida][Manual] login page detected, complete login or SMS verification now")
            remaining = max(0, probe_window - int(time.time() - started_at))
            if remaining != last_reported and (remaining % 10 == 0 or remaining <= 5):
                print(f"[Frida][Manual] remaining: {remaining}s")
                last_reported = remaining
            time.sleep(1)

        print("[Frida][Manual] manual interaction window finished, run a short monkey burst")
        self.run_monkey_burst(event_count=30, throttle_ms=150)
        return True

    @staticmethod
    def _merge_unique_text(items: List[Any]) -> List[str]:
        merged: List[str] = []
        seen = set()
        for item in items:
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            merged.append(text)
        return merged

    def _classify_frida_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        results = payload.get("results", {}) or {}
        summary = payload.get("summary", {}) or {}

        status_messages = self._merge_unique_text(
            list(results.get("status_messages", []) or []) + list(summary.get("status_messages", []) or [])
        )
        error_messages = self._merge_unique_text(
            list(results.get("errors", []) or []) + list(summary.get("error_messages", []) or [])
        )
        detached_events = self._merge_unique_text(
            list(results.get("detached_events", []) or []) + list(summary.get("detached_events", []) or [])
        )
        issue_messages = self._merge_unique_text(error_messages + detached_events)

        status_blob = "\n".join(str(item) for item in status_messages).lower()
        issue_blob = "\n".join(str(item) for item in issue_messages).lower()

        total_api_calls = int(summary.get("total_api_calls") or len(results.get("call_logs", []) or []))
        java_bridge_ready = bool(summary.get("java_bridge_ready")) or "java bridge ready" in status_blob
        java_hook_ready = bool(summary.get("java_hook_ready")) or "sensitive api hooks ready" in status_blob
        process_terminated = bool(summary.get("process_terminated")) or "process-terminated" in issue_blob
        session_detached = bool(summary.get("session_detached")) or "session detached:" in issue_blob

        warning_messages: List[str] = []
        hard_errors: List[str] = []
        for message in error_messages:
            lowered = str(message).lower()
            if java_hook_ready and "session detached:" in lowered:
                warning_messages.append(message)
                continue
            hard_errors.append(message)

        if java_hook_ready and session_detached and not warning_messages:
            if detached_events:
                warning_messages.append(detached_events[0])
            else:
                warning_messages.append("session detached: reason=unknown")

        if total_api_calls > 0:
            state = "captured"
        elif java_hook_ready and session_detached:
            state = "runtime_interrupted"
        elif java_hook_ready:
            state = "ready_no_hits"
        elif hard_errors or payload.get("error"):
            state = "startup_failed"
        elif java_bridge_ready:
            state = "bridge_ready_only"
        else:
            state = "startup_incomplete"

        results["status_messages"] = status_messages
        results["errors"] = hard_errors
        if detached_events:
            results["detached_events"] = detached_events
        if warning_messages:
            results["warnings"] = warning_messages

        summary["status_messages"] = status_messages[:30]
        summary["error_messages"] = hard_errors[:30]
        summary["detached_events"] = detached_events[:10]
        summary["warning_messages"] = warning_messages[:30]
        summary["java_bridge_ready"] = java_bridge_ready
        summary["java_hook_ready"] = java_hook_ready
        summary["process_terminated"] = process_terminated
        summary["session_detached"] = session_detached

        payload["results"] = results
        payload["summary"] = summary
        payload["state"] = state

        if state == "runtime_interrupted":
            payload["warning"] = "Java Hook 已就绪，但目标进程在运行中退出"
            payload.pop("error", None)
        elif state == "ready_no_hits":
            payload["warning"] = "Java Hook 已就绪，但当前探测窗口未捕获到敏感 API 调用"
            payload.pop("error", None)
        elif state == "captured":
            payload.pop("error", None)
            if session_detached and warning_messages:
                payload["warning"] = warning_messages[0]
            else:
                payload.pop("warning", None)
        else:
            payload.pop("warning", None)
            if not payload.get("error") and hard_errors:
                payload["error"] = hard_errors[0]

        return payload

    def _aggregate_frida_call_logs(self, call_logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        grouped: Dict[str, Dict[str, Any]] = {}
        for entry in call_logs:
            signal_key = str(entry.get("signal_key") or entry.get("api") or "unknown")
            api_name = str(entry.get("api") or "")
            category = str(entry.get("category") or "other")
            description = str(entry.get("description") or signal_key)

            group = grouped.setdefault(
                signal_key,
                {
                    "signal_key": signal_key,
                    "category": category,
                    "description": description,
                    "count": 0,
                    "sample_apis": [],
                },
            )
            group["count"] += 1
            if api_name and api_name not in group["sample_apis"]:
                group["sample_apis"].append(api_name)

        return sorted(grouped.values(), key=lambda item: (-item["count"], item["signal_key"]))

    def _merge_frida_payload(
        self,
        first_payload: Dict[str, Any],
        second_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        first_results = first_payload.get("results", {}) or {}
        second_results = second_payload.get("results", {}) or {}
        first_summary = first_payload.get("summary", {}) or {}
        second_summary = second_payload.get("summary", {}) or {}

        call_logs = list(first_results.get("call_logs", []) or []) + list(second_results.get("call_logs", []) or [])
        hooked_apis = self._merge_unique_text(
            list(first_results.get("hooked_apis", []) or []) + list(second_results.get("hooked_apis", []) or [])
        )
        status_messages = self._merge_unique_text(
            list(first_results.get("status_messages", []) or []) + list(second_results.get("status_messages", []) or [])
        )
        errors = self._merge_unique_text(
            list(first_results.get("errors", []) or []) + list(second_results.get("errors", []) or [])
        )

        signal_counts: Dict[str, int] = {}
        for source in [first_results.get("signal_counts", {}) or {}, second_results.get("signal_counts", {}) or {}]:
            for key, value in source.items():
                signal_counts[str(key)] = signal_counts.get(str(key), 0) + int(value or 0)

        category_counts: Dict[str, int] = {}
        for source in [first_results.get("category_counts", {}) or {}, second_results.get("category_counts", {}) or {}]:
            for key, value in source.items():
                category_counts[str(key)] = category_counts.get(str(key), 0) + int(value or 0)

        detached_events = self._merge_unique_text(
            list(first_results.get("detached_events", []) or [])
            + list(second_results.get("detached_events", []) or [])
            + list(first_summary.get("detached_events", []) or [])
            + list(second_summary.get("detached_events", []) or [])
        )

        aggregated_calls = self._aggregate_frida_call_logs(call_logs)
        merged_duration = round(
            float(first_results.get("duration") or first_summary.get("duration") or 0.0)
            + float(second_results.get("duration") or second_summary.get("duration") or 0.0),
            3,
        )

        merged_results = {
            "hooked_apis": hooked_apis,
            "call_logs": call_logs,
            "duration": merged_duration,
            "errors": errors,
            "signal_counts": signal_counts,
            "category_counts": category_counts,
            "aggregated_calls": aggregated_calls,
            "status_messages": status_messages,
            "detached_events": detached_events,
        }
        merged_summary = {
            "total_hooked_apis": len(hooked_apis),
            "total_api_calls": len(call_logs),
            "total_hooked_signals": len(signal_counts),
            "total_categories": len(category_counts),
            "duration": merged_duration,
            "errors": len(errors),
            "hooked_apis": hooked_apis,
            "signal_counts": signal_counts,
            "category_counts": category_counts,
            "aggregated_calls": aggregated_calls[:30],
            "status_messages": status_messages[:30],
            "error_messages": errors[:30],
            "detached_events": detached_events[:10],
            "java_bridge_ready": any("java bridge ready" in item.lower() for item in status_messages),
            "java_hook_ready": any("sensitive api hooks ready" in item.lower() for item in status_messages),
            "process_terminated": any("process-terminated" in item.lower() for item in errors + detached_events),
        }
        merged_payload: Dict[str, Any] = {
            "results": merged_results,
            "summary": merged_summary,
            "adaptive_probe": {
                "enabled": True,
                "manual_probe_seconds": self.manual_probe_seconds,
                "low_coverage_api_threshold": self.low_coverage_api_threshold,
                "pass_count": 2,
            },
        }
        if errors and not merged_summary["total_api_calls"]:
            merged_payload["error"] = errors[0]
        return self._classify_frida_payload(merged_payload)

    def _run_frida_pass(
        self,
        label: str,
        duration: int,
        probe_callback: Optional[Any],
        spawn_first: bool,
    ) -> Dict[str, Any]:
        last_payload: Dict[str, Any] = {
            "results": {},
            "summary": {},
            "pass_label": label,
        }
        for attempt_index in range(2):
            if spawn_first:
                self._force_stop_app()
                time.sleep(2)
            else:
                self._warm_up_app_process()
                if not self._get_preferred_app_pids():
                    print(f"[Frida] {label} pass detected no stable app pid, relaunch before attach")
                    self.start_app(force_launch=True)
                    self._refresh_app_pid()
                time.sleep(1)

            pass_results = self.frida_analyzer.perform_frida_analysis(
                duration=max(15, int(duration)),
                probe_callback=probe_callback,
                spawn_first=spawn_first,
            )
            pass_summary = self.frida_analyzer.get_frida_summary()
            payload: Dict[str, Any] = {
                "results": pass_results,
                "summary": pass_summary,
                "pass_label": label,
            }
            if pass_results.get("error"):
                payload["error"] = pass_results["error"]
            elif pass_summary.get("error_messages") and not pass_summary.get("total_api_calls"):
                payload["error"] = pass_summary["error_messages"][0]
            payload = self._classify_frida_payload(payload)
            last_payload = payload

            detached_after_ready = payload.get("state") == "runtime_interrupted"
            if (
                not detached_after_ready
                or attempt_index >= 1
                or not self._has_analysis_budget(minimum_seconds=max(8, int(duration / 2)), reserve_seconds=4)
            ):
                return payload

            print(f"[Frida] {label} pass detached after hooks were ready, retry same pass once")
            self.cleanup_runtime_state()
            time.sleep(2)

        return last_payload

    def _perform_frida_analysis(self) -> Dict[str, Any]:
        print("start Frida runtime analysis")
        if not self.package_name:
            return {"error": "package name is unknown"}
        if not self.frida_analyzer:
            return {"error": "Frida module is unavailable"}
        try:
            remaining_budget = self._remaining_analysis_budget()
            compact_mode = remaining_budget is not None and remaining_budget <= 64

            executed_labels: List[str] = []
            cold_duration = self._step_budget(14 if compact_mode else 18, minimum_seconds=10, reserve_seconds=24)
            warm_duration = self._step_budget(18 if compact_mode else 22, minimum_seconds=12, reserve_seconds=12)

            cold_start_payload: Optional[Dict[str, Any]] = None
            if cold_duration > 0:
                cold_start_payload = self._run_frida_pass(
                    label="cold_start",
                    duration=cold_duration,
                    probe_callback=self._exercise_cold_start_under_frida,
                    spawn_first=True,
                )
                executed_labels.append("cold_start")

            warm_interaction_payload: Optional[Dict[str, Any]] = None
            if warm_duration > 0:
                warm_interaction_payload = self._run_frida_pass(
                    label="warm_interaction",
                    duration=warm_duration,
                    probe_callback=self.exercise_app_under_frida,
                    spawn_first=False,
                )
                executed_labels.append("warm_interaction")

            if cold_start_payload and warm_interaction_payload:
                merged_payload = self._merge_frida_payload(cold_start_payload, warm_interaction_payload)
            elif warm_interaction_payload:
                merged_payload = warm_interaction_payload
            elif cold_start_payload:
                merged_payload = cold_start_payload
            else:
                return {"error": "analysis budget exhausted before Frida probe"}

            merged_payload["adaptive_probe"] = {
                "enabled": True,
                "manual_probe_seconds": self.manual_probe_seconds,
                "low_coverage_api_threshold": self.low_coverage_api_threshold,
                "pass_count": len(executed_labels),
                "pass_labels": executed_labels[:],
                "budget_mode": "compact" if compact_mode else "standard",
                "pass_durations": {
                    "cold_start": cold_duration,
                    "warm_interaction": warm_duration,
                },
                "triggered_manual_probe": False,
                "triggered_recovery_probe": False,
            }

            if self._is_low_coverage_frida(merged_payload.get("summary", {})):
                recovery_duration = self._step_budget(12 if compact_mode else 16, minimum_seconds=10, reserve_seconds=6)
            else:
                recovery_duration = 0

            if recovery_duration > 0 and self._is_low_coverage_frida(merged_payload.get("summary", {})):
                print("[Frida] low coverage detected, starting recovery spawn pass")
                recovery_payload = self._run_frida_pass(
                    label="recovery_spawn",
                    duration=recovery_duration,
                    probe_callback=self._exercise_recovery_under_frida,
                    spawn_first=True,
                )
                merged_payload = self._merge_frida_payload(merged_payload, recovery_payload)
                executed_labels.append("recovery_spawn")
                merged_payload["adaptive_probe"] = {
                    "enabled": True,
                    "manual_probe_seconds": self.manual_probe_seconds,
                    "low_coverage_api_threshold": self.low_coverage_api_threshold,
                    "pass_count": len(executed_labels),
                    "pass_labels": executed_labels[:],
                    "budget_mode": "compact" if compact_mode else "standard",
                    "pass_durations": {
                        "cold_start": cold_duration,
                        "warm_interaction": warm_duration,
                        "recovery_spawn": recovery_duration,
                    },
                    "triggered_manual_probe": False,
                    "triggered_recovery_probe": True,
                }

            should_run_manual_probe = (
                self.manual_probe_seconds > 0
                and self._is_low_coverage_frida(merged_payload.get("summary", {}))
                and self._has_analysis_budget(minimum_seconds=24, reserve_seconds=4)
            )
            if should_run_manual_probe:
                manual_duration = self._step_budget(
                    max(24, self.manual_probe_seconds + 8),
                    minimum_seconds=20,
                    reserve_seconds=4,
                )
                if manual_duration <= 0:
                    return merged_payload
                print("[Frida] low coverage persists, starting manual-guided pass")
                manual_payload = self._run_frida_pass(
                    label="manual_guided",
                    duration=manual_duration,
                    probe_callback=self._manual_guided_probe,
                    spawn_first=False,
                )
                merged_payload = self._merge_frida_payload(merged_payload, manual_payload)
                executed_labels.append("manual_guided")
                merged_payload["adaptive_probe"] = {
                    "enabled": True,
                    "manual_probe_seconds": self.manual_probe_seconds,
                    "low_coverage_api_threshold": self.low_coverage_api_threshold,
                    "pass_count": len(executed_labels),
                    "pass_labels": executed_labels[:],
                    "budget_mode": "compact" if compact_mode else "standard",
                    "pass_durations": {
                        "cold_start": cold_duration,
                        "warm_interaction": warm_duration,
                        "recovery_spawn": recovery_duration,
                        "manual_guided": manual_duration,
                    },
                    "triggered_manual_probe": True,
                    "triggered_recovery_probe": "recovery_spawn" in executed_labels,
                }
            return merged_payload
        except Exception as error:
            return {"error": str(error)}

    def perform_dynamic_analysis(self) -> Dict[str, Any]:
        print("=" * 60)
        print("start dynamic analysis")
        print("=" * 60)
        self._activate_analysis_budget()

        analysis_result: Dict[str, Any] = {
            "device_connected": False,
            "apk_installed": False,
            "app_started": False,
            "user_interactions": False,
            "runtime_probe_api_calls": {},
            "sensitive_api_calls": {},
            "frida_sensitive_api_calls": {},
            "frida_analysis": {},
            "network_traffic": [],
            "battery_usage": None,
            "memory_usage": None,
            "cpu_usage": None,
            "app_info": None,
            "app_permissions": None,
            "errors": [],
        }
        runtime_probe_duration = self._step_budget(14, minimum_seconds=8, reserve_seconds=26 if self.frida_analyzer else 10)

        steps = [
            ("check_device", self._check_device_with_retry),
            ("install_apk", self.install_apk),
            ("start_app", self.start_app),
            ("simulate_user_interactions", self.simulate_user_interactions),
            ("monitor_sensitive_api_calls", lambda: self.monitor_sensitive_api_calls(runtime_probe_duration, exercise_callback=self._exercise_runtime_probe)),
            ("perform_frida_analysis", self._perform_frida_analysis),
            ("get_network_traffic", self.get_network_traffic),
            ("get_battery_usage", self.get_battery_usage),
            ("get_memory_usage", self.get_memory_usage),
            ("get_cpu_usage", self.get_cpu_usage),
            ("get_app_info", self.get_app_info),
            ("get_app_permissions", self.get_app_permissions),
        ]

        for step_name, step_func in tqdm(steps, desc="dynamic analysis", unit="step"):
            try:
                if step_name == "monitor_sensitive_api_calls" and runtime_probe_duration <= 0:
                    print("[dynamic] skip runtime probe: analysis budget is low")
                    continue
                if step_name == "perform_frida_analysis" and not self._has_analysis_budget(minimum_seconds=12, reserve_seconds=6):
                    print("[dynamic] skip Frida analysis: analysis budget is exhausted")
                    analysis_result["frida_analysis"] = {"error": "analysis budget exhausted before Frida probe"}
                    continue
                if step_name in {"get_network_traffic", "get_battery_usage", "get_memory_usage", "get_cpu_usage"} and not self._has_analysis_budget(minimum_seconds=3):
                    print(f"[dynamic] skip {step_name}: analysis budget is exhausted")
                    continue
                if step_name == "check_device":
                    if not step_func():
                        analysis_result["errors"].append("device is not connected")
                        break
                    analysis_result["device_connected"] = True
                elif step_name == "install_apk":
                    if not step_func():
                        analysis_result["errors"].append("apk install failed")
                        break
                    analysis_result["apk_installed"] = True
                elif step_name == "start_app":
                    if not step_func():
                        analysis_result["errors"].append("app start failed")
                        break
                    analysis_result["app_started"] = True
                elif step_name == "simulate_user_interactions":
                    if not step_func():
                        analysis_result["errors"].append("user interaction simulation failed")
                    analysis_result["user_interactions"] = True
                elif step_name == "monitor_sensitive_api_calls":
                    analysis_result["runtime_probe_api_calls"] = step_func()
                    analysis_result["sensitive_api_calls"] = self._merge_sensitive_api_calls(
                        analysis_result.get("runtime_probe_api_calls"),
                        None,
                    )
                elif step_name == "perform_frida_analysis":
                    analysis_result["frida_analysis"] = step_func()
                    frida_state = str(analysis_result["frida_analysis"].get("state") or "").strip().lower()
                    if analysis_result["frida_analysis"].get("error") and frida_state in {
                        "startup_failed",
                        "startup_incomplete",
                        "bridge_ready_only",
                    }:
                        analysis_result["errors"].append(
                            f"frida probe issue: {analysis_result['frida_analysis']['error']}"
                        )
                    frida_sensitive_calls = self._extract_frida_sensitive_api_calls(analysis_result.get("frida_analysis"))
                    analysis_result["frida_sensitive_api_calls"] = frida_sensitive_calls
                    analysis_result["sensitive_api_calls"] = self._merge_sensitive_api_calls(
                        analysis_result.get("runtime_probe_api_calls"),
                        frida_sensitive_calls,
                    )
                elif step_name == "get_network_traffic":
                    analysis_result["network_traffic"] = step_func()
                elif step_name == "get_battery_usage":
                    analysis_result["battery_usage"] = step_func()
                elif step_name == "get_memory_usage":
                    analysis_result["memory_usage"] = step_func()
                elif step_name == "get_cpu_usage":
                    analysis_result["cpu_usage"] = step_func()
                elif step_name == "get_app_info":
                    analysis_result["app_info"] = step_func()
                elif step_name == "get_app_permissions":
                    analysis_result["app_permissions"] = step_func()
            except Exception as error:
                print(f"step {step_name} failed: {error}")
                analysis_result["errors"].append(f"{step_name} failed: {error}")

        print("=" * 60)
        print("dynamic analysis finished")
        print("=" * 60)
        return analysis_result

    def save_result(self, output_file: str) -> Dict[str, Any]:
        result = self.perform_dynamic_analysis()
        with open(output_file, "w", encoding="utf-8") as output_handle:
            json.dump(result, output_handle, ensure_ascii=False, indent=2)
        print(f"dynamic analysis result saved to: {output_file}")
        return result


def _dynamic_analysis_worker(
    apk_path: str,
    results_dir: str,
    result_file: str,
    status_file: str,
    manual_probe_seconds: int,
    low_coverage_api_threshold: int,
    analysis_timeout_budget_seconds: int,
) -> None:
    status_payload = {"success": False, "error": ""}
    analyzer: Optional[DynamicAnalyzer] = None
    try:
        analyzer = DynamicAnalyzer(
            apk_path,
            results_dir,
            manual_probe_seconds=manual_probe_seconds,
            low_coverage_api_threshold=low_coverage_api_threshold,
            analysis_timeout_budget_seconds=analysis_timeout_budget_seconds,
        )
        analyzer.save_result(result_file)
        status_payload["success"] = True
    except Exception as error:
        status_payload["error"] = f"{type(error).__name__}: {error}"
    finally:
        if analyzer is not None:
            try:
                analyzer.cleanup_runtime_state()
            except Exception:
                pass
        with open(status_file, "w", encoding="utf-8") as output_handle:
            json.dump(status_payload, output_handle, ensure_ascii=False, indent=2)


class DynamicBatchAnalyzer:
    def __init__(
        self,
        samples_dir: str,
        results_dir: str = "results",
        per_apk_timeout: int = 300,
        manual_probe_seconds: int = 0,
        low_coverage_api_threshold: int = 4,
        manual_probe_apk_allowlist: Optional[List[str]] = None,
        clear_app_data_after_analysis: bool = False,
    ):
        self.samples_dir = samples_dir
        self.results_dir = results_dir
        self.per_apk_timeout = max(120, int(per_apk_timeout))
        self.internal_timeout_budget = max(
            75,
            self.per_apk_timeout - max(18, min(30, int(self.per_apk_timeout / 6))),
        )
        self.manual_probe_seconds = max(0, int(manual_probe_seconds))
        self.low_coverage_api_threshold = max(1, int(low_coverage_api_threshold))
        self.clear_app_data_after_analysis = bool(clear_app_data_after_analysis)
        self.manual_probe_apk_allowlist = {
            str(item).strip().lower()
            for item in (manual_probe_apk_allowlist or [])
            if str(item).strip()
        }
        os.makedirs(results_dir, exist_ok=True)

    def _cleanup_analysis_environment(
        self,
        apk_file: str,
        apk_path: str,
        clear_app_data: bool,
        phase: str,
    ) -> None:
        cleanup_analyzer: Optional[DynamicAnalyzer] = None
        try:
            cleanup_analyzer = DynamicAnalyzer(
                apk_path,
                self.results_dir,
                manual_probe_seconds=0,
                low_coverage_api_threshold=self.low_coverage_api_threshold,
            )
            cleanup_result = cleanup_analyzer.reset_analysis_environment(
                clear_app_data=clear_app_data,
                cleanup_background_apps=True,
                clear_logs=True,
                cleanup_label=f"{phase}: {apk_file}",
            )
            print(
                "[cleanup] "
                f"{phase} {apk_file}: "
                f"desktop_ready={cleanup_result.get('desktop_ready')} "
                f"force_stopped={len(cleanup_result.get('force_stopped_packages', []))} "
                f"background_cleaned={len(cleanup_result.get('background_packages_cleaned', []))} "
                f"app_data_cleared={cleanup_result.get('app_data_cleared')}"
            )
        except Exception as error:
            print(f"[cleanup] {phase} {apk_file} failed: {error}")
        finally:
            if cleanup_analyzer is not None:
                cleanup_analyzer.app_pid = None

    def _build_failed_result(self, apk_file: str, error_message: str) -> Dict[str, Any]:
        return {
            "apk_file": apk_file,
            "device_connected": False,
            "apk_installed": False,
            "app_started": False,
            "user_interactions": False,
            "runtime_probe_api_calls": {},
            "sensitive_api_calls": {},
            "frida_sensitive_api_calls": {},
            "frida_analysis": {"error": error_message},
            "network_traffic": [],
            "battery_usage": None,
            "memory_usage": None,
            "cpu_usage": None,
            "app_info": None,
            "app_permissions": None,
            "errors": [error_message],
        }

    def _analyze_single_apk(self, apk_file: str, apk_path: str) -> Dict[str, Any]:
        result_file = os.path.join(self.results_dir, f"{apk_file}_dynamic_analysis.json")
        status_file = os.path.join(self.results_dir, f"{apk_file}_dynamic_status.json")
        normalized_apk_name = str(apk_file).strip().lower()
        should_use_manual_probe = (
            self.manual_probe_seconds > 0
            and (
                not self.manual_probe_apk_allowlist
                or normalized_apk_name in self.manual_probe_apk_allowlist
            )
        )
        manual_seconds_for_apk = self.manual_probe_seconds if should_use_manual_probe else 0

        for stale_file in [result_file, status_file]:
            if os.path.exists(stale_file):
                try:
                    os.remove(stale_file)
                except OSError:
                    pass

        worker = multiprocessing.Process(
            target=_dynamic_analysis_worker,
            args=(
                apk_path,
                self.results_dir,
                result_file,
                status_file,
                manual_seconds_for_apk,
                self.low_coverage_api_threshold,
                self.internal_timeout_budget,
            ),
        )
        worker.start()
        worker.join(timeout=self.per_apk_timeout)

        if worker.is_alive():
            print(f"analysis timeout: {apk_file} exceeded {self.per_apk_timeout}s, terminating worker")
            worker.terminate()
            worker.join(timeout=10)
            if worker.is_alive():
                worker.kill()
                worker.join(timeout=5)

            return self._build_failed_result(
                apk_file,
                f"dynamic analysis timeout after {self.per_apk_timeout}s",
            )

        status_payload: Dict[str, Any] = {"success": False, "error": "dynamic worker exited unexpectedly"}
        if os.path.exists(status_file):
            try:
                with open(status_file, "r", encoding="utf-8") as input_handle:
                    status_payload = json.load(input_handle)
            except Exception as error:
                status_payload = {"success": False, "error": f"unable to parse worker status: {error}"}
            finally:
                try:
                    os.remove(status_file)
                except OSError:
                    pass

        if status_payload.get("success") and os.path.exists(result_file):
            with open(result_file, "r", encoding="utf-8") as input_handle:
                result = json.load(input_handle)
            result["apk_file"] = apk_file
            return result

        error_message = str(status_payload.get("error") or "dynamic worker failed")
        failed_result = self._build_failed_result(apk_file, error_message)

        if os.path.exists(result_file):
            try:
                with open(result_file, "r", encoding="utf-8") as input_handle:
                    partial_result = json.load(input_handle)
                if isinstance(partial_result, dict):
                    partial_result["apk_file"] = apk_file
                    partial_result.setdefault("errors", [])
                    if error_message not in partial_result["errors"]:
                        partial_result["errors"].append(error_message)
                    return partial_result
            except Exception:
                pass

        return failed_result

    def analyze_all(self) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        apk_files = [file_name for file_name in os.listdir(self.samples_dir) if file_name.endswith(".apk")]
        print(f"found {len(apk_files)} APK files")
        print(f"dynamic per-APK timeout: {self.per_apk_timeout}s")
        print(f"dynamic internal soft budget: {self.internal_timeout_budget}s")
        print(
            f"adaptive manual probe: {'on' if self.manual_probe_seconds > 0 else 'off'} "
            f"(window={self.manual_probe_seconds}s, threshold={self.low_coverage_api_threshold})"
        )
        if self.manual_probe_apk_allowlist:
            print(
                "manual probe allowlist: "
                + ", ".join(sorted(self.manual_probe_apk_allowlist))
            )
        print(
            "batch cleanup: on "
            f"(clear_app_data_after_analysis={'on' if self.clear_app_data_after_analysis else 'off'})"
        )

        if apk_files:
            first_apk_path = os.path.join(self.samples_dir, apk_files[0])
            self._cleanup_analysis_environment(
                apk_files[0],
                first_apk_path,
                clear_app_data=False,
                phase="pre-batch cleanup",
            )

        for apk_file in apk_files:
            apk_path = os.path.join(self.samples_dir, apk_file)
            print(f"\nanalyzing: {apk_file}")
            result = self._analyze_single_apk(apk_file, apk_path)
            results.append(result)
            self._cleanup_analysis_environment(
                apk_file,
                apk_path,
                clear_app_data=self.clear_app_data_after_analysis,
                phase="post-analysis cleanup",
            )

        self.save_summary(results)
        return results

    def save_summary(self, results: List[Dict[str, Any]]) -> None:
        summary = {
            "total_analyzed": len(results),
            "successfully_analyzed": sum(1 for result in results if result.get("app_started")),
            "results": results,
        }
        summary_file = os.path.join(self.results_dir, "dynamic_analysis_summary.json")
        with open(summary_file, "w", encoding="utf-8") as output_handle:
            json.dump(summary, output_handle, ensure_ascii=False, indent=2)
        print(f"dynamic analysis summary saved to: {summary_file}")


if __name__ == "__main__":
    samples_dir = "../samples"
    results_dir = "../results"
    batch_analyzer = DynamicBatchAnalyzer(samples_dir, results_dir)
    batch_analyzer.analyze_all()
