# =============================================================================
# 动态分析模块
# 功能：通过 ADB 控制 Android 模拟器，对 APK 应用进行全自动化动态隐私检测。
# 包括：UI 自动化交互、敏感 API 运行时监控、Frida Hook 深度分析、
#       登录页绕过、闪退恢复、自适应探测策略等核心能力。
# =============================================================================

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

# 尝试导入 Frida 动态分析引擎，若不可用则跳过 Frida 相关分析
try:
    from dynamic_engine.frida_analyzer import EnhancedDynamicAnalyzer

    frida_available = True
except ImportError:
    print("warning: Frida module is unavailable, dynamic Frida analysis will be skipped")
    frida_available = False


class DynamicAnalyzer:
    """动态分析主控制器。

    负责完成 ADB 设备连接、APK 安装、应用启动、引导式交互、
    运行时敏感 API 探测以及 Frida 深度取证等工作。

    核心设计思路：
    1. **UI 自动化**：通过 uiautomator dump 解析界面元素，智能识别并点击权限授权、
       隐私弹窗、引导页等关键按钮。
    2. **安全交互策略**：严格区分"安全操作"（允许/同意/下一步）与"危险操作"
       （下载/安装/拒绝），避免自动化误操作导致数据丢失或应用异常。
    3. **自适应探测**：根据时间预算动态调整分析深度，支持多轮 Frida 注入和
       低覆盖率时的自动补测。
    4. **登录页绕行**：自动检测登录/注册页面并通过返回键等策略绕行，确保持续探测。
    5. **闪退恢复**：监控应用进程状态，在闪退时自动重新拉起应用并恢复交互。
    """
    # -------------------------------------------------------------------------
    # 安全操作关键词 —— 包含这些文字的按钮被视为"安全可点击"
    # 例如：权限授权弹窗中的"允许"、引导页的"下一步"、协议的"同意"等
    # -------------------------------------------------------------------------
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
        "下一步",
        "完成",
        "立即体验",
        "立即开始",
        "同意并继续",
        "继续浏览",
        "next",
        "finish",
        "done",
        "complete",
        "proceed",
    )

    # -------------------------------------------------------------------------
    # 跳过/忽略操作关键词 —— 包含这些文字的按钮可跳过当前提示
    # 例如：开屏广告的"跳过"、新手引导的"以后再说"等
    # -------------------------------------------------------------------------
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
        "跳过广告",
        "以后再看",
        "以后体验",
        "暂时关闭",
        "skip",
        "skip ad",
        "close",
        "later",
        "not now",
        "maybe later",
    )

    # -------------------------------------------------------------------------
    # 负面/拒绝操作关键词 —— 绝对不应自动点击的按钮
    # 例如：权限弹窗中的"拒绝"、协议中的"不同意"等
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # 关闭弹窗操作关键词 —— 用于关闭广告/弹窗等无关界面
    # -------------------------------------------------------------------------
    CLOSE_ACTION_KEYWORDS = (
        "×",
        "✕",
        "✖",
        "╳",
        "关闭",
        "关闭广告",
        "关闭弹窗",
        "close",
        "dismiss",
    )

    # -------------------------------------------------------------------------
    # 关闭按钮的 resource-id 提示词 —— 通过资源ID匹配关闭按钮
    # -------------------------------------------------------------------------
    CLOSE_RESOURCE_HINTS = (
        "close",
        "dismiss",
        "cancel",
        "iv_close",
        "img_close",
        "btn_close",
        "close_btn",
        "close_button",
        "dialog_close",
        "tt_video_ad_close",
        "skip",
    )

    # -------------------------------------------------------------------------
    # 权限允许按钮的 resource-id 提示词 —— Android 系统权限弹窗中的"允许"按钮
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # 权限拒绝按钮的 resource-id 提示词 —— 应避免点击的拒绝按钮
    # -------------------------------------------------------------------------
    PERMISSION_DENY_RESOURCE_HINTS = (
        "permission_deny_and_dont_ask_again_button",
        "permission_deny_button",
        "permission_no_upgrade_button",
        "permission_no_upgrade_and_dont_ask_again_button",
        "grant_dialog_button_deny",
        "button2",
    )

    # -------------------------------------------------------------------------
    # 登录页检测关键词 —— 识别当前界面是否为登录/注册页面
    # 命中后采取返回键绕行策略，避免卡在登录页无法继续探测
    # -------------------------------------------------------------------------
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
        "请输入手机号",
        "输入手机号",
        "手机号码",
        "获取验证码",
        "短信验证码",
        "快捷登录",
        "免密登录",
    )

    # -------------------------------------------------------------------------
    # 登录页跳过关键词 —— 在登录页面中可以安全点击的"跳过"类按钮
    # -------------------------------------------------------------------------
    LOGIN_SKIP_KEYWORDS = (
        "跳过",
        "暂不登录",
        "暂不注册",
        "稍后登录",
        "以后再说",
        "游客",
        "随便看看",
        "先逛逛",
        "看看再说",
        "关闭",
        "skip",
        "later",
        "not now",
        "close",
    )

    # -------------------------------------------------------------------------
    # 手机号输入框提示关键词 —— 识别登录页中的手机号输入框
    # -------------------------------------------------------------------------
    PHONE_INPUT_KEYWORDS = (
        "手机号",
        "手机号码",
        "请输入手机号",
        "输入手机号",
        "phone",
        "mobile",
        "tel",
        "account",
        "username",
    )

    # 演示用手机号，填入登录页输入框以触发后续行为
    DEMO_PHONE_NUMBER = "13800138000"

    # -------------------------------------------------------------------------
    # 加载中关键词 —— 判断应用是否处于启动/加载状态
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # 系统对话框包名 —— Android 系统级弹窗的包名列表
    # 系统权限弹窗、安装确认弹窗等的包名，需要特殊处理
    # -------------------------------------------------------------------------
    SYSTEM_DIALOG_PACKAGES = (
        "android",
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
        "com.android.packageinstaller",
        "com.android.systemui",
    )

    # -------------------------------------------------------------------------
    # 危险交互关键词 —— 绝对不应自动点击的操作，避免触发下载/安装/更新等
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # 清理时受保护的包名 —— 强制停止后台应用时不会触碰这些系统/模拟器关键进程
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # 清理时受保护的包名前缀 —— 以这些前缀开头的包名都不会被清理
    # -------------------------------------------------------------------------
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
        """
        初始化动态分析器。

        参数：
            apk_path: APK 文件路径，待分析的目标应用
            output_dir: 分析结果输出目录，默认为 "output"
            manual_probe_seconds: 手动探测窗口时长（秒），0 表示禁用。
                当 Frida 自动探测覆盖率不满足阈值时，会开启此窗口供人工介入
            low_coverage_api_threshold: 低覆盖率阈值。当捕获的 API 调用数低于
                此值时认为覆盖率不足，触发补测策略
            analysis_timeout_budget_seconds: 整体分析超时预算（秒），0 表示无限制。
                所有步骤会共享此时间预算，超时后跳过低优步骤
        """
        self.apk_path = apk_path
        self.output_dir = output_dir
        # 从 APK 中提取包名和主 Activity
        self.package_name = self._extract_package_name_from_apk()
        self.main_activity = self._extract_main_activity_from_apk()
        # 定位 ADB 可执行文件路径
        self.adb_path = self._find_adb()
        # 加载敏感 API 映射表（API名 → 描述）
        self.sensitive_apis = self._load_sensitive_apis()
        self.monitoring_logs: List[str] = []
        # 参数规范化，确保非负
        self.manual_probe_seconds = max(0, int(manual_probe_seconds))
        self.low_coverage_api_threshold = max(1, int(low_coverage_api_threshold))
        self.analysis_timeout_budget_seconds = max(0, int(analysis_timeout_budget_seconds))
        # 分析开始时间与截止时间（由 _activate_analysis_budget 激活）
        self.analysis_started_at = 0.0
        self.analysis_deadline: Optional[float] = None
        # 初始化 Frida 分析器
        self.frida_analyzer = EnhancedDynamicAnalyzer(apk_path, output_dir) if frida_available else None
        # 设备与应用进程状态
        self.device_id: Optional[str] = None
        self.app_pid: Optional[str] = None
        self.app_pids: List[str] = []
        self.last_launch_error: Optional[str] = None
        # 将包名同步给 Frida 分析器
        if self.frida_analyzer and self.package_name:
            self.frida_analyzer.set_package_name(self.package_name)

    def _activate_analysis_budget(self) -> None:
        """激活分析时间预算，记录开始时间并计算截止时间。"""
        self.analysis_started_at = time.time()
        if self.analysis_timeout_budget_seconds > 0:
            self.analysis_deadline = self.analysis_started_at + self.analysis_timeout_budget_seconds
        else:
            self.analysis_deadline = None

    def _remaining_analysis_budget(self) -> Optional[float]:
        """返回剩余的预算秒数。若未设置预算则返回 None（表示无限制）。"""
        if self.analysis_deadline is None:
            return None
        return max(0.0, self.analysis_deadline - time.time())

    def _has_analysis_budget(self, minimum_seconds: int = 1, reserve_seconds: int = 0) -> bool:
        """检查是否还有足够的分析预算（含最小需求秒数和预留秒数）。"""
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
        """
        计算某步骤实际可用的时间预算。

        参数：
            requested_seconds: 请求的时间（秒）
            minimum_seconds: 最少需要的时间，预算不足此值时返回 0
            reserve_seconds: 需要预留的时间，从剩余预算中扣除后再分配

        返回：
            实际分配的秒数。若未设预算则直接返回请求值；若预算不足
            minimum+reserve 则返回 0
        """
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
        """
        在系统中定位 ADB 可执行文件。

        按优先级搜索：夜神模拟器自带 ADB → 系统标准 ADB → PATH 中的 adb。
        返回找到的 ADB 路径，若都未找到则返回 "adb" 作为后备。
        """
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
        """
        在系统中定位 AAPT 可执行文件。

        AAPT 用于解析 APK 的包名和主 Activity。按优先级搜索：
        ANDROID_HOME → 夜神模拟器内置 AAPT → PATH 中的 aapt。
        """
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
        """
        从 APK 文件中提取包名。

        策略：优先使用 AAPT dump badging 解析，失败后降级到 androguard 库。
        返回应用包名字符串，若两者都失败则返回 None。
        """
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
                    # 从输出中匹配 package: name='xxx' 模式
                    match = re.search(r"package: name='([^']+)'", result.stdout)
                    if match:
                        return match.group(1)
            except Exception as error:
                print(f"extract package name by aapt failed: {error}")
        # 降级方案：使用 androguard 库解析
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
        """
        从 APK 中提取主 Activity 名称。

        使用 AAPT dump badging 解析 launchable-activity，失败时降级到 androguard。
        """
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
        """
        构建 ADB am start 所需的完整组件名（package/activity 格式）。

        处理三种 Activity 名称格式：
        - 以 "." 开头：省略形式的相对类名 → 拼接为 package/activity
        - 不含 "."：系统类 → 拼接为 package/.activity
        - 完整限定名：直接使用 package/activity
        """
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
        """加载敏感 API 映射表，键为 API 标识名，值为中文描述。"""
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
        """
        执行 ADB 命令的通用封装。

        参数：
            command: ADB 命令参数列表（不含 "adb" 前缀）
            timeout: 命令超时时间（秒）
            quiet: 是否静默模式（不打印错误信息）

        返回：
            命令的标准输出字符串，失败或超时返回 None
        """
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
        """检查系统中是否存在指定命令。"""
        try:
            subprocess.run([command, "--version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def check_device_connected(self) -> bool:
        """
        检查是否有 Android 设备通过 ADB 连接。

        解析 adb devices 输出，找到第一个处于 "device" 状态的设备。
        若找到则将 device_id 保存到实例变量中。
        """
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
        """
        在设备上启动 Frida Server。

        步骤：终止已有 frida-server → 设置执行权限 → 建立端口转发 → 后台启动。
        """
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
        """
        带重试机制的设备连接检查。

        尝试 3 轮：先直接检查连接 → 重启 ADB 服务 → 尝试连接夜神模拟器。
        每次成功后自动启动 Frida Server。
        """
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
        """
        将 APK 安装到模拟器。

        使用 adb install -r -t -g 参数：
        -r: 替换已存在的应用
        -t: 允许测试包
        -g: 自动授予所有运行时权限

        参数：
            timeout: 安装超时时间（秒）
        """
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
        """
        刷新应用进程 PID。

        通过 adb shell pidof 获取目标包名对应的进程 ID 列表。
        主 PID 取列表第一个，同时同步到 Frida 分析器。
        """
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
        """获取应用所有进程 PID 的整数列表，供 Frida 注入使用。"""
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
        """将当前应用的 PID 列表同步到 Frida 分析器。"""
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
        """检查目标应用是否有进程在运行。"""
        return self._refresh_app_pid() is not None

    def _force_stop_app(self) -> bool:
        """强制停止目标应用，清除 PID 缓存。"""
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
        """
        从任意文本中提取包名。

        使用多种正则模式匹配包名格式（如 "com.example.app"），
        返回去重排序后的包名列表。
        """
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
        """列出模拟器上所有第三方（用户安装）应用的包名。"""
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
        """收集所有桌面启动器（Home/Launcher）应用的包名列表。"""
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
        """判断包名是否属于桌面/启动器/系统弹窗。"""
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
        """构建环境清理时的受保护包名集合。"""
        protected_packages = set(self.SYSTEM_DIALOG_PACKAGES)
        protected_packages.update(self.CLEANUP_PROTECTED_PACKAGES)
        protected_packages.update(self._collect_home_packages())
        return {str(item).strip() for item in protected_packages if str(item).strip()}

    def _is_protected_cleanup_package(  
        #判断包名是否属于清理保护名单。
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
        #强制停止指定包名的应用（受保护包名不会被停止）。
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
        """清除指定包名的应用数据。"""
        normalized = str(package_name or "").strip()
        if not normalized:
            return False
        output = self._run_adb_command(["shell", "pm", "clear", normalized], timeout=45, quiet=quiet)
        if output is None:
            return False
        return "success" in output.lower()

    def _collect_background_candidate_packages(self) -> List[str]:
        """收集可能的后台候选包名列表（用于环境清理）。"""
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
        """通过 KEYCODE_HOME 返回桌面。"""
        for _ in range(max(1, int(retries))):
            self._run_adb_command(["shell", "input", "keyevent", "3"], timeout=8, quiet=True)
            time.sleep(1)
            foreground_package = self._get_foreground_package()
            if self._is_home_surface_package(foreground_package):
                return True
        return False

    def reset_analysis_environment(
        #重置分析环境：清理后台应用、返回桌面、可选清除应用数据。
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
        #清理运行时状态，调用 reset_analysis_environment 的内部包装。
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
        """通过 dumpsys window 和 activity 获取当前前台包名。"""
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
        """判断目标应用是否在前台。"""
        if not self.package_name:
            return False
        return self._get_foreground_package() == self.package_name

    def _is_system_dialog_package(self, package_name: Optional[str]) -> bool:
        """判断包名是否属于系统弹窗包名列表。"""
        return str(package_name or "").strip() in self.SYSTEM_DIALOG_PACKAGES

    def _is_controlled_foreground(self, allow_system_dialogs: bool = False) -> bool:
        """判断前台是否处于受控状态（目标应用或可选系统弹窗）。"""
        foreground_package = self._get_foreground_package()
        if not foreground_package:
            return False
        if self.package_name and foreground_package == self.package_name:
            return True
        return allow_system_dialogs and self._is_system_dialog_package(foreground_package)

    def _should_keep_ui_node(self, package_name: str, include_system_dialogs: bool = False) -> bool:
        """判断 UI 节点是否应保留。仅保留属于目标应用或系统弹窗（当允许时）的节点。"""
        normalized = str(package_name or "").strip()
        if not normalized:
            return True
        if self.package_name and normalized == self.package_name:
            return True
        return include_system_dialogs and self._is_system_dialog_package(normalized)

    def _parse_bounds(self, bounds_text: str) -> Optional[Dict[str, int]]:
        """解析 UI 元素的 bounds 属性字符串，返回包含坐标和尺寸信息的字典。"""
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
        """通过 adb shell wm size 获取设备屏幕分辨率，默认 1080x1920。"""
        output = self._run_adb_command(["shell", "wm", "size"], timeout=10, quiet=True) or ""
        matches = re.findall(r"(\d+)x(\d+)", output)
        if matches:
            width, height = matches[-1]
            return {"width": max(int(width), 480), "height": max(int(height), 800)}
        return {"width": 1080, "height": 1920}

    def _dump_ui_snapshot(self, include_system_dialogs: bool = False) -> Dict[str, Any]:
        """
        📸 UI 快照采集 —— 核心 UI 解析方法。

        工作流程：
        1. 通过 `uiautomator dump` 将当前屏幕的 UI 层级导出为 XML 文件到 SD 卡
        2. 通过 `adb shell cat` 读取 XML 内容
        3. 使用 ElementTree 解析每个 <node> 元素，提取以下属性：
           - 包名 (package)、文本 (text)、内容描述 (content-desc)
           - 资源 ID (resource-id)、类名 (class)
           - 可点击 (clickable)、可交互 (enabled)、可滚动 (scrollable)
           - 焦点状态 (focused)、坐标边界 (bounds)
        4. 聚合文本信息生成 normalized_text（text + content_desc + resource_id）
        5. 筛选尺寸 ≥ 24x24 的可点击节点，进一步分类为 safe_action_nodes：
           - 不包含负面/拒绝操作
           - 属于权限允许、通用正向操作、跳过/关闭操作之一

        参数：
            include_system_dialogs: 是否保留 Android 系统权限弹窗（如 PermissionController）的 UI 节点。
                                   设为 True 时可以看到系统的"允许/拒绝"弹窗按钮。

        返回：
            字典包含：
            - nodes:              所有解析出的 UI 节点列表
            - clickable_nodes:    可点击且可交互的节点（尺寸≥24x24）
            - safe_action_nodes:  安全可操作的节点（可自动点击）
            - texts:              界面文本列表（前30条）
            - signature:          界面签名（前8个有意义的节点标签，用"|"分隔），
                                 用于判断界面是否已发生变化
        """
        # Step 1: 导出 UI 层级为 XML 文件
        target_path = "/sdcard/appprivacydetector_ui.xml"
        dump_output = self._run_adb_command(["shell", "uiautomator", "dump", target_path], timeout=20, quiet=True)
        if dump_output is None:
            return {"nodes": [], "clickable_nodes": [], "safe_action_nodes": [], "texts": [], "signature": ""}

        # Step 2: 读取 XML 文件内容
        xml_text = self._run_adb_command(["shell", "cat", target_path], timeout=20, quiet=True) or ""
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return {"nodes": [], "clickable_nodes": [], "safe_action_nodes": [], "texts": [], "signature": ""}

        nodes: List[Dict[str, Any]] = []
        clickable_nodes: List[Dict[str, Any]] = []
        safe_action_nodes: List[Dict[str, Any]] = []
        texts: List[str] = []

        # Step 3: 遍历 XML 树中的每个 <node> 元素
        for element in root.iter("node"):
            # 过滤：只保留目标应用和（可选）系统弹窗的节点
            package_name = str(element.attrib.get("package", "")).strip()
            if not self._should_keep_ui_node(package_name, include_system_dialogs=include_system_dialogs):
                continue

            # 解析坐标边界
            bounds = self._parse_bounds(element.attrib.get("bounds", ""))
            if not bounds:
                continue

            # 提取节点属性
            text = str(element.attrib.get("text", "")).strip()
            content_desc = str(element.attrib.get("content-desc", "")).strip()
            resource_id = str(element.attrib.get("resource-id", "")).strip()
            class_name = str(element.attrib.get("class", "")).strip()
            clickable = str(element.attrib.get("clickable", "")).lower() == "true"
            enabled = str(element.attrib.get("enabled", "")).lower() == "true"
            scrollable = str(element.attrib.get("scrollable", "")).lower() == "true"
            focused = str(element.attrib.get("focused", "")).lower() == "true"

            # 构建节点的标准化文本（用于关键词匹配）
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
                "focused": focused,
                "bounds": bounds,
                "normalized_text": normalized_text,
                "is_system_dialog": self._is_system_dialog_package(package_name),
            }
            nodes.append(node)
            if normalized_text:
                texts.append(normalized_text)

            # Step 4: 筛选安全可操作节点
            # 条件：可点击 + 可交互 + 尺寸≥24x24 + 非负面操作 + 属于安全操作类型
            if clickable and enabled and bounds["width"] >= 24 and bounds["height"] >= 24:
                clickable_nodes.append(node)
                if not self._is_negative_action_node(node) and (
                    self._is_permission_allow_node(node)
                    or self._is_general_positive_action_node(node)
                    or self._is_dismiss_action_node(node)
                    or self._is_close_action_node(node)
                    or self._is_progress_action_node(node)
                ):
                    safe_action_nodes.append(node)

        # Step 5: 生成界面签名（用于后续去重，判断界面是否刷新）
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
        """检测界面是否处于加载状态（含"加载中""loading""splash"等关键词）。"""
        texts = snapshot.get("texts", []) or []
        lowered_texts = " ".join(str(item) for item in texts).lower()
        return any(keyword in lowered_texts for keyword in self.LOADING_KEYWORDS)

    def _detect_login_gate(self, snapshot: Optional[Dict[str, Any]] = None) -> bool:
        """检测当前界面是否为登录/注册页面。通过关键词匹配和手机号输入框检测。"""
        snapshot = snapshot or self._dump_ui_snapshot()
        texts = snapshot.get("texts", []) or []
        merged = " ".join(str(item) for item in texts)
        lowered = merged.lower()
        has_keyword = any(keyword in merged for keyword in self.LOGIN_GATE_KEYWORDS) or any(
            keyword in lowered for keyword in ["login", "sign in", "sign-in", "手机号", "password", "wechat", "qq"]
        )
        return has_keyword or self._find_phone_input_node(snapshot) is not None

    def _find_phone_input_node(self, snapshot: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """在 UI 快照中查找手机号输入框（EditText）节点，辅助登录页检测。"""
        snapshot = snapshot or self._dump_ui_snapshot()
        nodes = snapshot.get("nodes", []) or []
        edit_nodes = [
            node
            for node in nodes
            if node.get("enabled") and "edittext" in str(node.get("class_name") or "").lower()
        ]
        if not edit_nodes:
            return None
        for node in edit_nodes:
            normalized = self._normalized_node_text(node).lower()
            resource_id = str(node.get("resource_id") or "").lower()
            if any(keyword.lower() in normalized or keyword.lower() in resource_id for keyword in self.PHONE_INPUT_KEYWORDS):
                return node
        focused_nodes = [node for node in edit_nodes if node.get("focused")]
        if focused_nodes:
            return focused_nodes[0]
        if len(edit_nodes) == 1:
            return edit_nodes[0]
        return sorted(edit_nodes, key=lambda node: int((node.get("bounds") or {}).get("center_y", 0)))[0]

    def _select_login_skip_candidate(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """在登录页面中查找可安全点击的跳过按钮候选。"""
        candidates = []
        for node in snapshot.get("clickable_nodes", []) or []:
            normalized = self._normalized_node_text(node)
            lowered = normalized.lower()
            if any(keyword in normalized for keyword in self.LOGIN_SKIP_KEYWORDS) or any(
                keyword in lowered for keyword in ["skip", "later", "not now", "close"]
            ):
                candidates.append(node)
        if not candidates:
            return None
        return sorted(
            candidates,
            key=lambda node: (
                int((node.get("bounds") or {}).get("center_y", 0)),
                -int((node.get("bounds") or {}).get("center_x", 0)),
            ),
        )[0]

    def _input_text(self, text: str) -> bool:
        """通过 ADB 在模拟器中输入文本。"""
        escaped = str(text).replace(" ", "%s")
        output = self._run_adb_command(["shell", "input", "text", escaped], timeout=10, quiet=True)
        time.sleep(0.4)
        return output is not None

    def _press_keyevent(self, key_code: str, settle_seconds: float = 0.6) -> bool:
        """发送按键事件（如 KEYCODE_BACK）并等待界面稳定。"""
        output = self._run_adb_command(["shell", "input", "keyevent", str(key_code)], timeout=10, quiet=True)
        time.sleep(max(0.1, float(settle_seconds)))
        return output is not None

    def _handle_login_gate(self, snapshot: Optional[Dict[str, Any]] = None) -> bool:
        """
        🚪 登录页绕行处理 —— 检测并绕过登录/注册页面。

        策略：
        1. 首先检测当前界面是否为登录/注册页（通过 _detect_login_gate）
        2. 如果是，连续按两次返回键（KEYCODE_BACK）尝试退出
        3. 每次按返回键后重新检测，确保真正离开了登录页

        为什么用返回键而非尝试登录：
        - 自动化分析不需要真实登录，只需探测隐私行为
        - 返回键是最通用的退出方式，无需预测具体 UI 布局
        - 大部分应用在登录页按返回键会回到首页/游客模式

        参数：
            snapshot: 可选的预采集 UI 快照，避免重复采集

        返回：
            是否检测到并处理了登录页
        """
        snapshot = snapshot or self._dump_ui_snapshot(include_system_dialogs=True)
        # 未检测到登录页则直接返回
        if not self._detect_login_gate(snapshot):
            return False
        # 第一次按返回键尝试退出登录页
        self._press_keyevent("KEYCODE_BACK", settle_seconds=0.8)
        time.sleep(0.5)
        # 重新检测，若仍处于登录页则再按一次
        if self._detect_login_gate(self._dump_ui_snapshot(include_system_dialogs=True)):
            self._press_keyevent("KEYCODE_BACK", settle_seconds=0.8)
        return True

    def _recover_app_if_needed(self, force_launch: bool = False) -> bool:
        """
        🔄 闪退恢复 —— 在应用意外退出时自动恢复前台状态。

        这是保障自动化分析连续性的关键方法。应用可能因以下原因退出：
        - 内存不足被系统杀死
        - 应用自身崩溃（ANR / 闪退）
        - Monkey 测试触发的边界情况
        - 权限弹窗处理时的进程切换

        恢复策略（三层递进）：
        1. 检查前台是否已是目标应用或系统弹窗 → 直接返回成功
        2. 如果应用进程仍在运行（_is_app_running），按返回键尝试切回
        3. 以上都失败 → 调用 start_app 重新启动应用

        参数：
            force_launch: 是否强制重新启动（跳过前两层检查）

        返回：
            恢复是否成功
        """
        # 第一层：前台已正常，无需恢复
        if self._is_controlled_foreground(allow_system_dialogs=True):
            return True
        # 第二层：进程存在但不前台，尝试通过返回键切回
        if self._is_app_running() and not force_launch:
            self._press_keyevent("KEYCODE_BACK", settle_seconds=0.5)
            if self._is_controlled_foreground(allow_system_dialogs=True):
                return True
        # 第三层：重新启动应用
        return self.start_app(force_launch=force_launch)

    def _is_blocked_interaction_node(self, node: Dict[str, Any]) -> bool:
        """判断节点是否属于危险交互（下载/安装/更新）。"""
        normalized_text = str(node.get("normalized_text") or "").strip().lower()
        return any(keyword.lower() in normalized_text for keyword in self.BLOCKED_INTERACTION_KEYWORDS)

    def _is_interaction_candidate(self, node: Dict[str, Any], screen: Optional[Dict[str, int]] = None) -> bool:
        """判断节点是否适合作为交互候选（尺寸、位置均需合理）。"""
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
        if center_y <= int(screen["height"] * 0.18) or center_y >= int(screen["height"] * 0.92):
            return False
        if center_x <= int(screen["width"] * 0.05) or center_x >= int(screen["width"] * 0.95):
            return False
        return True

    @staticmethod
    def _normalized_node_text(node: Dict[str, Any]) -> str:
        """提取节点的标准化文本。"""
        return str(node.get("normalized_text") or "").strip()

    def _is_negative_action_node(self, node: Dict[str, Any]) -> bool:
        """判断节点是否代表负面操作（拒绝/取消/不同意）。"""
        normalized_text = self._normalized_node_text(node)
        lowered_text = normalized_text.lower()
        resource_id = str(node.get("resource_id") or "").strip().lower()
        if any(hint in resource_id for hint in self.PERMISSION_DENY_RESOURCE_HINTS):
            return True
        if any(keyword in normalized_text for keyword in self.NEGATIVE_ACTION_KEYWORDS):
            return True
        return any(keyword in lowered_text for keyword in ["deny", "disagree", "forbid", "cancel", "decline"])

    def _is_dismiss_action_node(self, node: Dict[str, Any]) -> bool:
        """判断节点是否代表跳过/忽略操作。"""
        normalized_text = self._normalized_node_text(node)
        lowered_text = normalized_text.lower()
        resource_id = str(node.get("resource_id") or "").strip().lower()
        if any(hint in resource_id for hint in self.CLOSE_RESOURCE_HINTS):
            return True
        if any(keyword in normalized_text for keyword in self.DISMISS_ACTION_KEYWORDS):
            return True
        return any(
            keyword in lowered_text
            for keyword in ["skip", "close", "later", "not now", "got it", "dismiss"]
        )

    def _is_close_action_node(self, node: Dict[str, Any]) -> bool:
        """判断节点是否代表关闭操作（×/关闭/close）。"""
        normalized_text = self._normalized_node_text(node)
        lowered_text = normalized_text.lower()
        resource_id = str(node.get("resource_id") or "").strip().lower()
        if any(hint in resource_id for hint in self.CLOSE_RESOURCE_HINTS):
            return True
        if any(keyword in normalized_text for keyword in self.CLOSE_ACTION_KEYWORDS):
            return True
        return any(keyword in lowered_text for keyword in ["skip", "close", "dismiss"])

    def _is_progress_action_node(self, node: Dict[str, Any]) -> bool:
        """判断节点是否代表进度推进操作（下一步/完成/继续）。"""
        if self._is_negative_action_node(node) or self._is_dismiss_action_node(node) or self._is_close_action_node(node):
            return False
        normalized_text = self._normalized_node_text(node)
        lowered_text = normalized_text.lower()
        resource_id = str(node.get("resource_id") or "").strip().lower()
        if any(keyword in normalized_text for keyword in self.SAFE_ACTION_KEYWORDS):
            return True
        if any(hint in resource_id for hint in ["next", "finish", "done", "complete", "proceed", "continue"]):
            return True
        return any(
            keyword in lowered_text
            for keyword in ["next", "finish", "done", "complete", "proceed", "continue", "start", "enter", "open"]
        )

    def _is_permission_allow_node(self, node: Dict[str, Any]) -> bool:
        """判断节点是否代表权限允许操作。"""
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
        """对权限允许按钮进行优先级排名（始终允许=0 > 仅在使用中=1 > 仅此一次=2 > 普通=3）。"""
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
        """判断节点是否代表通用正向操作（导航按钮等）。"""
        if (
            self._is_negative_action_node(node)
            or self._is_dismiss_action_node(node)
            or self._is_close_action_node(node)
        ):
            return False
        normalized_text = self._normalized_node_text(node)
        lowered_text = normalized_text.lower()
        resource_id = str(node.get("resource_id") or "").strip().lower()
        if any(keyword in normalized_text for keyword in self.SAFE_ACTION_KEYWORDS):
            return True
        if resource_id.endswith(":id/button1") or resource_id.endswith("/button1"):
            return True
        return any(
            keyword in lowered_text
            for keyword in [
                "allow",
                "agree",
                "confirm",
                "continue",
                "next",
                "enter",
                "open",
                "start",
                "grant",
                "home",
                "video",
                "feed",
                "discover",
                "search",
                "message",
                "messages",
                "mine",
                "my",
                "profile",
                "follow",
                "following",
                "recommend",
                "recommendation",
                "watch",
                "play",
                "chat",
                "ask",
                "send",
                "new",
                "create",
                "content",
                "list",
            ]
        )

    def _select_safe_action_candidate(self, snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        🔍 从 UI 快照中智能选择最佳的安全操作候选节点。

        选优优先级（从高到低）：
        1. 系统弹窗中的权限允许按钮（最优先，因为需要处理权限授予）
           → 按权限级别排名：始终允许 > 仅在使用中 > 仅此一次 > 普通允许
        2. 关闭按钮（系统弹窗优先）
        3. 进度推进按钮（如"下一步""完成""继续"）
        4. 通用正向操作按钮（如导航按钮：首页/视频/关注/消息等）
        5. 跳过操作按钮（最后备选，且仅当无系统弹窗时才考虑）

        返回：
            最佳候选节点字典，若无合适候选则返回 None
        """
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

        close_nodes = [
            node
            for node in target_nodes
            if self._is_close_action_node(node) and not self._is_negative_action_node(node)
        ]
        if close_nodes:
            return sorted(
                close_nodes,
                key=lambda node: (
                    0 if node.get("is_system_dialog") else 1,
                    int((node.get("bounds") or {}).get("center_y", 0)),
                    -int((node.get("bounds") or {}).get("center_x", 0)),
                ),
            )[0]

        progress_nodes = [
            node
            for node in target_nodes
            if self._is_progress_action_node(node) and not self._is_negative_action_node(node)
        ]
        if progress_nodes:
            return sorted(
                progress_nodes,
                key=lambda node: (
                    0 if node.get("is_system_dialog") else 1,
                    -int((node.get("bounds") or {}).get("center_y", 0)),
                    -int((node.get("bounds") or {}).get("center_x", 0)),
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
        """获取界面中所有适合交互的候选节点列表。"""
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
        """
        在指定绝对坐标执行点击操作。

        参数：
            x, y: 屏幕绝对坐标
            settle_seconds: 点击后等待界面稳定的秒数
            allow_system_dialogs: 是否允许目标前台为系统弹窗

        返回：
            点击后目标前台是否仍处于受控状态
        """
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
        """点击 UI 节点的中心坐标。"""
        bounds = node.get("bounds") or {}
        return self._tap_absolute(
            bounds.get("center_x", 0),
            bounds.get("center_y", 0),
            settle_seconds=settle_seconds,
            allow_system_dialogs=allow_system_dialogs,
        )

    def _handle_safe_actions(self, max_actions: int = 3) -> int:
        """
        🛡️ 安全操作处理 —— 自动处理权限弹窗、引导页等 UI 障碍。

        功能：
        在目标应用或系统弹窗处于前台时，循环检测并点击安全操作按钮。
        每次循环：
        1. 截取当前 UI 快照（含系统弹窗）
        2. 通过 _select_safe_action_candidate 选出最佳候选按钮
        3. 点击该按钮并等待界面稳定

        这是整个自动化交互流程中最核心的安全机制，确保：
        - 权限弹窗被授予（允许/始终允许/仅在使用中）
        - 引导页被推进（下一步/完成/跳过）
        - 广告弹窗被关闭（关闭/×）
        - 绝不点击拒绝/下载/安装等危险操作

        参数：
            max_actions: 每次调用最多处理的弹窗数量（避免无限循环）

        返回：
            实际处理的弹窗数量
        """
        # 前提条件：目标应用或系统弹窗必须在最前台
        if not self._is_controlled_foreground(allow_system_dialogs=True):
            return 0
        handled = 0
        for _ in range(max(1, int(max_actions))):
            # 每次循环重新截取 UI 快照（因为界面可能已变化）
            snapshot = self._dump_ui_snapshot(include_system_dialogs=True)
            candidate = self._select_safe_action_candidate(snapshot)
            if not candidate:
                break
            if not self._tap_node(candidate, settle_seconds=1.0, allow_system_dialogs=True):
                break
            handled += 1
        return handled

    @staticmethod
    def _node_action_key(node: Dict[str, Any]) -> str:
        """生成节点的唯一操作标识键（用于去重）。"""
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
        #执行屏幕滑动手势（支持上下/左右滑动）。
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
        """
        🎯 引导式交互循环 —— 自动化 UI 交互的核心引擎。

        在指定时长内对目标应用执行智能的 UI 交互，模拟真实用户行为。
        采用"安全优先"策略，结合点击和滑动手势，最大化触发应用的隐私行为。

        每轮循环执行以下步骤：
        1. 🛡️ **安全操作**：优先处理权限弹窗、引导页等 UI 障碍
        2. 🚪 **登录绕行**：检测并退出登录/注册页面
        3. ⏳ **加载等待**：如果界面显示加载中且无可操作节点，保持前台等待
        4. 🖱️ **智能点击**：对可交互节点按优先级排序后依次点击（从下往上、从中间扩散）
           - 使用 seen_targets 集合去重，避免重复点击同一位置
           - 每轮最多点击 4 个新节点
        5. 👆 **交替滑动**：在目标前台时交替执行上下滑动和左右滑动
           - 偶数轮：垂直滑动（模拟列表浏览）
           - 奇数轮：水平滑动（模拟页面切换）
        6. 🐵 **Monkey 降级**：当引导式交互无新节点可点时，降级到随机 Monkey 测试

        参数：
            duration_seconds: 交互持续时长（秒），建议 8-18 秒
            allow_monkey_fallback: 是否允许引导式交互无效时降级到 Monkey 随机测试
            monkey_event_count: Monkey 降级时的事件数量
            monkey_throttle_ms: Monkey 降级时的事件间隔（毫秒）

        返回：
            执行的操作总数（包括点击、滑动、弹窗处理等）
        """
        if not self.package_name:
            return 0

        loop_seconds = max(3, int(duration_seconds))
        deadline = time.time() + loop_seconds  # 交互截止时间
        screen = self._get_screen_size()
        seen_targets = set()  # 已点击过的节点记录（用于去重）
        actions = 0
        round_index = 0

        while time.time() < deadline:
            # ── 步骤 1: 闪退恢复 ──
            # 如果应用不在前台，尝试恢复
            if not self._is_controlled_foreground(allow_system_dialogs=True):
                if not self._recover_app_if_needed(force_launch=False):
                    time.sleep(0.8)
                    continue

            # ── 步骤 2: 安全操作处理 ──
            # 优先处理权限弹窗、引导页等 UI 障碍
            actions += self._handle_safe_actions(max_actions=2)
            snapshot = self._dump_ui_snapshot(include_system_dialogs=True)

            # ── 步骤 3: 登录页绕行 ──
            if self._handle_login_gate(snapshot):
                actions += 1
                snapshot = self._dump_ui_snapshot(include_system_dialogs=True)

            # ── 步骤 4: 加载状态等待 ──
            # 界面显示"加载中"且无可操作节点时，等待而非盲目操作
            if self._has_loading_marker(snapshot) and not self._get_interaction_candidates(snapshot):
                self._keep_app_foreground(dwell_seconds=min(4, max(2, int(deadline - time.time()))))
                round_index += 1
                continue

            # ── 步骤 5: 智能点击 ──
            # 对可交互节点排序：优先点击下方元素（center_y 大的），
            # 水平方向优先点击靠近屏幕中央的（避免误触边缘元素）
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
                # 去重：已点击过的节点不再重复点击
                if action_key in seen_targets:
                    continue
                if self._tap_node(node, settle_seconds=0.8):
                    seen_targets.add(action_key)
                    actions += 1
                    tapped_this_round += 1
                    # 每次点击后立即处理可能弹出的安全操作
                    actions += self._handle_safe_actions(max_actions=2)
                if tapped_this_round >= 4:
                    break

            if time.time() >= deadline:
                break

            # ── 步骤 6: 交替滑动 ──
            # 偶数轮：上下滑动（模拟列表浏览）
            # 奇数轮：左右滑动（模拟页面切换/ViewPager）
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
                actions += self._handle_safe_actions(max_actions=2)

            # ── 步骤 7: Monkey 降级 ──
            # 当本轮引导式交互没有点击任何新节点，且允许降级时，
            # 执行随机 Monkey 测试作为兜底策略
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
                    actions += self._handle_safe_actions(max_actions=2)

            round_index += 1

        return actions

    def _is_snapshot_ready(self, snapshot: Dict[str, Any]) -> bool:
        """判断 UI 快照是否已达到稳定状态（节点数≥4且有交互候选）。"""
        nodes = snapshot.get("nodes", []) or []
        texts = snapshot.get("texts", []) or []
        interactive_nodes = self._get_interaction_candidates(snapshot)
        if len(nodes) < 4:
            return False
        if self._has_loading_marker(snapshot) and not interactive_nodes:
            return False
        return bool(interactive_nodes) or len(texts) >= 3

    def _should_avoid_aggressive_navigation(self, snapshot: Optional[Dict[str, Any]] = None) -> bool:
        """判断是否应避免激进导航（登录页或加载页时不适用）。"""
        snapshot = snapshot or self._dump_ui_snapshot()
        return self._detect_login_gate(snapshot) or self._has_loading_marker(snapshot)

    def _keep_app_foreground(self, dwell_seconds: int = 6) -> bool:
        """确保目标应用保持在最前台，处理弹窗和登录页。"""
        if not self.package_name:
            return False
        deadline = time.time() + max(1, int(dwell_seconds))
        while time.time() < deadline:
            if not self._is_controlled_foreground(allow_system_dialogs=True):
                if not self._recover_app_if_needed(force_launch=False):
                    time.sleep(1)
                    continue
            self._handle_safe_actions(max_actions=2)
            self._handle_login_gate()
            time.sleep(1)
        return self._is_app_running()

    def _wait_for_app_ready(self, max_wait_seconds: int = 45) -> bool:
        """等待应用启动完成并进入稳定交互状态。"""
        if not self.package_name:
            return False
        wait_budget = self._step_budget(max_wait_seconds, minimum_seconds=4)
        if wait_budget <= 0:
            return self._is_app_running()
        start_time = time.time()
        while time.time() - start_time < wait_budget:
            foreground_package = self._get_foreground_package()
            if self._is_system_dialog_package(foreground_package):
                self._handle_safe_actions(max_actions=3)
                time.sleep(1.4)
                continue
            if foreground_package == self.package_name:
                self._handle_safe_actions(max_actions=3)
                snapshot = self._dump_ui_snapshot()
                if self._is_snapshot_ready(snapshot):
                    return True
            elif self._is_app_running():
                time.sleep(2.2)
                continue
            time.sleep(1.4)
        return self._is_app_running()

    def _launch_via_explicit_activity(self) -> bool:
        """通过指定 Activity 组件名启动应用。"""
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
        """
        通过 Monkey 测试启动应用。
        :return: 是否成功启动应用
        """
        if not self.package_name:
            return False
        output = self._run_adb_command(
            ["shell", "monkey", "-p", self.package_name, "-c", "android.intent.category.LAUNCHER", "1"],
            timeout=30,
            quiet=True,
        )
        return output is not None

    def start_app(self, force_launch: bool = True) -> bool:
        """
        启动应用，根据 force_launch 参数判断是否强制启动。
        :param force_launch: 是否强制启动应用，默认 True
        :return: 是否成功启动应用
        """
        if not self.package_name:
            return False
        self.last_launch_error = None
        launch_succeeded = False
        if not force_launch and self._is_target_foreground() and self._wait_for_app_ready(max_wait_seconds=12):
            return True
        if force_launch:
            self._force_stop_app()

        launch_plan = [
            (self._launch_via_explicit_activity, 30 if force_launch else 16),
            (self._launch_via_monkey, 36 if force_launch else 20),
        ]
        if not self.main_activity:
            launch_plan = [(self._launch_via_monkey, 36 if force_launch else 20)]

        for launch_func, wait_window in launch_plan:
            if not launch_func():
                continue
            launch_succeeded = True
            time.sleep(3.2)
            wait_budget = self._step_budget(wait_window, minimum_seconds=6)
            if wait_budget > 0 and self._wait_for_app_ready(max_wait_seconds=wait_budget):
                self._refresh_app_pid()
                self._handle_safe_actions(max_actions=4)
                return True

        self.last_launch_error = "app launch did not stabilize"
        return launch_succeeded or self._is_app_running()

    def _perform_basic_interactions(self) -> None:
        """
        执行基本交互，包括点击应用图标、输入文本和点击按钮。
        """
        if not self._is_target_foreground():
            return
        interaction_window = self._step_budget(14, minimum_seconds=5, reserve_seconds=36 if self.frida_analyzer else 12)
        if interaction_window <= 0:
            self._handle_safe_actions(max_actions=3)
            return
        self._run_guided_interaction_loop(
            duration_seconds=interaction_window,
            allow_monkey_fallback=True,
            monkey_event_count=12,
            monkey_throttle_ms=160,
        )

    def observe_privacy_notice(self) -> Dict[str, Any]:
        """
        观察应用是否显示隐私政策或用户协议。
        :return: 包含隐私政策或用户协议的字典
        """
        snapshot = self._dump_ui_snapshot(include_system_dialogs=True)
        texts = snapshot.get("texts", []) or []
        merged_text = " ".join(str(item) for item in texts)
        lowered_text = merged_text.lower()
        privacy_keywords = ["隐私", "隐私政策", "用户协议", "个人信息", "权限", "收集", "使用规则", "privacy", "policy"]
        explicit_consent_keywords = ["同意", "我同意", "同意并继续", "允许", "拒绝", "不同意", "agree", "accept", "deny"]
        has_privacy_notice = any(keyword in merged_text for keyword in privacy_keywords) or any(
            keyword in lowered_text for keyword in privacy_keywords
        )
        has_explicit_consent = any(keyword in merged_text for keyword in explicit_consent_keywords) or any(
            keyword in lowered_text for keyword in explicit_consent_keywords
        )
        return {
            "observed": True,
            "has_privacy_notice": has_privacy_notice,
            "has_explicit_consent_action": has_explicit_consent,
            "texts": texts[:30],
            "signature": snapshot.get("signature", ""),
        }

    def simulate_user_interactions(self) -> bool:
        """
        👤 模拟用户交互 —— 执行完整的用户行为模拟流程。

        这是动态分析中"UI 交互"阶段的主入口，模拟一个新用户从安装到
        正常使用的完整流程。设计理念是尽可能触达应用的各个页面，从而
        触发更多的敏感 API 调用（如权限请求、网络请求、数据采集等）。

        流程：
        1. 启动应用（先尝试温启动，失败时冷启动）
        2. 处理启动时的权限弹窗和引导页（_handle_safe_actions）
        3. 执行基础交互循环（_perform_basic_interactions → _run_guided_interaction_loop）
        4. 检测并绕过登录页面
        5. 如果仍在前台再执行一轮补充交互

        返回：
            整体流程是否执行成功（是否至少完成了启动）
        """
        # Step 1: 启动应用（温启动优先，失败则冷启动）
        if not self.start_app(force_launch=False):
            if not self.start_app(force_launch=True):
                return False
        # Step 2: 处理初始弹窗（权限请求、隐私政策、引导页等）
        self._handle_safe_actions(max_actions=4)
        # Step 3: 执行引导式交互循环
        self._perform_basic_interactions()
        # Step 4: 登录页检测与绕行
        if self._detect_login_gate():
            print("[dynamic] login gate detected, press BACK and continue probing")
            self._handle_login_gate()
            if self._detect_login_gate():
                dwell_seconds = self._step_budget(6, minimum_seconds=3, reserve_seconds=28 if self.frida_analyzer else 8)
                if dwell_seconds > 0:
                    self._keep_app_foreground(dwell_seconds=dwell_seconds)
        # Step 5: 补充交互（如果仍在目标前台）
        if self._is_target_foreground():
            extra_window = self._step_budget(8, minimum_seconds=3, reserve_seconds=16 if self.frida_analyzer else 6)
            if extra_window > 0:
                self._run_guided_interaction_loop(
                    duration_seconds=extra_window,
                    allow_monkey_fallback=True,
                    monkey_event_count=8,
                    monkey_throttle_ms=180,
                )
        self._handle_safe_actions(max_actions=3)
        return True

    def run_monkey_burst(self, event_count: int = 80, throttle_ms: int = 180) -> bool: 
        """
        运行 Monkey 测试，模拟用户交互。
        :param event_count: 事件数量，默认 80
        :param throttle_ms: 事件间隔时间，默认 180ms
        :return: 是否成功运行测试
        """
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
            "--pct-touch",  # 55% 概率点击屏幕
            "55",
            "--pct-motion",  # 18% 概率移动屏幕
            "18",
            "--pct-nav",  # 12% 概率导航
            "12",
            "--pct-majornav",  # 3% 概率主要导航
            "3",
            "--pct-appswitch",  # 0% 概率切换应用
            "0",
            "--pct-anyevent",  # 0% 概率其他事件
            "0",
            "--pct-syskeys",  # 0% 概率系统按键
            "0",
            "--throttle",
            str(throttle_ms),
            "-v",
            str(event_count),
        ]
        output = self._run_adb_command(command, timeout=timeout, quiet=True)
        return output is not None

    def _warm_up_app_process(self) -> None:
        """预热应用进程：启动应用、处理弹窗、执行基础交互。"""
        if not self.start_app(force_launch=False):
            self.start_app(force_launch=True)
        self._refresh_app_pid()
        self._handle_safe_actions(max_actions=3)
        self._handle_login_gate()
        self._perform_basic_interactions()

    def exercise_app_under_frida(self) -> bool:
        """在 Frida 探针激活状态下对应用执行引导式交互。"""
        self._warm_up_app_process()
        if self._should_avoid_aggressive_navigation():
            self._handle_login_gate()
            dwell_seconds = self._step_budget(6, minimum_seconds=3, reserve_seconds=16)
            if dwell_seconds > 0:
                self._keep_app_foreground(dwell_seconds=dwell_seconds)
        else:
            interaction_window = self._step_budget(18, minimum_seconds=6, reserve_seconds=14)
            if interaction_window > 0:
                self._run_guided_interaction_loop(
                    duration_seconds=interaction_window,
                    allow_monkey_fallback=True,
                    monkey_event_count=16,
                    monkey_throttle_ms=170,
                )
            if self._is_target_foreground():
                follow_up_window = self._step_budget(8, minimum_seconds=3, reserve_seconds=10)
                if follow_up_window > 0:
                    self._run_guided_interaction_loop(
                        duration_seconds=follow_up_window,
                        allow_monkey_fallback=False,
                        monkey_event_count=6,
                        monkey_throttle_ms=180,
                    )
        self._warm_up_app_process()
        return True

    def _exercise_cold_start_under_frida(self) -> bool:
        """冷启动条件下对应用执行 Frida 探针引导式交互。"""
        if not self.start_app(force_launch=True):
            return False
        self._handle_safe_actions(max_actions=4)
        primary_window = self._step_budget(14, minimum_seconds=6, reserve_seconds=14)
        if primary_window > 0:
            self._run_guided_interaction_loop(
                duration_seconds=primary_window,
                allow_monkey_fallback=False,
            )
        if self._should_avoid_aggressive_navigation():
            self._handle_login_gate()
            dwell_seconds = self._step_budget(5, minimum_seconds=2, reserve_seconds=10)
            if dwell_seconds > 0:
                self._keep_app_foreground(dwell_seconds=dwell_seconds)
        else:
            secondary_window = self._step_budget(10, minimum_seconds=4, reserve_seconds=8)
            if secondary_window > 0:
                self._run_guided_interaction_loop(
                    duration_seconds=secondary_window,
                    allow_monkey_fallback=True,
                    monkey_event_count=10,
                    monkey_throttle_ms=180,
                )
        return True

    def _exercise_recovery_under_frida(self) -> bool:
        """执行恢复性 Frida 探针引导式交互（重冷启动+额外交互）。"""
        if not self.start_app(force_launch=True):
            return False
        self._handle_safe_actions(max_actions=4)
        if self._should_avoid_aggressive_navigation():
            self._handle_login_gate()
            dwell_seconds = self._step_budget(5, minimum_seconds=2, reserve_seconds=8)
            if dwell_seconds > 0:
                self._keep_app_foreground(dwell_seconds=dwell_seconds)
        else:
            recovery_window = self._step_budget(12, minimum_seconds=5, reserve_seconds=8)
            if recovery_window > 0:
                self._run_guided_interaction_loop(
                    duration_seconds=recovery_window,
                    allow_monkey_fallback=True,
                    monkey_event_count=12,
                    monkey_throttle_ms=170,
                )
        self._perform_basic_interactions()
        return True

    def _exercise_runtime_probe(self) -> bool:
        """执行运行时探针引导式交互（温启动优先）。"""
        if not self.start_app(force_launch=False):
            return False
        self._handle_safe_actions(max_actions=3)
        primary_window = self._step_budget(12, minimum_seconds=5, reserve_seconds=12 if self.frida_analyzer else 4)
        if primary_window > 0:
            self._run_guided_interaction_loop(
                duration_seconds=primary_window,
                allow_monkey_fallback=True,
                monkey_event_count=10,
                monkey_throttle_ms=170,
            )
        if self._should_avoid_aggressive_navigation():
            dwell_seconds = self._step_budget(6, minimum_seconds=3, reserve_seconds=8)
            if dwell_seconds > 0:
                self._keep_app_foreground(dwell_seconds=dwell_seconds)
        else:
            secondary_window = self._step_budget(8, minimum_seconds=4, reserve_seconds=6)
            if secondary_window > 0:
                self._run_guided_interaction_loop(
                    duration_seconds=secondary_window,
                    allow_monkey_fallback=True,
                    monkey_event_count=8,
                    monkey_throttle_ms=160,
                )
        return True

    def monitor_sensitive_api_calls(
        #监控 logcat 输出，检测敏感 API 调用并汇总统计。
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
        #合并 base_data 和 extra_data 中的敏感 API 调用结果。
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
        """从 Frida 分析结果中提取敏感 API 调用信息。"""
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
        """获取目标应用的网络连接信息（通过 netstat）。"""
        output = self._run_adb_command(["shell", "netstat", "-tunap"], timeout=20)
        if not output:
            return []
        connections = []
        for line in output.splitlines():
            if self.package_name and self.package_name in line:
                connections.append(line.strip())
        return connections

    def get_battery_usage(self) -> Optional[str]:
        """获取模拟器电池使用情况（通过 dumpsys battery）。"""
        return self._run_adb_command(["shell", "dumpsys", "battery"], timeout=20)

    def get_memory_usage(self) -> Optional[str]:
        """获取目标应用的内存使用情况（通过 dumpsys meminfo）。"""
        if not self.package_name:
            return None
        return self._run_adb_command(["shell", "dumpsys", "meminfo", self.package_name], timeout=20)

    def get_cpu_usage(self) -> Optional[str]:
        """获取目标应用的 CPU 使用情况（通过 top 命令）。"""
        pid = self.app_pid or (self._run_adb_command(["shell", "pidof", self.package_name], timeout=10) if self.package_name else None)
        if not pid:
            return None
        return self._run_adb_command(["shell", "top", "-n", "1", "-p", str(pid).split()[0]], timeout=20)

    def get_app_info(self) -> Optional[Dict[str, str]]:
        """获取目标应用的包详细信息（通过 dumpsys package）。"""
        if not self.package_name:
            return None
        app_info: Dict[str, str] = {}
        package_info = self._run_adb_command(["shell", "dumpsys", "package", self.package_name], timeout=30)
        if package_info:
            app_info["package_info"] = package_info
        return app_info or None

    def get_app_permissions(self) -> Optional[List[str]]:
        """获取目标应用的权限清单列表。"""
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
        """判断 Frida 分析结果是否覆盖率不足（API调用数低于阈值）。"""
        total_api_calls = int(frida_summary.get("total_api_calls") or 0)
        total_signals = int(frida_summary.get("total_hooked_signals") or 0)
        if total_api_calls < self.low_coverage_api_threshold:
            return True
        if total_signals < 2:
            return True
        return False

    def _manual_guided_probe(self) -> bool:
        """手动引导探测——开放交互窗口供人工操作补充覆盖率。"""
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
                self._recover_app_if_needed(force_launch=False)
            self._handle_safe_actions(max_actions=2)
            snapshot = self._dump_ui_snapshot(include_system_dialogs=True)
            if self._detect_login_gate(snapshot):
                print("[Frida][Manual] login page detected, press BACK and continue probing")
                self._handle_login_gate(snapshot)
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
        """合并文本列表，去重并保持顺序。"""
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
        """对 Frida 分析结果进行状态分类（captured/ready_no_hits/runtime_interrupted等）。"""
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
        """按 signal_key 聚合 Frida 调用日志，生成统计摘要。"""
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
        #合并两次 Frida 探测的结果载荷。
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
                "login_assist_enabled": True,
                "crash_recovery_enabled": True,
            },
        }
        if errors and not merged_summary["total_api_calls"]:
            merged_payload["error"] = errors[0]
        return self._classify_frida_payload(merged_payload)

    def _run_frida_pass(
        #执行单轮 Frida 探测（含重试机制），返回分类后的结果载荷。
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
                    self._handle_login_gate()
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
        """
        🔬 Frida 运行时分析编排 —— 多轮自适应 Hook 探测策略。

        这是整个动态分析中最核心的深度检测环节。通过 Frida 框架在目标应用
        进程中注入 JavaScript Hook，实时拦截并记录所有敏感 API 调用。

        自适应探测策略（四轮递进）：
        ┌─────────────┬──────────┬──────────────┬──────────────────────┐
        │   阶段名称    │  模式     │   交互策略     │       目的           │
        ├─────────────┼──────────┼──────────────┼──────────────────────┤
        │ cold_start  │ spawn    │ 冷启动+引导   │ 捕获应用启动时的行为   │
        │ warm_inter  │ attach   │ 温启动+交互   │ 捕获正常使用时的行为   │
        │ recovery    │ spawn    │ 重新冷启动    │ 覆盖率不足时补测       │
        │ manual      │ attach   │ 开放手动窗口  │ 低覆盖率时人工介入     │
        └─────────────┴──────────┴──────────────┴──────────────────────┘

        每轮的交互策略不同：
        - cold_start: 从零开始冷启动，捕获初始化阶段的 API 调用
        - warm_interaction: 在已运行的进程中交互，覆盖更多使用场景
        - recovery_spawn: 覆盖率低时重新冷启动补测
        - manual_guided: 开放窗口供人工操作（授予权限、登录、导航敏感页面）

        预算感知：
        - compact_mode: 剩余预算 ≤ 64 秒时启用，缩短各轮时长
        - 每轮开始前检查时间预算，不足时跳过

        返回：
            合并后的 Frida 分析结果字典，包含 state/error/warning 等字段
        """
        print("start Frida runtime analysis")
        if not self.package_name:
            return {"error": "package name is unknown"}
        if not self.frida_analyzer:
            return {"error": "Frida module is unavailable"}
        try:
            # 检查剩余预算，决定是否使用紧凑模式
            remaining_budget = self._remaining_analysis_budget()
            compact_mode = remaining_budget is not None and remaining_budget <= 64

            executed_labels: List[str] = []
            # 根据预算计算各轮时长
            cold_duration = self._step_budget(14 if compact_mode else 18, minimum_seconds=10, reserve_seconds=24)
            warm_duration = self._step_budget(18 if compact_mode else 22, minimum_seconds=12, reserve_seconds=12)

            # ── 第一轮：冷启动探测 ──
            cold_start_payload: Optional[Dict[str, Any]] = None
            if cold_duration > 0:
                cold_start_payload = self._run_frida_pass(
                    label="cold_start",
                    duration=cold_duration,
                    probe_callback=self._exercise_cold_start_under_frida,
                    spawn_first=True,
                )
                executed_labels.append("cold_start")

            # ── 第二轮：温交互探测 ──
            warm_interaction_payload: Optional[Dict[str, Any]] = None
            if warm_duration > 0:
                warm_interaction_payload = self._run_frida_pass(
                    label="warm_interaction",
                    duration=warm_duration,
                    probe_callback=self.exercise_app_under_frida,
                    spawn_first=False,
                )
                executed_labels.append("warm_interaction")

            # 合并前两轮结果
            if cold_start_payload and warm_interaction_payload:
                merged_payload = self._merge_frida_payload(cold_start_payload, warm_interaction_payload)
            elif warm_interaction_payload:
                merged_payload = warm_interaction_payload
            elif cold_start_payload:
                merged_payload = cold_start_payload
            else:
                return {"error": "analysis budget exhausted before Frida probe"}

            # 设置自适应探测元数据
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
                "login_assist_enabled": True,
                "crash_recovery_enabled": True,
            }

            # ── 第三轮：补充冷启动（覆盖率不足时触发）──
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
                    "login_assist_enabled": True,
                    "crash_recovery_enabled": True,
                }

            # ── 第四轮：手动引导探测（覆盖率仍不足且启用手动窗口时触发）──
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
                    "login_assist_enabled": True,
                    "crash_recovery_enabled": True,
                }
            return merged_payload
        except Exception as error:
            return {"error": str(error)}

    def perform_dynamic_analysis(self) -> Dict[str, Any]:
        """
        🚀 动态分析主入口 —— 执行完整的自动化动态隐私检测流程。

        这是 DynamicAnalyzer 类的核心调度方法，按序执行 12 个分析步骤，
        每个步骤都有独立的预算检查和错误处理。

        分析步骤流程：
        ┌──────┬──────────────────────────────────┬──────────────────────┐
        │ 序号  │            步骤名称               │        功能说明        │
        ├──────┼──────────────────────────────────┼──────────────────────┤
        │  1   │ check_device                    │ 检测模拟器 ADB 连接     │
        │  2   │ install_apk                     │ 安装目标 APK 到模拟器   │
        │  3   │ start_app                       │ 启动应用               │
        │  4   │ simulate_user_interactions      │ 模拟用户交互(核心)      │
        │  5   │ monitor_sensitive_api_calls     │ logcat 监控敏感 API    │
        │  6   │ perform_frida_analysis          │ Frida 深度 Hook 分析   │
        │  7   │ get_network_traffic             │ 采集网络连接信息        │
        │  8   │ get_battery_usage               │ 采集电池使用情况        │
        │  9   │ get_memory_usage                │ 采集内存使用情况        │
        │ 10   │ get_cpu_usage                   │ 采集 CPU 使用情况       │
        │ 11   │ get_app_info                    │ 采集应用包信息          │
        │ 12   │ get_app_permissions             │ 采集应用权限清单        │
        └──────┴──────────────────────────────────┴──────────────────────┘

        预算感知机制：
        - 步骤 5, 7-10 在预算不足时会自动跳过
        - 步骤 6（Frida）在预算不足 12 秒时跳过
        - 步骤 1-2 失败会直接终止（break），后续步骤继续

        返回：
            包含所有分析结果的字典，字段包括：
            - device_connected/apk_installed/app_started: 各阶段状态
            - user_interactions: 交互模拟是否执行
            - privacy_notice_observation: 启动前后的隐私政策观察
            - sensitive_api_calls: 合并后的敏感 API 调用汇总
            - frida_analysis: Frida 深度分析结果
            - network_traffic/battery/memory/cpu: 系统资源快照
            - app_info/app_permissions: 应用元信息
            - errors: 所有步骤的错误信息列表
        """
        print("=" * 60)
        print("start dynamic analysis")
        print("=" * 60)
        # 激活分析时间预算
        self._activate_analysis_budget()

        # 初始化结果结构（所有字段预设默认值）
        analysis_result: Dict[str, Any] = {
            "device_connected": False,
            "apk_installed": False,
            "app_started": False,
            "user_interactions": False,
            "privacy_notice_observation": {},
            "post_interaction_privacy_notice_observation": {},
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
        # 计算运行时探针的可用时长
        runtime_probe_duration = self._step_budget(14, minimum_seconds=8, reserve_seconds=26 if self.frida_analyzer else 10)

        # 定义分析步骤序列（步骤名, 执行函数）
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

        # 使用 tqdm 进度条依次执行各步骤
        for step_name, step_func in tqdm(steps, desc="dynamic analysis", unit="step"):
            try:
                # ── 预算感知跳过逻辑 ──
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

                # ── 步骤1: 设备连接检测 ──
                if step_name == "check_device":
                    if not step_func():
                        analysis_result["errors"].append("device is not connected")
                        break
                    analysis_result["device_connected"] = True

                # ── 步骤2: APK 安装 ──
                elif step_name == "install_apk":
                    if not step_func():
                        analysis_result["errors"].append("apk install failed")
                        break
                    analysis_result["apk_installed"] = True

                # ── 步骤3: 应用启动 + 隐私政策观察 ──
                elif step_name == "start_app":
                    if not step_func():
                        analysis_result["errors"].append("app start failed")
                    analysis_result["app_started"] = bool(self._is_app_running())
                    if analysis_result["app_started"]:
                        analysis_result["privacy_notice_observation"] = self.observe_privacy_notice()

                # ── 步骤4: 用户交互模拟 + 交互后隐私政策观察 ──
                elif step_name == "simulate_user_interactions":
                    if not step_func():
                        analysis_result["errors"].append("user interaction simulation failed")
                    analysis_result["user_interactions"] = True
                    if analysis_result.get("app_started"):
                        analysis_result["post_interaction_privacy_notice_observation"] = self.observe_privacy_notice()

                # ── 步骤5: logcat 敏感 API 监控 ──
                elif step_name == "monitor_sensitive_api_calls":
                    analysis_result["runtime_probe_api_calls"] = step_func()
                    analysis_result["sensitive_api_calls"] = self._merge_sensitive_api_calls(
                        analysis_result.get("runtime_probe_api_calls"),
                        None,
                    )

                # ── 步骤6: Frida 深度分析 + 结果合并 ──
                elif step_name == "perform_frida_analysis":
                    analysis_result["frida_analysis"] = step_func()
                    if analysis_result["frida_analysis"]:
                        analysis_result["app_started"] = True
                    frida_state = str(analysis_result["frida_analysis"].get("state") or "").strip().lower()
                    # Frida 启动失败时记录错误
                    if analysis_result["frida_analysis"].get("error") and frida_state in {
                        "startup_failed",
                        "startup_incomplete",
                        "bridge_ready_only",
                    }:
                        analysis_result["errors"].append(
                            f"frida probe issue: {analysis_result['frida_analysis']['error']}"
                        )
                    # 提取 Frida 捕获的敏感 API 并合并到总结果
                    frida_sensitive_calls = self._extract_frida_sensitive_api_calls(analysis_result.get("frida_analysis"))
                    analysis_result["frida_sensitive_api_calls"] = frida_sensitive_calls
                    analysis_result["sensitive_api_calls"] = self._merge_sensitive_api_calls(
                        analysis_result.get("runtime_probe_api_calls"),
                        frida_sensitive_calls,
                    )

                # ── 步骤7-12: 系统资源/应用信息采集 ──
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
        """执行完整动态分析并将结果保存为 JSON 文件。"""
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
    """
    动态分析工作进程入口函数。

    在独立进程中创建 DynamicAnalyzer 实例并执行完整分析。
    分析结果写入 result_file，状态信息写入 status_file。
    无论成功与否，最后都会清理运行时环境。
    """
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
    """
    批量动态分析控制器。

    功能：遍历指定目录下的所有 APK 文件，逐个执行动态隐私检测分析。
    每个 APK 在独立的子进程中运行，支持超时控制和环境清理。

    核心特性：
    - 多进程隔离：每个 APK 分析在独立进程中运行，避免互相干扰
    - 超时保护：per_apk_timeout 限制单个 APK 的最大分析时间
    - 环境清理：分析前后自动清理模拟器环境（返回桌面、清理后台）
    - 选择性分析：支持 include_apks 白名单和 manual_probe 白名单
    """
    def __init__(
        self,
        samples_dir: str,
        results_dir: str = "results",
        per_apk_timeout: int = 300,
        manual_probe_seconds: int = 0,
        low_coverage_api_threshold: int = 4,
        manual_probe_apk_allowlist: Optional[List[str]] = None,
        clear_app_data_after_analysis: bool = False,
        include_apks: Optional[List[str]] = None,
    ):
        """
        初始化批量分析器。

        参数：
            samples_dir: 存放 APK 样本的目录路径
            results_dir: 分析结果输出目录
            per_apk_timeout: 每个 APK 的最大分析时间（秒）
            manual_probe_seconds: 手动探测窗口时长
            low_coverage_api_threshold: 低覆盖率阈值
            manual_probe_apk_allowlist: 启用手动探测的 APK 白名单
            clear_app_data_after_analysis: 分析后是否清除应用数据
            include_apks: 仅分析指定的 APK 文件（白名单过滤）
        """
        self.samples_dir = samples_dir
        self.results_dir = results_dir
        self.include_apks = {str(item).strip() for item in (include_apks or []) if str(item).strip()}
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
        """分析环境清理——在每个 APK 分析前后调用，确保模拟器环境干净。"""
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
        """构建分析失败时的默认结果结构。"""
        return {
            "apk_file": apk_file,
            "device_connected": False,
            "apk_installed": False,
            "app_started": False,
            "user_interactions": False,
            "privacy_notice_observation": {},
            "post_interaction_privacy_notice_observation": {},
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
        """
        在独立子进程中分析单个 APK。

        通过 multiprocessing.Process 启动 _dynamic_analysis_worker，
        使用 per_apk_timeout 作为超时上限。超时后强制终止子进程。
        """
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
        """
        批量分析入口——遍历样本目录下的所有 APK 并依次分析。

        流程：
        1. 列出样本目录下所有 .apk 文件（可通过 include_apks 过滤）
        2. 对第一个 APK 执行预清理（pre-batch cleanup）
        3. 逐个分析每个 APK，分析后执行后清理
        4. 保存汇总结果
        """
        results: List[Dict[str, Any]] = []
        apk_files = [file_name for file_name in os.listdir(self.samples_dir) if file_name.endswith(".apk")]
        if self.include_apks:
            apk_files = [file_name for file_name in apk_files if file_name in self.include_apks]
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
        """保存批量分析汇总结果到 JSON 文件。"""
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
