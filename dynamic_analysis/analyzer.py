import json
import multiprocessing
import os
import re
import subprocess
import time
from typing import Any, Dict, List, Optional

from tqdm import tqdm

try:
    from dynamic_engine.frida_analyzer import EnhancedDynamicAnalyzer

    frida_available = True
except ImportError:
    print("warning: Frida module is unavailable, dynamic Frida analysis will be skipped")
    frida_available = False


class DynamicAnalyzer:
    def __init__(
        self,
        apk_path: str,
        output_dir: str = "output",
        manual_probe_seconds: int = 0,
        low_coverage_api_threshold: int = 4,
    ):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.package_name = self._extract_package_name_from_apk()
        self.adb_path = self._find_adb()
        self.sensitive_apis = self._load_sensitive_apis()
        self.monitoring_logs: List[str] = []
        self.manual_probe_seconds = max(0, int(manual_probe_seconds))
        self.low_coverage_api_threshold = max(1, int(low_coverage_api_threshold))
        self.frida_analyzer = EnhancedDynamicAnalyzer(apk_path, output_dir) if frida_available else None
        self.device_id: Optional[str] = None
        self.app_pid: Optional[str] = None
        if self.frida_analyzer and self.package_name:
            self.frida_analyzer.set_package_name(self.package_name)

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
        }

    def _run_adb_command(self, command: List[str], timeout: int = 15) -> Optional[str]:
        full_command = [self.adb_path] + command
        try:
            process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                print(f"adb command timed out: {' '.join(full_command)}")
                return None
            if process.returncode != 0:
                message = (stderr or stdout or "").strip()
                if message:
                    print(f"adb command failed: {message}")
                return None
            return (stdout or "").strip()
        except Exception as error:
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

    def _is_app_running(self) -> bool:
        if not self.package_name:
            return False
        output = self._run_adb_command(["shell", "pidof", self.package_name], timeout=10)
        if output:
            self.app_pid = output.split()[0].strip()
            return True
        return False

    def start_app(self) -> bool:
        if not self.package_name:
            return False
        if self._is_app_running():
            return True
        command = ["shell", "monkey", "-p", self.package_name, "-c", "android.intent.category.LAUNCHER", "1"]
        output = self._run_adb_command(command, timeout=30)
        time.sleep(4)
        if output is not None and self._is_app_running():
            return True
        return self._is_app_running()

    def simulate_user_interactions(self) -> bool:
        actions = [
            ["shell", "input", "tap", "540", "1680"],
            None,
            ["shell", "input", "tap", "540", "960"],
            None,
            ["shell", "input", "swipe", "900", "1700", "200", "300", "400"],
            None,
            ["shell", "input", "swipe", "540", "1600", "540", "500", "300"],
            None,
            ["shell", "input", "tap", "820", "320"],
            None,
            ["shell", "input", "keyevent", "4"],
        ]
        for action in actions:
            if action:
                self._run_adb_command(action, timeout=10)
            time.sleep(2)
        return True

    def run_monkey_burst(self, event_count: int = 120, throttle_ms: int = 250) -> bool:
        if not self.package_name:
            return False

        print(f"run monkey burst for {event_count} events")
        timeout = max(90, int((event_count * throttle_ms) / 1000) + 45)
        command = [
            "shell",
            "monkey",
            "-p",
            self.package_name,
            "--ignore-crashes",
            "--ignore-timeouts",
            "--ignore-security-exceptions",
            "--pct-syskeys",
            "0",
            "--throttle",
            str(throttle_ms),
            "-v",
            str(event_count),
        ]
        output = self._run_adb_command(command, timeout=timeout)
        return output is not None

    def exercise_app_under_frida(self) -> bool:
        self.simulate_user_interactions()
        self.run_monkey_burst()
        time.sleep(2)
        self.simulate_user_interactions()
        return True

    def monitor_sensitive_api_calls(self, duration: int = 60) -> Dict[str, Dict[str, Any]]:
        print(f"monitoring logcat sensitive APIs for {duration}s")
        self._run_adb_command(["logcat", "-c"])
        process = subprocess.Popen(
            [self.adb_path, "logcat"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        start_time = time.time()
        detected_apis: Dict[str, Dict[str, Any]] = {}
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
            with tqdm(total=duration, desc="monitor sensitive APIs", unit="s") as progress:
                while time.time() - start_time < duration:
                    raw_line = process.stdout.readline()
                    if not raw_line:
                        time.sleep(0.1)
                        continue
                    try:
                        line = raw_line.decode("utf-8")
                    except UnicodeDecodeError:
                        line = raw_line.decode("gbk", errors="replace")
                    normalized_line = line.strip()
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
                    progress.n = min(duration, int(time.time() - start_time))
                    progress.refresh()
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

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
        if self.manual_probe_seconds <= 0:
            return True

        print(
            f"[Frida][Manual] low coverage detected, manual interaction window: {self.manual_probe_seconds}s"
        )
        print("[Frida][Manual] please grant permissions / login / navigate sensitive pages in emulator now")

        started_at = time.time()
        last_reported = -1
        while time.time() - started_at < self.manual_probe_seconds:
            remaining = max(0, self.manual_probe_seconds - int(time.time() - started_at))
            if remaining != last_reported and (remaining % 10 == 0 or remaining <= 5):
                print(f"[Frida][Manual] remaining: {remaining}s")
                last_reported = remaining
            time.sleep(1)

        print("[Frida][Manual] manual interaction window finished, run a short monkey burst")
        self.run_monkey_burst(event_count=40, throttle_ms=150)
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
        return merged_payload

    def _perform_frida_analysis(self) -> Dict[str, Any]:
        print("start Frida runtime analysis")
        if not self.package_name:
            return {"error": "package name is unknown"}
        if not self.frida_analyzer:
            return {"error": "Frida module is unavailable"}
        if not self._is_app_running():
            self.start_app()
            time.sleep(3)
        try:
            first_results = self.frida_analyzer.perform_frida_analysis(
                duration=60,
                probe_callback=self.exercise_app_under_frida,
            )
            first_summary = self.frida_analyzer.get_frida_summary()
            first_payload: Dict[str, Any] = {"results": first_results, "summary": first_summary}
            if first_results.get("error"):
                first_payload["error"] = first_results["error"]
            elif first_summary.get("error_messages") and not first_summary.get("total_api_calls"):
                first_payload["error"] = first_summary["error_messages"][0]

            should_run_manual_probe = (
                self.manual_probe_seconds > 0
                and self._is_low_coverage_frida(first_summary)
            )
            if not should_run_manual_probe:
                first_payload["adaptive_probe"] = {
                    "enabled": self.manual_probe_seconds > 0,
                    "manual_probe_seconds": self.manual_probe_seconds,
                    "low_coverage_api_threshold": self.low_coverage_api_threshold,
                    "pass_count": 1,
                    "triggered_manual_probe": False,
                }
                return first_payload

            print("[Frida] low coverage detected, starting manual-guided second pass")
            second_duration = max(60, self.manual_probe_seconds + 20)
            second_results = self.frida_analyzer.perform_frida_analysis(
                duration=second_duration,
                probe_callback=self._manual_guided_probe,
            )
            second_summary = self.frida_analyzer.get_frida_summary()
            second_payload: Dict[str, Any] = {"results": second_results, "summary": second_summary}
            if second_results.get("error"):
                second_payload["error"] = second_results["error"]
            elif second_summary.get("error_messages") and not second_summary.get("total_api_calls"):
                second_payload["error"] = second_summary["error_messages"][0]

            merged_payload = self._merge_frida_payload(first_payload, second_payload)
            merged_payload["adaptive_probe"]["triggered_manual_probe"] = True
            return merged_payload
        except Exception as error:
            return {"error": str(error)}

    def perform_dynamic_analysis(self) -> Dict[str, Any]:
        print("=" * 60)
        print("start dynamic analysis")
        print("=" * 60)

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

        steps = [
            ("check_device", self._check_device_with_retry),
            ("install_apk", self.install_apk),
            ("start_app", self.start_app),
            ("simulate_user_interactions", self.simulate_user_interactions),
            ("monitor_sensitive_api_calls", lambda: self.monitor_sensitive_api_calls(20)),
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
                    if analysis_result["frida_analysis"].get("error"):
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
) -> None:
    status_payload = {"success": False, "error": ""}
    try:
        analyzer = DynamicAnalyzer(
            apk_path,
            results_dir,
            manual_probe_seconds=manual_probe_seconds,
            low_coverage_api_threshold=low_coverage_api_threshold,
        )
        analyzer.save_result(result_file)
        status_payload["success"] = True
    except Exception as error:
        status_payload["error"] = f"{type(error).__name__}: {error}"
    finally:
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
    ):
        self.samples_dir = samples_dir
        self.results_dir = results_dir
        self.per_apk_timeout = max(120, int(per_apk_timeout))
        self.manual_probe_seconds = max(0, int(manual_probe_seconds))
        self.low_coverage_api_threshold = max(1, int(low_coverage_api_threshold))
        self.manual_probe_apk_allowlist = {
            str(item).strip().lower()
            for item in (manual_probe_apk_allowlist or [])
            if str(item).strip()
        }
        os.makedirs(results_dir, exist_ok=True)

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
        print(
            f"adaptive manual probe: {'on' if self.manual_probe_seconds > 0 else 'off'} "
            f"(window={self.manual_probe_seconds}s, threshold={self.low_coverage_api_threshold})"
        )
        if self.manual_probe_apk_allowlist:
            print(
                "manual probe allowlist: "
                + ", ".join(sorted(self.manual_probe_apk_allowlist))
            )

        for apk_file in apk_files:
            apk_path = os.path.join(self.samples_dir, apk_file)
            print(f"\nanalyzing: {apk_file}")
            result = self._analyze_single_apk(apk_file, apk_path)
            results.append(result)

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
