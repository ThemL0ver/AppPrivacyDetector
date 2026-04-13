from __future__ import annotations

import os
import shutil
import threading
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

import frida


class HookManager:
    _agent_lock = threading.Lock()
    _bundle_cache: Dict[str, Dict[str, Any]] = {}

    def __init__(self, package_name: str):
        self.package_name = package_name
        self.device = None
        self.session = None
        self.script = None
        self.is_running = False

        self.hooked_apis: List[str] = []
        self.call_logs: List[Dict[str, Any]] = []
        self.signal_counts: Dict[str, int] = {}
        self.category_counts: Dict[str, int] = {}
        self.status_messages: List[str] = []
        self.errors: List[str] = []

    @classmethod
    def _get_bundle_mtime(cls, script_path: str) -> float:
        project_root = os.path.dirname(script_path)
        tracked_paths = [
            script_path,
            os.path.join(project_root, "package.json"),
        ]
        mtimes = [os.path.getmtime(path) for path in tracked_paths if os.path.exists(path)]
        return max(mtimes) if mtimes else 0.0

    @classmethod
    def _ensure_agent_dependencies(cls, project_root: str) -> None:
        dependency_root = os.path.join(project_root, "node_modules", "frida-java-bridge")
        if os.path.isdir(dependency_root):
            return

        print("[HookManager] installing Frida agent dependencies")
        package_manager = frida.PackageManager()
        package_manager.install(project_root=project_root)

    @classmethod
    def _stage_agent_project(cls, script_path: str) -> Tuple[str, str]:
        source_project_root = os.path.dirname(script_path)
        stage_root = os.path.join(tempfile.gettempdir(), "appprivacydetector_frida_agent")
        os.makedirs(stage_root, exist_ok=True)

        files_to_stage = [
            ("package.json", os.path.join(source_project_root, "package.json")),
            (os.path.basename(script_path), script_path),
        ]
        for staged_name, source_path in files_to_stage:
            staged_path = os.path.join(stage_root, staged_name)
            if not os.path.exists(source_path):
                raise FileNotFoundError(source_path)
            if (not os.path.exists(staged_path)) or (
                os.path.getmtime(source_path) > os.path.getmtime(staged_path)
            ):
                shutil.copyfile(source_path, staged_path)

        return stage_root, os.path.basename(script_path)

    @classmethod
    def _build_agent_bundle(cls, script_path: str) -> str:
        script_path = os.path.abspath(script_path)
        source_mtime = cls._get_bundle_mtime(script_path)

        cached = cls._bundle_cache.get(script_path)
        if cached and cached.get("mtime") == source_mtime:
            return str(cached["bundle"])

        with cls._agent_lock:
            cached = cls._bundle_cache.get(script_path)
            if cached and cached.get("mtime") == source_mtime:
                return str(cached["bundle"])

            project_root, entrypoint = cls._stage_agent_project(script_path)
            cls._ensure_agent_dependencies(project_root)
            print(f"[HookManager] compiling Frida agent: {entrypoint}")
            compiler = frida.Compiler()
            bundle = compiler.build(entrypoint, project_root=project_root, type_check="none")
            cls._bundle_cache[script_path] = {"mtime": source_mtime, "bundle": bundle}
            return bundle

    def connect_device(self) -> bool:
        strategies = [
            (
                "remote",
                lambda: frida.get_device_manager().add_remote_device("127.0.0.1:27042"),
            ),
            (
                "enumerate_remote",
                lambda: next(
                    (
                        device
                        for device in frida.get_device_manager().enumerate_devices()
                        if device.type == "remote"
                    ),
                    None,
                ),
            ),
            (
                "enumerate_local",
                lambda: next(
                    (
                        device
                        for device in frida.get_device_manager().enumerate_devices()
                        if device.type == "local"
                    ),
                    None,
                ),
            ),
            ("usb", lambda: frida.get_usb_device(timeout=15)),
            (
                "enumerate",
                lambda: next(
                    (
                        device
                        for device in frida.get_device_manager().enumerate_devices()
                        if device.type in {"remote", "local", "usb"}
                    ),
                    None,
                ),
            ),
            ("local", lambda: frida.get_local_device()),
        ]

        for strategy_name, resolver in strategies:
            try:
                device = resolver()
                if device is not None:
                    self.device = device
                    print(f"[HookManager] connected device via {strategy_name}: {device.name}")
                    return True
            except Exception as error:
                print(f"[HookManager] device strategy {strategy_name} failed: {error}")

        print("[HookManager] unable to connect to Frida device")
        return False

    def _find_running_pids(self) -> List[int]:
        if not self.device:
            return []

        matched: List[int] = []
        try:
            for process in self.device.enumerate_processes():
                identifier = str(getattr(process, "identifier", "") or "")
                name = str(getattr(process, "name", "") or "")
                if self.package_name == identifier or self.package_name == name:
                    matched.append(int(process.pid))
                elif self.package_name in identifier or self.package_name in name:
                    matched.append(int(process.pid))
        except Exception as error:
            print(f"[HookManager] enumerate processes failed: {error}")

        deduplicated: List[int] = []
        seen = set()
        for pid in matched:
            if pid not in seen:
                seen.add(pid)
                deduplicated.append(pid)
        return deduplicated

    def start(self, spawn: bool = False) -> Tuple[bool, Optional[int]]:
        if not self.device and not self.connect_device():
            return False, None

        attach_attempts: List[Tuple[str, Any]] = []
        if not spawn:
            attach_attempts.append(("package", lambda: self.device.attach(self.package_name)))
            for pid in self._find_running_pids():
                attach_attempts.append((f"pid:{pid}", lambda pid=pid: self.device.attach(pid)))
            attach_attempts.append(("spawn_fallback", lambda: ("spawn", self.device.spawn([self.package_name]))))
        else:
            attach_attempts.append(("spawn", lambda: ("spawn", self.device.spawn([self.package_name]))))
            attach_attempts.append(("package_fallback", lambda: self.device.attach(self.package_name)))
            for pid in self._find_running_pids():
                attach_attempts.append((f"pid:{pid}", lambda pid=pid: self.device.attach(pid)))

        for attempt_name, attempt in attach_attempts:
            try:
                result = attempt()
                if isinstance(result, tuple) and result[0] == "spawn":
                    pid = int(result[1])
                    self.session = self.device.attach(pid)
                    self.is_running = True
                    print(f"[HookManager] attached by {attempt_name}, pid={pid}")
                    return True, pid

                self.session = result
                self.is_running = True
                print(f"[HookManager] attached by {attempt_name}")
                return True, None
            except Exception as error:
                print(f"[HookManager] attach strategy {attempt_name} failed: {error}")

        print("[HookManager] all attach strategies failed")
        return False, None

    def load_script(self, js_path: str, pid: Optional[int] = None) -> bool:
        if not self.session:
            print("[HookManager] session not established")
            return False

        try:
            bundle = self._build_agent_bundle(js_path)
            self.script = self.session.create_script(bundle, name=os.path.basename(js_path))
            self.script.on("message", self._on_message)
            self.script.load()

            if pid is not None:
                self.device.resume(pid)
                print(f"[HookManager] resumed spawned process: {pid}")

            print(f"[HookManager] hook script loaded: {js_path}")
            return True
        except Exception as error:
            print(f"[HookManager] load script failed: {error}")
            return False

    def _record_api_call(self, payload: Dict[str, Any]) -> None:
        api_name = str(payload.get("api") or "").strip()
        signal_key = str(payload.get("signal_key") or api_name or "unknown").strip()
        category = str(payload.get("category") or "other").strip()

        entry: Dict[str, Any] = {
            "timestamp": payload.get("timestamp") or time.time(),
            "api": api_name,
            "signal_key": signal_key,
            "category": category,
            "description": str(payload.get("description") or signal_key),
            "args": payload.get("args") or [],
            "return_value": payload.get("return_value"),
            "uri": payload.get("uri", ""),
            "stack": payload.get("stack", ""),
        }
        for key, value in payload.items():
            if key in {
                "type",
                "timestamp",
                "api",
                "signal_key",
                "category",
                "description",
                "args",
                "return_value",
                "uri",
                "stack",
            }:
                continue
            entry[key] = value

        self.call_logs.append(entry)

        if api_name and api_name not in self.hooked_apis:
            self.hooked_apis.append(api_name)

        self.signal_counts[signal_key] = self.signal_counts.get(signal_key, 0) + 1
        self.category_counts[category] = self.category_counts.get(category, 0) + 1

    def _record_appscan_style_event(self, payload: Dict[str, Any]) -> None:
        action = str(payload.get("action") or "runtime_probe").strip()
        message = str(payload.get("messages") or action).strip()
        args_text = str(payload.get("arg") or "").strip()
        stack_text = str(payload.get("stacks") or "").strip()
        api_name = message.replace("\r", " ").replace("\n", " ").strip()

        self._record_api_call(
            {
                "timestamp": payload.get("time") or time.time(),
                "api": api_name,
                "signal_key": api_name,
                "category": action,
                "description": message,
                "args": [args_text] if args_text else [],
                "return_value": "",
                "stack": stack_text,
            }
        )

    def _on_message(self, message: Dict[str, Any], data: Any) -> None:
        message_type = message.get("type")
        if message_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                payload_type = str(payload.get("type") or "").strip()
                if payload_type == "api_call" or payload.get("api"):
                    self._record_api_call(payload)
                elif payload_type in {"method_result", "request_result"}:
                    self._record_appscan_style_event(payload)
                elif payload_type == "status":
                    status = str(payload.get("message") or "").strip()
                    if status:
                        self.status_messages.append(status)
                elif payload_type == "error":
                    error_message = str(payload.get("message") or "").strip()
                    if error_message:
                        self.errors.append(error_message)
            elif payload:
                self.status_messages.append(str(payload))
        elif message_type == "error":
            stack = str(message.get("stack") or message.get("description") or "").strip()
            if stack:
                self.errors.append(stack)
                print(f"[HookManager] script error: {stack}")

    def get_hooked_apis(self) -> List[str]:
        return list(self.hooked_apis)

    def get_call_logs(self) -> List[Dict[str, Any]]:
        return list(self.call_logs)

    def get_signal_counts(self) -> Dict[str, int]:
        return dict(self.signal_counts)

    def get_category_counts(self) -> Dict[str, int]:
        return dict(self.category_counts)

    def get_status_messages(self) -> List[str]:
        return list(self.status_messages)

    def get_errors(self) -> List[str]:
        return list(self.errors)

    def get_aggregated_calls(self) -> List[Dict[str, Any]]:
        grouped: Dict[str, Dict[str, Any]] = {}
        for log in self.call_logs:
            signal_key = str(log.get("signal_key") or log.get("api") or "unknown")
            if signal_key not in grouped:
                grouped[signal_key] = {
                    "signal_key": signal_key,
                    "category": log.get("category", "other"),
                    "description": log.get("description", signal_key),
                    "count": 0,
                    "sample_apis": [],
                }

            grouped_entry = grouped[signal_key]
            grouped_entry["count"] += 1
            api_name = str(log.get("api") or "")
            if api_name and api_name not in grouped_entry["sample_apis"]:
                grouped_entry["sample_apis"].append(api_name)

        return sorted(grouped.values(), key=lambda item: (-item["count"], item["signal_key"]))

    def stop(self) -> None:
        if self.script:
            try:
                self.script.unload()
            except Exception as error:
                print(f"[HookManager] unload script failed: {error}")
            finally:
                self.script = None

        if self.session:
            try:
                self.session.detach()
            except Exception as error:
                print(f"[HookManager] detach session failed: {error}")
            finally:
                self.session = None

        self.is_running = False

    def is_connected(self) -> bool:
        return self.device is not None
