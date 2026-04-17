from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from dynamic_engine.hook_manager import HookManager


class FridaDynamicAnalyzer:
    def __init__(self, apk_path: str, package_name: str, output_dir: str = "results"):
        self.apk_path = apk_path
        self.package_name = package_name
        self.output_dir = output_dir
        self.hook_manager = HookManager(package_name)
        self.preferred_pids: List[int] = []
        self.hook_results: Dict[str, Any] = self._build_empty_hook_results()

    def _build_empty_hook_results(self) -> Dict[str, Any]:
        return {
            "hooked_apis": [],
            "call_logs": [],
            "duration": 0.0,
            "errors": [],
            "signal_counts": {},
            "category_counts": {},
            "aggregated_calls": [],
            "status_messages": [],
        }

    def reset_runtime_state(self) -> None:
        try:
            self.hook_manager.stop()
        except Exception:
            pass
        self.hook_manager = HookManager(self.package_name)
        self.hook_manager.set_preferred_pids(self.preferred_pids)
        self.hook_results = self._build_empty_hook_results()

    def set_preferred_pids(self, pids: List[int]) -> None:
        ordered: List[int] = []
        seen = set()
        for pid in pids or []:
            try:
                normalized = int(pid)
            except (TypeError, ValueError):
                continue
            if normalized <= 0 or normalized in seen:
                continue
            seen.add(normalized)
            ordered.append(normalized)
        self.preferred_pids = ordered
        self.hook_manager.set_preferred_pids(self.preferred_pids)

    def start_hook(self, spawn: bool = False) -> bool:
        print("=" * 60)
        print("start Frida runtime monitor")
        print("=" * 60)

        if not self.hook_manager.connect_device():
            self.hook_results["errors"].append("unable to connect Frida device")
            return False

        success, pid = self.hook_manager.start(spawn=spawn)
        if not success:
            self.hook_results["errors"].append("unable to create Frida session")
            return False

        script_path = os.path.join(os.path.dirname(__file__), "frida_agent", "sensitive_api_hook.ts")
        if not self.hook_manager.load_script(script_path, pid):
            self.hook_results["errors"].append("unable to load hook script")
            return False

        if not self.hook_manager.wait_for_script_ready(timeout=10 if spawn else 8):
            self.hook_results["errors"] = self.hook_results.get("errors", []) + self.hook_manager.get_errors()
            self.hook_results["status_messages"] = self.hook_manager.get_status_messages()
            if not self.hook_results["errors"]:
                self.hook_results["errors"].append("hook script did not reach ready state")
            return False

        return True

    def monitor(self, duration: int = 60) -> Dict[str, Any]:
        start_time = time.time()
        print(f"[Frida] monitoring for {duration}s")

        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print("[Frida] interrupted by user")
        finally:
            self.hook_manager.stop()
            self.hook_results["hooked_apis"] = self.hook_manager.get_hooked_apis()
            self.hook_results["call_logs"] = self.hook_manager.get_call_logs()
            self.hook_results["duration"] = round(time.time() - start_time, 3)
            self.hook_results["errors"] = self.hook_results.get("errors", []) + self.hook_manager.get_errors()
            self.hook_results["signal_counts"] = self.hook_manager.get_signal_counts()
            self.hook_results["category_counts"] = self.hook_manager.get_category_counts()
            self.hook_results["aggregated_calls"] = self.hook_manager.get_aggregated_calls()
            self.hook_results["status_messages"] = self.hook_manager.get_status_messages()
            detached_events = self.hook_manager.get_detached_events()
            if detached_events:
                self.hook_results["detached_events"] = detached_events

        self._save_hook_results()
        print("=" * 60)
        print("Frida monitor finished")
        print("=" * 60)
        return self.hook_results

    def _save_hook_results(self) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        output_file = os.path.join(self.output_dir, f"{os.path.basename(self.apk_path)}_frida_hook.json")
        with open(output_file, "w", encoding="utf-8") as output_handle:
            json.dump(self.hook_results, output_handle, ensure_ascii=False, indent=2)
        print(f"[Frida] hook results saved to: {output_file}")

    def get_summary(self) -> Dict[str, Any]:
        aggregated_calls = self.hook_results.get("aggregated_calls", [])
        status_messages = self.hook_results.get("status_messages", [])
        error_messages = self.hook_results.get("errors", [])
        detached_events = self.hook_results.get("detached_events", [])
        status_blob = "\n".join(str(item) for item in status_messages).lower()
        issue_blob = "\n".join(str(item) for item in (list(error_messages) + list(detached_events))).lower()
        return {
            "total_hooked_apis": len(self.hook_results.get("hooked_apis", [])),
            "total_api_calls": len(self.hook_results.get("call_logs", [])),
            "total_hooked_signals": len(self.hook_results.get("signal_counts", {})),
            "total_categories": len(self.hook_results.get("category_counts", {})),
            "duration": self.hook_results.get("duration", 0.0),
            "errors": len(self.hook_results.get("errors", [])),
            "hooked_apis": self.hook_results.get("hooked_apis", []),
            "signal_counts": self.hook_results.get("signal_counts", {}),
            "category_counts": self.hook_results.get("category_counts", {}),
            "aggregated_calls": aggregated_calls[:30],
            "status_messages": status_messages[:30],
            "error_messages": error_messages[:30],
            "detached_events": detached_events[:10],
            "java_bridge_ready": "java bridge ready" in status_blob,
            "java_hook_ready": "sensitive api hooks ready" in status_blob,
            "process_terminated": "process-terminated" in issue_blob,
            "session_detached": "session detached:" in issue_blob,
        }


class EnhancedDynamicAnalyzer:
    def __init__(self, apk_path: str, output_dir: str = "results"):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.package_name: Optional[str] = None
        self.frida_analyzer: Optional[FridaDynamicAnalyzer] = None

    def set_package_name(self, package_name: str) -> None:
        self.package_name = package_name
        if package_name:
            self.frida_analyzer = FridaDynamicAnalyzer(
                self.apk_path,
                package_name,
                output_dir=self.output_dir,
            )

    def set_preferred_pids(self, pids: List[int]) -> None:
        if self.frida_analyzer:
            self.frida_analyzer.set_preferred_pids(pids)

    def _run_probe_callback(self, probe_callback: Callable[[], None]) -> None:
        try:
            print("[Frida] run probe callback")
            probe_callback()
            print("[Frida] probe callback done")
        except Exception as error:
            if self.frida_analyzer:
                self.frida_analyzer.hook_results.setdefault("errors", []).append(
                    f"probe callback failed: {error}"
                )
            print(f"[Frida] probe callback failed: {error}")

    def _should_retry_with_spawn(self, result: Dict[str, Any]) -> bool:
        errors = [str(item) for item in result.get("errors", [])]
        status_messages = [str(item) for item in result.get("status_messages", [])]
        detached_events = [str(item) for item in result.get("detached_events", [])]
        status_blob = "\n".join(status_messages).lower()
        java_hook_ready = "sensitive api hooks ready" in status_blob
        if any("Java bridge is not available." in item or "Java runtime is not available." in item for item in errors):
            return True
        if any("waiting for Java bridge" in item or "waiting for Java runtime" in item for item in status_messages):
            return not any("sensitive api hooks ready" in item for item in status_messages)
        if not java_hook_ready and any("session detached:" in item.lower() for item in detached_events + errors):
            return True
        return False

    def _monitor_with_optional_probe(
        self,
        duration: int,
        probe_callback: Optional[Callable[[], None]] = None,
    ) -> Dict[str, Any]:
        probe_thread: Optional[threading.Thread] = None
        if probe_callback is not None:
            probe_thread = threading.Thread(
                target=self._run_probe_callback,
                args=(probe_callback,),
                daemon=True,
            )
            probe_thread.start()

        try:
            return self.frida_analyzer.monitor(duration)
        except Exception as error:
            return {"error": f"Frida analysis failed: {error}"}
        finally:
            if probe_thread is not None and probe_thread.is_alive():
                probe_thread.join(timeout=5)

    def perform_frida_analysis(
        self,
        duration: int = 60,
        probe_callback: Optional[Callable[[], None]] = None,
        spawn_first: bool = False,
    ) -> Dict[str, Any]:
        if not self.frida_analyzer:
            return {"error": "package name is not set"}

        last_result: Dict[str, Any] = {"error": "unable to start Frida hook"}
        attempt_order = [True, False] if spawn_first else [False, True]
        for attempt_index, spawn in enumerate(attempt_order):
            self.frida_analyzer.reset_runtime_state()
            if not self.frida_analyzer.start_hook(spawn=spawn):
                continue

            result = self._monitor_with_optional_probe(duration, probe_callback)
            last_result = result
            should_retry = self._should_retry_with_spawn(result)
            is_last_attempt = attempt_index >= len(attempt_order) - 1
            if should_retry and not is_last_attempt:
                retry_mode = "spawn" if not spawn else "attach"
                print(f"[Frida] session ended before stable capture, retrying with {retry_mode} mode")
                continue
            if not should_retry:
                return result

            return result

        return last_result

    def get_frida_summary(self) -> Dict[str, Any]:
        if not self.frida_analyzer:
            return {}
        return self.frida_analyzer.get_summary()
