from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Callable, Dict, Optional

from dynamic_engine.hook_manager import HookManager


class FridaDynamicAnalyzer:
    def __init__(self, apk_path: str, package_name: str, output_dir: str = "results"):
        self.apk_path = apk_path
        self.package_name = package_name
        self.output_dir = output_dir
        self.hook_manager = HookManager(package_name)
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
        self.hook_results = self._build_empty_hook_results()

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
            "status_messages": self.hook_results.get("status_messages", [])[:30],
            "error_messages": self.hook_results.get("errors", [])[:30],
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
        if any("Java bridge is not available." in item or "Java runtime is not available." in item for item in errors):
            return True
        if any("waiting for Java bridge" in item or "waiting for Java runtime" in item for item in status_messages):
            return not any("sensitive api hooks ready" in item for item in status_messages)
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
    ) -> Dict[str, Any]:
        if not self.frida_analyzer:
            return {"error": "package name is not set"}

        last_result: Dict[str, Any] = {"error": "unable to start Frida hook"}
        for attempt_index, spawn in enumerate([False, True]):
            self.frida_analyzer.reset_runtime_state()
            if not self.frida_analyzer.start_hook(spawn=spawn):
                continue

            result = self._monitor_with_optional_probe(duration, probe_callback)
            last_result = result
            if spawn or not self._should_retry_with_spawn(result):
                return result

            print("[Frida] Java runtime not ready on attach attempt, retrying with spawn mode")

        return last_result

    def get_frida_summary(self) -> Dict[str, Any]:
        if not self.frida_analyzer:
            return {}
        return self.frida_analyzer.get_summary()
