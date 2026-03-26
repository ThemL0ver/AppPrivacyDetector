# 基于Frida的动态行为监控引擎
import os
import json
import time
from typing import Dict, List, Optional
from dynamic_engine.hook_manager import HookManager


class FridaDynamicAnalyzer:
    def __init__(self, apk_path: str, package_name: str):
        self.apk_path = apk_path
        self.package_name = package_name
        self.hook_results = {
            "hooked_apis": [],
            "call_logs": [],
            "duration": 0,
            "errors": []
        }
        # hook_manager 不在构造函数中创建，每次 start_hook 前重新实例化
        self.hook_manager = None

    def _make_fresh_hook_manager(self) -> HookManager:
        """每次启动前创建全新的 HookManager，避免复用失败状态的对象"""
        if self.hook_manager:
            try:
                self.hook_manager.stop()
            except Exception:
                pass
        self.hook_manager = HookManager(self.package_name)
        return self.hook_manager

    def start_hook(self, spawn: bool = True) -> bool:
        """启动 Frida Hook，每次调用均重新创建 HookManager"""
        print("=" * 60)
        print(f"启动Frida动态行为监控 (spawn={spawn})")
        print("=" * 60)

        # 每次都重新实例化，确保内部状态干净
        hm = self._make_fresh_hook_manager()

        # 连接设备
        if not hm.connect_device():
            self.hook_results["errors"].append("无法连接设备")
            return False

        # 启动 Hook 会话
        success, pid = hm.start(spawn=spawn)
        if not success:
            self.hook_results["errors"].append(
                f"无法启动Hook会话 (spawn={spawn})"
            )
            return False

        # 加载 Hook 脚本
        script_path = os.path.join(
            os.path.dirname(__file__), "hooks", "sensitive_api_hook.js"
        )
        if not os.path.exists(script_path):
            self.hook_results["errors"].append(
                f"Hook脚本不存在: {script_path}"
            )
            return False

        print(f"[Frida] 加载Hook脚本: {script_path}")
        for retry in range(3):
            if hm.load_script(script_path, pid):
                print("[Frida] Hook启动成功！开始监控敏感API调用...")
                return True
            print(f"[Frida] 加载脚本失败，重试 {retry + 1}/3...")
            time.sleep(2)

        self.hook_results["errors"].append("无法加载Hook脚本")
        return False

    def monitor(self, duration: int = 60) -> Dict:
        """监控敏感API调用"""
        start_time = time.time()
        print(f"[Frida] 开始监控，持续 {duration} 秒...")

        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print("[Frida] 监控被用户中断")
        finally:
            if self.hook_manager:
                self.hook_manager.stop()
                self.hook_results["hooked_apis"] = self.hook_manager.get_hooked_apis()
                self.hook_results["call_logs"] = self.hook_manager.get_call_logs()
            self.hook_results["duration"] = time.time() - start_time

        self._save_hook_results()

        print("=" * 60)
        print("Frida动态行为监控完成")
        print("=" * 60)

        return self.hook_results

    def _save_hook_results(self):
        """保存 Hook 结果到文件"""
        output_dir = "results"
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(
            output_dir,
            f"{os.path.basename(self.apk_path)}_frida_hook.json"
        )
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.hook_results, f, ensure_ascii=False, indent=2)
        print(f"[Frida] Hook结果已保存到: {output_file}")

    def get_summary(self) -> Dict:
        """获取监控摘要"""
        api_call_counts = {}
        for call in self.hook_results["call_logs"]:
            api = call.get("api", "")
            if api:
                api_call_counts[api] = api_call_counts.get(api, 0) + 1

        return {
            "total_hooked_apis": len(self.hook_results["hooked_apis"]),
            "total_api_calls": len(self.hook_results["call_logs"]),
            "duration": self.hook_results["duration"],
            "errors": len(self.hook_results["errors"]),
            "hooked_apis": self.hook_results["hooked_apis"],
            "api_call_counts": api_call_counts
        }


class EnhancedDynamicAnalyzer:
    def __init__(self, apk_path: str, output_dir: str = "results"):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.package_name = None
        self.frida_analyzer = None

    def set_package_name(self, package_name: str):
        """设置包名并重建分析器"""
        self.package_name = package_name
        if package_name:
            self.frida_analyzer = FridaDynamicAnalyzer(self.apk_path, package_name)

    def perform_frida_analysis(self, duration: int = 60) -> Dict:
        """执行 Frida 动态分析，依次尝试 spawn 和 attach 两种模式"""
        if not self.frida_analyzer:
            return {"error": "包名未设置，无法执行Frida分析"}

        # 尝试顺序：spawn → attach
        modes = [
            (True,  "Spawn(注入优先)模式"),
            (False, "Attach(附加)模式"),
        ]

        for spawn_flag, mode_name in modes:
            print(f"[Frida] 尝试以 {mode_name} 启动Hook...")
            if self.frida_analyzer.start_hook(spawn=spawn_flag):
                try:
                    return self.frida_analyzer.monitor(duration)
                except Exception as e:
                    print(f"[Frida] 监控过程出错: {e}")
                    return {"error": f"监控过程出错: {str(e)}"}
            print(f"[Frida] {mode_name} 启动失败，尝试下一种模式...")

        print("[Frida] 所有模式均启动失败，跳过Frida分析")
        return {"error": "无法启动Frida Hook，已跳过Frida分析"}

    def get_frida_summary(self) -> Dict:
        """获取 Frida 分析摘要"""
        if not self.frida_analyzer:
            return {
                "total_hooked_apis": 0,
                "total_api_calls": 0,
                "duration": 0,
                "errors": 0,
                "hooked_apis": [],
                "api_call_counts": {}
            }
        return self.frida_analyzer.get_summary()


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <apk_path> <package_name>")
        sys.exit(1)

    analyzer = EnhancedDynamicAnalyzer(sys.argv[1])
    analyzer.set_package_name(sys.argv[2])
    results = analyzer.perform_frida_analysis(duration=30)
    summary = analyzer.get_frida_summary()
    print("\nFrida分析摘要:")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
