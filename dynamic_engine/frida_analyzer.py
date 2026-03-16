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
        self.hook_manager = HookManager(package_name)
        self.hook_results = {
            "hooked_apis": [],
            "call_logs": [],
            "duration": 0,
            "errors": []
        }
    
    def start_hook(self, spawn: bool = False) -> bool:
        """启动Frida Hook"""
        print("=" * 60)
        print("启动Frida动态行为监控")
        print("=" * 60)
        
        # 连接设备
        if not self.hook_manager.connect_device():
            self.hook_results["errors"].append("无法连接设备")
            return False
        
        # 启动Hook会话
        if not self.hook_manager.start(spawn=spawn):
            # 尝试以spawn方式启动
            if not self.hook_manager.start(spawn=True):
                self.hook_results["errors"].append("无法启动Hook会话")
                return False
        
        # 加载Hook脚本
        script_path = os.path.join(os.path.dirname(__file__), "hooks", "sensitive_api_hook.js")
        if not self.hook_manager.load_script(script_path):
            self.hook_results["errors"].append("无法加载Hook脚本")
            return False
        
        print("[Frida] Hook启动成功！开始监控敏感API调用...")
        return True
    
    def monitor(self, duration: int = 60) -> Dict:
        """监控敏感API调用"""
        start_time = time.time()
        
        print(f"[Frida] 开始监控，持续 {duration} 秒...")
        
        try:
            # 等待监控完成
            time.sleep(duration)
        except KeyboardInterrupt:
            print("[Frida] 监控被用户中断")
        finally:
            # 停止Hook
            self.hook_manager.stop()
            
            # 收集结果
            self.hook_results["hooked_apis"] = self.hook_manager.get_hooked_apis()
            self.hook_results["call_logs"] = self.hook_manager.get_call_logs()
            self.hook_results["duration"] = time.time() - start_time
        
        # 保存Hook结果
        self._save_hook_results()
        
        print("=" * 60)
        print("Frida动态行为监控完成")
        print("=" * 60)
        
        return self.hook_results
    
    def _save_hook_results(self):
        """保存Hook结果"""
        output_dir = "results"
        os.makedirs(output_dir, exist_ok=True)
        
        output_file = os.path.join(output_dir, f"{os.path.basename(self.apk_path)}_frida_hook.json")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.hook_results, f, ensure_ascii=False, indent=2)
        
        print(f"[Frida] Hook结果已保存到: {output_file}")
    
    def get_summary(self) -> Dict:
        """获取监控摘要"""
        summary = {
            "total_hooked_apis": len(self.hook_results["hooked_apis"]),
            "total_api_calls": len(self.hook_results["call_logs"]),
            "duration": self.hook_results["duration"],
            "errors": len(self.hook_results["errors"]),
            "hooked_apis": self.hook_results["hooked_apis"]
        }
        
        # 统计API调用次数
        api_call_counts = {}
        for call in self.hook_results["call_logs"]:
            api = call["api"]
            api_call_counts[api] = api_call_counts.get(api, 0) + 1
        
        summary["api_call_counts"] = api_call_counts
        
        return summary

# 集成到现有动态分析系统
class EnhancedDynamicAnalyzer:
    def __init__(self, apk_path: str, output_dir: str = "results"):
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.package_name = None
        self.frida_analyzer = None
    
    def set_package_name(self, package_name: str):
        """设置包名"""
        self.package_name = package_name
        if package_name:
            self.frida_analyzer = FridaDynamicAnalyzer(self.apk_path, package_name)
    
    def perform_frida_analysis(self, duration: int = 60) -> Dict:
        """执行Frida动态分析"""
        if not self.frida_analyzer:
            return {
                "error": "包名未设置，无法执行Frida分析"
            }
        
        # 尝试正常启动Hook
        print("[Frida] 尝试启动Hook...")
        if not self.frida_analyzer.start_hook():
            # 尝试使用spawn方式启动
            print("[Frida] 尝试使用spawn方式启动Hook...")
            if not self.frida_analyzer.start_hook(spawn=True):
                print("[Frida] Frida Hook启动失败，跳过Frida分析")
                return {
                    "error": "无法启动Frida Hook，已跳过Frida分析"
                }
        
        try:
            return self.frida_analyzer.monitor(duration)
        except Exception as e:
            print(f"[Frida] 执行Frida分析时出错: {e}")
            return {
                "error": f"执行Frida分析时出错: {str(e)}"
            }
    
    def get_frida_summary(self) -> Dict:
        """获取Frida分析摘要"""
        if not self.frida_analyzer:
            return {}
        
        return self.frida_analyzer.get_summary()

if __name__ == "__main__":
    # 示例用法
    import sys
    
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <apk_path> <package_name>")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    package_name = sys.argv[2]
    
    analyzer = EnhancedDynamicAnalyzer(apk_path)
    analyzer.set_package_name(package_name)
    
    results = analyzer.perform_frida_analysis(duration=30)
    summary = analyzer.get_frida_summary()
    
    print("\nFrida分析摘要:")
    print(json.dumps(summary, ensure_ascii=False, indent=2))