# Frida Hook管理器 - 动态行为监控引擎
import frida
import sys
import json
import time
from typing import Dict, List, Optional

class HookManager:
    def __init__(self, package_name):
        self.package_name = package_name
        self.device = None
        self.session = None
        self.script = None
        self.hooked_apis = []
        self.call_logs = []
        self.is_running = False
        
    def connect_device(self) -> bool:
        """连接到设备"""
        print("[HookManager] 正在连接设备...")
        try:
            # 尝试连接夜神模拟器
            self.device = frida.get_device_manager().add_remote_device("127.0.0.1:62001")
            print("[HookManager] 成功连接到设备")
            return True
        except Exception as e:
            print(f"[HookManager] 连接设备失败: {e}")
            # 尝试使用默认设备
            try:
                self.device = frida.get_usb_device(timeout=5)
                print("[HookManager] 成功连接到USB设备")
                return True
            except Exception as e2:
                print(f"[HookManager] 连接USB设备失败: {e2}")
                return False
    
    def start(self, spawn: bool = False) -> bool:
        """启动Frida会话"""
        print(f"[HookManager] 启动Frida会话，注入 {self.package_name}...")
        
        # 尝试多次附加
        max_retries = 3
        for retry in range(max_retries):
            try:
                if spawn:
                    # 以spawn方式启动应用
                    print(f"[HookManager] 尝试以spawn方式启动应用 (尝试 {retry+1}/{max_retries})...")
                    pid = self.device.spawn([self.package_name])
                    self.session = self.device.attach(pid)
                    self.device.resume(pid)
                    print(f"[HookManager] 以spawn方式启动应用，PID: {pid}")
                else:
                    # 附加到已运行的应用
                    print(f"[HookManager] 尝试附加到已运行的应用 (尝试 {retry+1}/{max_retries})...")
                    self.session = self.device.attach(self.package_name)
                    print("[HookManager] 成功附加到应用")
                
                self.is_running = True
                return True
            except Exception as e:
                print(f"[HookManager] 附加失败: {e}")
                # 增加延迟后重试
                time.sleep(2)
                continue
        
        # 尝试使用PID附加
        try:
            print("[HookManager] 尝试通过PID附加...")
            # 获取应用的PID
            import subprocess
            result = subprocess.run(["adb", "shell", "ps", "|", "grep", self.package_name], 
                                  capture_output=True, text=True)
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if self.package_name in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            pid = int(parts[1])
                            print(f"[HookManager] 找到应用PID: {pid}")
                            self.session = self.device.attach(pid)
                            print("[HookManager] 成功通过PID附加到应用")
                            self.is_running = True
                            return True
        except Exception as e:
            print(f"[HookManager] 通过PID附加失败: {e}")
        
        return False
    
    def load_script(self, js_path: str) -> bool:
        """加载Hook脚本"""
        try:
            with open(js_path, 'r', encoding='utf-8') as f:
                js_code = f.read()
            
            self.script = self.session.create_script(js_code)
            self.script.on('message', self._on_message)
            self.script.load()
            print(f"[HookManager] 成功加载脚本: {js_path}")
            return True
        except Exception as e:
            print(f"[HookManager] 加载脚本失败: {e}")
            return False
    
    def _on_message(self, message, data):
        """处理从Frida脚本发送的消息"""
        if message['type'] == 'send':
            payload = message['payload']
            print(f"[HOOK] {payload}")
            
            # 解析payload，记录API调用
            if isinstance(payload, dict):
                self.call_logs.append({
                    'timestamp': time.time(),
                    'api': payload.get('api', ''),
                    'args': payload.get('args', []),
                    'return_value': payload.get('return_value', ''),
                    'stack': payload.get('stack', [])
                })
                
                # 记录已hook的API
                api_name = payload.get('api', '')
                if api_name not in self.hooked_apis:
                    self.hooked_apis.append(api_name)
        elif message['type'] == 'error':
            print(f"[HookManager] 错误: {message['stack']}")
    
    def get_hooked_apis(self) -> List[str]:
        """获取已hook的API列表"""
        return self.hooked_apis
    
    def get_call_logs(self) -> List[Dict]:
        """获取API调用日志"""
        return self.call_logs
    
    def stop(self):
        """停止Hook"""
        if self.script:
            try:
                self.script.unload()
                print("[HookManager] 脚本已卸载")
            except Exception as e:
                print(f"[HookManager] 卸载脚本失败: {e}")
        
        if self.session:
            try:
                self.session.detach()
                print("[HookManager] 会话已分离")
            except Exception as e:
                print(f"[HookManager] 分离会话失败: {e}")
        
        self.is_running = False
    
    def is_connected(self) -> bool:
        """检查是否已连接"""
        return self.device is not None

# 示例用法
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"用法: {sys.argv[0]} <package_name>")
        sys.exit(1)
    
    package_name = sys.argv[1]
    hm = HookManager(package_name)
    
    if not hm.connect_device():
        print("无法连接设备")
        sys.exit(1)
    
    if not hm.start():
        print("无法启动Hook")
        sys.exit(1)
    
    # 加载敏感API Hook脚本
    script_path = "dynamic_engine/hooks/sensitive_api_hook.js"
    if not hm.load_script(script_path):
        print("无法加载Hook脚本")
        hm.stop()
        sys.exit(1)
    
    print("[*] 正在监听敏感API调用... 按 Ctrl+C 停止")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 停止监听")
    finally:
        hm.stop()
        
        # 保存调用日志
        if hm.get_call_logs():
            log_file = f"hook_logs_{package_name}_{int(time.time())}.json"
            with open(log_file, 'w', encoding='utf-8') as f:
                json.dump(hm.get_call_logs(), f, ensure_ascii=False, indent=2)
            print(f"[*] 调用日志已保存到: {log_file}")
        
        print(f"[*] 已hook的API: {hm.get_hooked_apis()}")
        print("[*] Hook已停止")