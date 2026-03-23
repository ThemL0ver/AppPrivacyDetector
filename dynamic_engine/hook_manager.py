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
        
        # 尝试使用 frida.get_usb_device() 连接，这是 frida 命令行工具使用的方式
        try:
            print("[HookManager] 尝试使用 frida.get_usb_device()")
            self.device = frida.get_usb_device(timeout=15)
            print(f"[HookManager] 成功连接到设备: {self.device.name}")
            return True
        except Exception as e:
            print(f"[HookManager] frida.get_usb_device() 连接失败: {e}")
        
        # 尝试使用 frida.get_device() 作为备用
        try:
            print("[HookManager] 尝试使用 frida.get_device()")
            self.device = frida.get_device(timeout=15)
            print(f"[HookManager] 成功连接到设备: {self.device.name}")
            return True
        except Exception as e:
            print(f"[HookManager] frida.get_device() 连接失败: {e}")
        
        # 尝试使用设备管理器枚举设备并连接
        try:
            print("[HookManager] 尝试枚举所有设备")
            manager = frida.get_device_manager()
            devices = manager.enumerate_devices()
            print(f"[HookManager] 发现设备: {[d.name for d in devices]}")
            if devices:
                self.device = devices[0]
                print(f"[HookManager] 成功连接到设备: {self.device.name}")
                return True
        except Exception as e:
            print(f"[HookManager] 枚举设备失败: {e}")
        
        print("[HookManager] 所有连接方式均失败")
        return False
    
    def start(self, spawn: bool = False) -> tuple[bool, int]:
        """启动Frida会话"""
        print(f"[HookManager] 启动Frida会话，注入 {self.package_name}...")
        
        # 先尝试启动应用（如果没有运行）
        try:
            import subprocess
            # 检查应用是否在运行
            result = subprocess.run(["adb", "shell", "ps"], capture_output=True, text=True)
            app_running = False
            pids = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if self.package_name in line:
                        app_running = True
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                pid = int(parts[1])
                                pids.append(pid)
                            except ValueError:
                                pass
            
            if not app_running:
                print(f"[HookManager] 应用 {self.package_name} 未运行，尝试启动...")
                # 启动应用
                start_result = subprocess.run(["adb", "shell", "am", "start", "-n", f"{self.package_name}/.MainActivity"], capture_output=True, text=True)
                print(f"[HookManager] 启动应用结果: {start_result.returncode}")
                # 等待应用完全启动
                time.sleep(5)
                # 再次检查应用是否运行
                result = subprocess.run(["adb", "shell", "ps"], capture_output=True, text=True)
                if result.stdout:
                    for line in result.stdout.strip().split('\n'):
                        if self.package_name in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                try:
                                    pid = int(parts[1])
                                    pids.append(pid)
                                except ValueError:
                                    pass
            else:
                # 应用已运行，等待一下确保Java运行时已加载
                time.sleep(2)
            
            print(f"[HookManager] 找到应用进程: {pids}")
        except Exception as e:
            print(f"[HookManager] 检查应用状态失败: {e}")
        
        # 尝试多种附加策略
        strategies = [
            ("使用包名附加", lambda: self.device.attach(self.package_name)),
        ]
        
        # 添加PID附加策略
        if 'pids' in locals() and pids:
            for pid in pids:
                strategies.append((f"通过PID {pid} 附加", lambda pid=pid: self.device.attach(pid)))
        
        # 添加spawn策略
        if spawn:
            strategies.append(("以spawn方式启动", lambda: (self.device.spawn([self.package_name]), True)))
        
        # 尝试所有策略
        for strategy_name, attach_func in strategies:
            print(f"[HookManager] 尝试策略: {strategy_name}")
            try:
                result = attach_func()
                if isinstance(result, tuple) and len(result) == 2 and result[1]:
                    # spawn方式
                    pid = result[0]
                    self.session = self.device.attach(pid)
                    print(f"[HookManager] 以spawn方式启动应用，PID: {pid}")
                    self.is_running = True
                    return True, pid
                else:
                    # 普通附加
                    self.session = result
                    print(f"[HookManager] 成功通过 {strategy_name} 附加到应用")
                    self.is_running = True
                    return True, None
            except Exception as e:
                print(f"[HookManager] {strategy_name} 失败: {e}")
                continue
        
        # 尝试多次重试
        max_retries = 3
        for retry in range(max_retries):
            print(f"[HookManager] 重试附加 (尝试 {retry+1}/{max_retries})...")
            try:
                # 再次检查应用进程
                import subprocess
                result = subprocess.run(["adb", "shell", "ps"], capture_output=True, text=True)
                current_pids = []
                if result.stdout:
                    for line in result.stdout.strip().split('\n'):
                        if self.package_name in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                try:
                                    pid = int(parts[1])
                                    current_pids.append(pid)
                                except ValueError:
                                    pass
                
                print(f"[HookManager] 当前应用进程: {current_pids}")
                
                # 尝试附加到第一个进程
                for pid in current_pids:
                    try:
                        print(f"[HookManager] 尝试附加到 PID: {pid}")
                        self.session = self.device.attach(pid)
                        print(f"[HookManager] 成功通过PID {pid} 附加到应用")
                        self.is_running = True
                        return True, None
                    except Exception as e:
                        print(f"[HookManager] 附加到PID {pid} 失败: {e}")
                        continue
            except Exception as e:
                print(f"[HookManager] 重试过程中出错: {e}")
            
            time.sleep(3)
        
        print("[HookManager] 所有附加策略均失败")
        return False, None
    
    def load_script(self, js_path: str, pid: int = None) -> bool:
        """加载Hook脚本"""
        try:
            with open(js_path, 'r', encoding='utf-8') as f:
                js_code = f.read()
            
            # 确保脚本在 Java.perform 中执行，并添加错误处理
            if 'Java.perform' not in js_code:
                js_code = '''
                try {
                    Java.perform(function() {
                        ''' + js_code + '''
                    });
                } catch (e) {
                    console.log('[Hook] 错误: ' + e);
                    send({error: '' + e});
                }
                '''
            else:
                # 如果已经有 Java.perform，添加错误处理
                js_code = '''
                try {
                    ''' + js_code + '''
                } catch (e) {
                    console.log('[Hook] 错误: ' + e);
                    send({error: '' + e});
                }
                '''
            
            self.script = self.session.create_script(js_code)
            self.script.on('message', self._on_message)
            
            # 尝试多次加载脚本
            max_retries = 3
            for retry in range(max_retries):
                try:
                    self.script.load()
                    print(f"[HookManager] 成功加载脚本: {js_path}")
                    
                    # 如果是spawn模式，加载脚本后恢复进程
                    if pid is not None:
                        print(f"[HookManager] 恢复进程，PID: {pid}")
                        self.device.resume(pid)
                    
                    return True
                except Exception as e:
                    print(f"[HookManager] 加载脚本失败 (尝试 {retry+1}/{max_retries}): {e}")
                    time.sleep(2)
                    continue
            
            return False
        except Exception as e:
            print(f"[HookManager] 加载脚本失败: {e}")
            import traceback
            traceback.print_exc()
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